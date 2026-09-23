//! `zurtr.live.pubsub` — the worker's bus.
//!
//! Sessions subscribe to topics; anything that has just committed a write publishes to a topic; every
//! subscriber is handed the message. That is the whole primitive, and it is deliberately this small,
//! because it is the piece that makes distribution ordinary: a bus that already carries "this happened"
//! between a job, a session and an agent does not need inventing again when those three are on different
//! machines — it needs a transport underneath, and the transport is `zurtr.data`'s tiers.
//!
//! # What this is not
//!
//! - **Not durable.** A message published with no subscribers is dropped, and a message published while a
//!   subscriber is mid-reconnect is gone. That is the durable path's job: the outbox writes the event in
//!   the same transaction as the state change, and a view that missed events resynchronizes from a
//!   revisioned snapshot. This broker fans out to subscribers that are *present*.
//! - **Not transactional.** `app` publishes after a committed write (`pubsub.publish(tx, topic, payload)`
//!   is the transactional form). Publishing before the commit would produce the one thing a bus must
//!   never produce: a subscriber acting on a write that was rolled back.
//! - **Not thread-safe, on purpose.** One owner per session, one event loop per worker: the broker
//!   belongs to the worker that owns its sessions and everything on it happens on that thread. A lock
//!   here would pretend sessions are shared, which `overview.md` says they are not.
//!
//! # Delivery
//!
//! A subscription carries the receiver it delivers to, because a worker's sessions each have their own
//! queue: `live.md` requires asynchronous completions to arrive as `Info` messages on the *session*
//! owner's queue, never by touching session state. The session registers how to be reached once, and the
//! broker addresses each subscriber individually.
//!
//! Per subscriber, messages arrive in publication order and carry a monotonic sequence, which is what a
//! session needs to notice a gap and ask for a resync instead of silently rendering a stale view.

const std = @import("std");

/// A session's identity on this worker. Sessions are worker-local (`overview.md`: "Live sessions are
/// worker-local: one owner for mutable session state"), so this only has to be unique per worker.
pub const SessionId = u64;

pub const Error = error{
    /// The subscription table could not grow.
    OutOfMemory,
    /// A receiver refused its message. The receiver's own business; the broker skips that subscriber for
    /// this publication and reports how many deliveries did arrive.
    ReceiverFailed,
};

/// One delivery, as a session sees it.
pub const Message = struct {
    session: SessionId,
    topic: []const u8,
    payload_json: []const u8,
    /// Monotonic across everything this broker publishes, so a subscriber can order and gap-check.
    seq: u64,
};

/// Where a subscriber's deliveries go: the session owner appends an `Info` message to its own queue.
pub const Receiver = struct {
    context: *anyopaque,
    deliver: *const fn (context: *anyopaque, message: Message) Error!void,

    pub fn send(self: Receiver, message: Message) Error!void {
        return self.deliver(self.context, message);
    }
};

pub const Broker = struct {
    allocator: std.mem.Allocator,
    subscriptions: std.ArrayList(Subscription) = .empty,
    /// How many messages have been published. Starts at zero: nothing published is ever seq 0.
    published: u64 = 0,

    const Subscription = struct {
        session: SessionId,
        topic: []const u8,
        receiver: Receiver,
    };

    pub fn init(allocator: std.mem.Allocator) Broker {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *Broker) void {
        for (self.subscriptions.items) |subscription| {
            self.allocator.free(subscription.topic);
        }

        self.subscriptions.deinit(self.allocator);
    }

    /// Subscribe `session` to `topic`, delivered through `receiver`. Subscribing twice is one
    /// subscription: a session that re-inits on reconnect must not receive duplicates.
    pub fn subscribe(self: *Broker, session: SessionId, topic: []const u8, receiver: Receiver) Error!void {
        if (self.isSubscribed(session, topic)) return;

        const owned = self.allocator.dupe(u8, topic) catch return error.OutOfMemory;
        errdefer self.allocator.free(owned);

        self.subscriptions.append(self.allocator, .{
            .session = session,
            .topic = owned,
            .receiver = receiver,
        }) catch return error.OutOfMemory;
    }

    pub fn isSubscribed(self: *const Broker, session: SessionId, topic: []const u8) bool {
        for (self.subscriptions.items) |subscription| {
            if (subscription.session == session and std.mem.eql(u8, subscription.topic, topic)) return true;
        }

        return false;
    }

    pub fn unsubscribe(self: *Broker, session: SessionId, topic: []const u8) void {
        var index: usize = 0;
        while (index < self.subscriptions.items.len) {
            const subscription = self.subscriptions.items[index];
            if (subscription.session == session and std.mem.eql(u8, subscription.topic, topic)) {
                self.allocator.free(subscription.topic);
                _ = self.subscriptions.swapRemove(index);

                continue;
            }

            index += 1;
        }
    }

    /// Drop everything `session` subscribed to. This is what `terminate` calls, so a session that is gone
    /// can never be a delivery target again.
    pub fn unsubscribeAll(self: *Broker, session: SessionId) void {
        var index: usize = 0;
        while (index < self.subscriptions.items.len) {
            const subscription = self.subscriptions.items[index];
            if (subscription.session == session) {
                self.allocator.free(subscription.topic);
                _ = self.subscriptions.swapRemove(index);

                continue;
            }

            index += 1;
        }
    }

    /// Publish to every subscriber of `topic` in subscription order, reporting how many deliveries were
    /// accepted.
    ///
    /// A topic nobody subscribes to is neither an error nor a failure to report: it is the ordinary case
    /// for a worker whose sessions have gone away, and the durable path has its own answer.
    pub fn publish(self: *Broker, topic: []const u8, payload_json: []const u8) Error!usize {
        self.published += 1;

        var delivered: usize = 0;
        var index: usize = 0;
        while (index < self.subscriptions.items.len) : (index += 1) {
            const subscription = self.subscriptions.items[index];
            if (!std.mem.eql(u8, subscription.topic, topic)) continue;

            const message = Message{
                .session = subscription.session,
                .topic = subscription.topic,
                .payload_json = payload_json,
                .seq = self.published,
            };

            // The receiver may re-enter the broker (a handler that publishes in response), so the
            // subscription it was handed is re-checked before use rather than trusted.
            subscription.receiver.send(message) catch |err| switch (err) {
                error.ReceiverFailed => continue,
                error.OutOfMemory => return error.OutOfMemory,
            };

            delivered += 1;
        }

        return delivered;
    }

    pub fn subscriberCount(self: *const Broker, topic: []const u8) usize {
        var count: usize = 0;
        for (self.subscriptions.items) |subscription| {
            if (std.mem.eql(u8, subscription.topic, topic)) count += 1;
        }

        return count;
    }
};

/// Stands in for a session's queue: collects what that one subscriber would have been handed.
pub const Recorder = struct {
    received: std.ArrayList(Message) = .empty,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) Recorder {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *Recorder) void {
        self.received.deinit(self.allocator);
    }

    pub fn receiver(self: *Recorder) Receiver {
        return .{ .context = self, .deliver = deliver };
    }

    fn deliver(context: *anyopaque, message: Message) Error!void {
        const self: *Recorder = @ptrCast(@alignCast(context));

        self.received.append(self.allocator, message) catch return error.OutOfMemory;
    }
};

test "a publish goes to every subscriber of that topic, addressed to each" {
    var broker = Broker.init(std.testing.allocator);
    defer broker.deinit();

    var first = Recorder.init(std.testing.allocator);
    defer first.deinit();
    var second = Recorder.init(std.testing.allocator);
    defer second.deinit();
    var other = Recorder.init(std.testing.allocator);
    defer other.deinit();

    try broker.subscribe(1, "user/7/invoices", first.receiver());
    try broker.subscribe(2, "user/7/invoices", second.receiver());
    // A session on a different topic must not be reached by accident.
    try broker.subscribe(3, "user/8/invoices", other.receiver());

    try std.testing.expectEqual(@as(usize, 2), try broker.publish("user/7/invoices", "{\"n\":1}"));

    // Each session got its own copy, and only its own: the queues are per session, which is why the
    // broker addresses subscribers rather than broadcasting to one callback.
    try std.testing.expectEqual(@as(usize, 1), first.received.items.len);
    try std.testing.expectEqual(@as(SessionId, 1), first.received.items[0].session);
    try std.testing.expectEqualStrings("{\"n\":1}", first.received.items[0].payload_json);
    try std.testing.expectEqual(@as(usize, 1), second.received.items.len);
    try std.testing.expectEqual(@as(SessionId, 2), second.received.items[0].session);
    try std.testing.expectEqual(@as(usize, 0), other.received.items.len);
}

test "subscribing twice is one subscription" {
    var broker = Broker.init(std.testing.allocator);
    defer broker.deinit();

    var recorder = Recorder.init(std.testing.allocator);
    defer recorder.deinit();

    try broker.subscribe(1, "t", recorder.receiver());
    try broker.subscribe(1, "t", recorder.receiver());

    try std.testing.expectEqual(@as(usize, 1), broker.subscriberCount("t"));
    // One delivery, not two: a reconnect that re-inits the session must not duplicate the view.
    try std.testing.expectEqual(@as(usize, 1), try broker.publish("t", "{}"));
    try std.testing.expectEqual(@as(usize, 1), recorder.received.items.len);
}

test "a terminated session stops receiving, and its topics are released" {
    var broker = Broker.init(std.testing.allocator);
    defer broker.deinit();

    var gone = Recorder.init(std.testing.allocator);
    defer gone.deinit();
    var staying = Recorder.init(std.testing.allocator);
    defer staying.deinit();

    try broker.subscribe(1, "a", gone.receiver());
    try broker.subscribe(1, "b", gone.receiver());
    try broker.subscribe(2, "a", staying.receiver());

    broker.unsubscribeAll(1);

    try std.testing.expectEqual(@as(usize, 1), broker.subscriberCount("a"));
    try std.testing.expectEqual(@as(usize, 0), broker.subscriberCount("b"));
    try std.testing.expectEqual(@as(usize, 0), try broker.publish("b", "{}"));

    try std.testing.expectEqual(@as(usize, 1), try broker.publish("a", "{}"));
    try std.testing.expectEqual(@as(usize, 0), gone.received.items.len);
    try std.testing.expectEqual(@as(SessionId, 2), staying.received.items[0].session);
}

test "messages carry a monotonic sequence, in publication order" {
    var broker = Broker.init(std.testing.allocator);
    defer broker.deinit();

    var recorder = Recorder.init(std.testing.allocator);
    defer recorder.deinit();

    try broker.subscribe(1, "t", recorder.receiver());

    _ = try broker.publish("t", "first");
    _ = try broker.publish("t", "second");
    _ = try broker.publish("t", "third");

    try std.testing.expectEqual(@as(usize, 3), recorder.received.items.len);
    try std.testing.expectEqualStrings("first", recorder.received.items[0].payload_json);
    try std.testing.expectEqualStrings("third", recorder.received.items[2].payload_json);
    // A subscriber can tell where it is, and notice a gap, from these alone.
    try std.testing.expect(recorder.received.items[0].seq < recorder.received.items[1].seq);
    try std.testing.expect(recorder.received.items[1].seq < recorder.received.items[2].seq);
}

test "a topic with no subscribers is not an error" {
    var broker = Broker.init(std.testing.allocator);
    defer broker.deinit();

    // The ordinary case for a worker whose sessions have gone: the publish is still counted, and the
    // durable path (the outbox) is what makes the event recoverable.
    try std.testing.expectEqual(@as(usize, 0), try broker.publish("nobody", "{}"));
    try std.testing.expectEqual(@as(u64, 1), broker.published);
}
