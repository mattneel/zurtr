//! zix fix namespace: FIX 4.x session protocol (SOH-delimited tag=value framing).

const core = @import("core.zig");

// --------------------------------------------------------- //

pub const Server = @import("server.zig").FixServer;
pub const ServerConfig = @import("config.zig").FixServerConfig;
pub const Client = @import("client.zig").FixClient;
pub const ClientConfig = @import("config.zig").FixClientConfig;
pub const DispatchModel = @import("../config.zig").DispatchModel;

pub const Tag = core.Tag;
pub const MsgType = core.MsgType;
pub const Field = core.Field;
pub const BuildField = core.BuildField;

pub const SOH = core.SOH;
pub const VERSION = core.VERSION;
pub const MAX_FIELDS = core.MAX_FIELDS;
pub const MAX_MSG_SIZE = core.MAX_MSG_SIZE;

pub const findMessageEnd = core.findMessageEnd;
pub const parseFields = core.parseFields;
pub const getField = core.getField;
pub const computeChecksum = core.computeChecksum;
pub const verifyChecksum = core.verifyChecksum;
pub const buildMessage = core.buildMessage;
pub const ServeOpts = core.FixServeOpts;
pub const serveConn = core.serveConn;

pub const HandlerFn = core.HandlerFn;
pub const Route = core.FixRoute;
pub const Request = core.FixRequest;
pub const Response = core.FixResponse;
pub const Context = core.FixContext;
pub const Router = @import("router.zig").FixRouter;
pub const wallClockNs = core.wallClockNs;
