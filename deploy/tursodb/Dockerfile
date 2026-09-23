# The Turso sync server the vendored SDK Kit synchronizes against.
#
# The commit is pinned to the *same* upstream revision the SDK Kit is compiled from (see
# deps/turso/build.zig.zon, which pins the native SDK to this hash): the binding checks the runtime
# version it finds, so a server from a different revision is refused rather than silently mismatched.
#
# Build is from source on purpose — there are no published binaries — and the upstream ships this shape
# itself in its own Dockerfile.cli, which this follows.
FROM rust:1.88.0-bookworm AS builder

WORKDIR /src

RUN git clone --filter=blob:none https://github.com/tursodatabase/turso . \
 && git checkout 6e527a75595576790566f3d36560fbe95c5d87a2

RUN cargo build --release --package turso_cli

FROM debian:bookworm-slim

RUN useradd --system --uid 10001 --create-home tursodb

COPY --from=builder /src/target/release/tursodb /usr/local/bin/tursodb

# The database lives on a mounted volume (see fly.toml), so the server can be replaced without losing it.
RUN mkdir -p /data && chown tursodb:tursodb /data

USER tursodb
WORKDIR /data

# --sync-server is the address the synchronization routes are served on (/pull-updates, /v2/pipeline);
# the database file is the positional argument. There is no authentication in this server, which is why
# the Fly app is deployed without a public service and is reached only through `fly proxy`.
# `[::]` rather than `0.0.0.0`: Fly's private network is IPv6, so a proxy or another app machine
# reaches this one over 6PN and an IPv4-only listener resets the connection. A wildcard IPv6 socket
# accepts IPv4 as well (Linux defaults to bindv6only=0), so both paths work.
ENTRYPOINT ["/usr/local/bin/tursodb", "--sync-server", "[::]:8080", "/data/server.db"]
