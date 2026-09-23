//! zix gRPC namespace: gRPC h2c server and client.
//! h2c transport (cleartext). TLS termination via a reverse proxy.

const core_mod = @import("core.zig");
const config_mod = @import("config.zig");
const status_mod = @import("status.zig");
const frame_mod = @import("frame.zig");
const proto_mod = @import("proto.zig");
const timeout_mod = @import("timeout.zig");
const client_mod = @import("client.zig");

// --------------------------------------------------------- //

pub const Server = @import("server.zig").GrpcServer;
pub const Client = client_mod.GrpcClient;
pub const ServerConfig = config_mod.GrpcServerConfig;
pub const ClientConfig = config_mod.GrpcClientConfig;
pub const HandlerFn = core_mod.HandlerFn;
pub const Route = core_mod.Route;
pub const Router = core_mod.Router;
pub const ServeOpts = core_mod.GrpcServeOpts;
pub const serveConn = core_mod.serveGrpcConn;
pub const Request = core_mod.GrpcRequest;
pub const Response = core_mod.GrpcResponse;
pub const Context = core_mod.GrpcContext;
pub const ResponseCache = @import("../../../utils/response_cache.zig").ResponseCache;
pub const setCache = core_mod.setCache;
pub const cacheTtl = core_mod.cacheTtl;
pub const Status = status_mod.GrpcStatus;
pub const ContentType = core_mod.GrpcContentType;
pub const Path = core_mod.GrpcPath;
pub const parsePath = core_mod.parsePath;
pub const detectContentType = core_mod.detectContentType;

pub const ClientResponse = client_mod.GrpcClientResponse;

// --------------------------------------------------------- //

pub const Prefix = frame_mod.GrpcPrefix;
pub const readPrefix = frame_mod.readGrpcPrefix;
pub const writePrefix = frame_mod.writeGrpcPrefix;
pub const sendHeadersFD = frame_mod.sendGrpcHeadersFD;
pub const sendDataFD = frame_mod.sendGrpcDataFD;
pub const sendTrailerFD = frame_mod.sendGrpcTrailerFD;
pub const sendErrorFD = frame_mod.sendGrpcErrorFD;

// --------------------------------------------------------- //

pub const WT_VARINT = proto_mod.WT_VARINT;
pub const WT_I64 = proto_mod.WT_I64;
pub const WT_LEN = proto_mod.WT_LEN;
pub const WT_I32 = proto_mod.WT_I32;
pub const encodeVarint = proto_mod.encodeVarint;
pub const decodeVarint = proto_mod.decodeVarint;
pub const encodeString = proto_mod.encodeString;
pub const encodeInt32 = proto_mod.encodeInt32;
pub const encodeDouble = proto_mod.encodeDouble;
pub const decodeDouble = proto_mod.decodeDouble;
pub const ProtoField = proto_mod.ProtoField;
pub const MessageReader = proto_mod.MessageReader;

// --------------------------------------------------------- //

pub const parseTimeout = timeout_mod.parseTimeout;
pub const wallClockNs = core_mod.wallClockNs;
pub const DispatchModel = @import("../../config.zig").DispatchModel;
