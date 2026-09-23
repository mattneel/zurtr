//! zix http namespace

const config = @import("config.zig");
const client_config = @import("client_config.zig");
const client = @import("client.zig");
const response = @import("response.zig");
const request = @import("request.zig");
const context = @import("context.zig");
const router = @import("router.zig");
const content = @import("content.zig");
const multipart = @import("../../utils/multipart.zig");
const ws_client = @import("ws_client.zig");
const sse_client = @import("sse_client.zig");
const rc = @import("../../utils/response_cache.zig");

// --------------------------------------------------------- //

pub const Server = @import("server.zig").Server;
pub const ServerConfig = config.HttpServerConfig;
pub const DispatchModel = config.DispatchModel;
pub const Client = client.HttpClient;
pub const ClientConfig = client_config.HttpClientConfig;
pub const ClientVersion = client_config.Version;
pub const default_user_agent = client_config.user_agent;
pub const ClientResponse = client.ClientResponse;
pub const ClientRequestOpts = client.RequestOpts;
pub const Request = request.Request;
pub const Response = response.Response;
pub const SseWriter = response.SseWriter;
pub const ResponseCache = rc.ResponseCache;
pub const setCache = response.setCache;
pub const cacheTtl = response.cacheTtl;
pub const Context = context.Context;
pub const HandlerFn = router.HandlerFn;
pub const Route = router.Route;
pub const RouteKind = router.RouteKind;
pub const Router = router.Router;
pub const Header = response.HttpHeader;
pub const HeaderSize = response.HeaderSize;
pub const RequestHeaderSize = @import("parser.zig").RequestHeaderSize;
pub const parseErrorResponse = response.parseErrorResponse;
pub const ContentType = content.Type;
pub const Content = content;
pub const Method = @import("method.zig");
pub const Status = @import("status.zig");
pub const Multipart = multipart.Parser;
pub const MultipartField = multipart.Field;
pub const WebSocket = @import("websocket.zig");
pub const WsClient = ws_client.WsClient;
pub const WsClientConfig = ws_client.WsClientConfig;
pub const WsConn = ws_client.WsConn;
pub const WsOpcode = ws_client.Opcode;
pub const WsFrame = ws_client.Frame;
pub const SseClient = sse_client.SseClient;
pub const SseClientConfig = sse_client.SseClientConfig;
pub const SseStream = sse_client.SseStream;
pub const SseEvent = sse_client.SseEvent;
pub const Logger = @import("../../logger/logger.zig").Logger;
