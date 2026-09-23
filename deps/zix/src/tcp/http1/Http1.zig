//! zix http1 namespace

const core = @import("core.zig");
const router = @import("router.zig");

// --------------------------------------------------------- //

pub const Server = @import("server.zig").Server;
pub const ServerConfig = @import("config.zig").Http1ServerConfig;
pub const DispatchModel = @import("../config.zig").DispatchModel;

pub const HandlerFn = core.HandlerFn;
pub const ParsedHead = core.ParsedHead;
pub const ParseResult = core.ParseResult;
pub const Range = core.Range;
pub const ServeOpts = core.ServeOpts;
pub const ConnOutcome = core.ConnOutcome;

pub const Route = router.Route;
pub const RouteKind = router.RouteKind;
pub const Router = router.Router;
pub const PathParam = router.PathParam;
pub const pathParam = router.pathParam;

pub const Request = @import("request.zig").Request;
pub const Response = @import("response.zig").Response;
pub const Context = @import("context.zig").Context;

pub const Method = @import("method.zig");
pub const Status = @import("status.zig");
pub const Content = @import("content.zig");
pub const ContentType = @import("content.zig").Type;
pub const SseWriter = @import("response.zig").SseWriter;
pub const Header = @import("response.zig").HttpHeader;
pub const HeaderSize = @import("response.zig").HeaderSize;
pub const Multipart = @import("../../utils/multipart.zig").Parser;
pub const MultipartField = @import("../../utils/multipart.zig").Field;

pub const WebSocket = @import("websocket.zig");
pub const WsFrameFn = core.WsFrameFn;

// --------------------------------------------------------- //

pub const setTimeout = core.setTimeout;
pub const isExpired = core.isExpired;

pub const parseHead = core.parseHead;
pub const parseErrorResponse = core.parseErrorResponse;
pub const getHeader = core.getHeader;
pub const acceptEncoding = core.acceptEncoding;
pub const queryParam = core.queryParam;
pub const percentDecode = core.percentDecode;
pub const parseRange = core.parseRange;

pub const cacheLookup = core.cacheLookup;
pub const cacheStore = core.cacheStore;
pub const cacheLookupEncoded = core.cacheLookupEncoded;
pub const cacheStoreEncoded = core.cacheStoreEncoded;
pub const sendGzipCachedFD = core.sendGzipCachedFD;
pub const sendWithCacheFD = core.sendWithCacheFD;
pub const cacheTtl = core.cacheTtl;
pub const ExternalFn = core.ExternalFn;
pub const setExternalHandler = core.setExternalHandler;
pub const uringWatchFd = core.uringWatchFd;
pub const setCache = core.setCache;
pub const setStatic = core.setStatic;
pub const ResponseCache = @import("../../utils/response_cache.zig").ResponseCache;

pub const writeAllFD = core.writeAllFD;
pub const responseReserve = core.responseReserve;
pub const responseCommit = core.responseCommit;
pub const flushPending = core.flushPending;
pub const beginStream = core.beginStream;
pub const sendSimpleFD = core.sendSimpleFD;
pub const sendSimpleNoBodyFD = core.sendSimpleNoBodyFD;
pub const sendJsonFD = core.sendJsonFD;
pub const sendGzipFD = core.sendGzipFD;
pub const sendBrotliFD = core.sendBrotliFD;
pub const sendBrotliCachedFD = core.sendBrotliCachedFD;
pub const sendNegotiateFD = core.sendNegotiateFD;
pub const sendNegotiateCachedFD = core.sendNegotiateCachedFD;
pub const sendChunkedStartFD = core.sendChunkedStartFD;
pub const sendChunkFD = core.sendChunkFD;
pub const sendChunkedEndFD = core.sendChunkedEndFD;
pub const sendRangeFD = core.sendRangeFD;
pub const send100ContinueFD = core.send100ContinueFD;
