//! zix tls namespace: TLS 1.3 server layer (RFC 8446).
//!
//! Sans-I/O: drive a handshake with `serverHandshake`, then read / write application records
//! through the returned `Connection`. The caller owns the socket loop. cleartext stays the
//! default, https is an opt-in path on its own perf band.

const connection = @import("connection.zig");
const extensions = @import("extensions.zig");
const handshake = @import("handshake.zig");
const record = @import("record.zig");
const alert = @import("alert.zig");

// --------------------------------------------------------------- //

pub const Connection = connection.Connection;
pub const HandshakeOptions = connection.HandshakeOptions;
/// The server signing key (ECDSA P-256 or Ed25519), matching the certificate's key type.
pub const SigningKey = @import("certificate.zig").SigningKey;

/// Server-side TLS context (the loaded cert/key + validated policy, the SSL_CTX analog). Built once
/// with Context.init, attached to the HTTP server config by pointer (tls: ?*Tls.Context), the https
/// opt-in gate. Context.Config is the plain settings struct, mirroring Logger / Logger.Config.
pub const Context = @import("context.zig").Context;
pub const Version = @import("context.zig").Version;
/// The curve / cipher sets zix implements, the secure defaults for Context.Config.
pub const default_curves = @import("context.zig").default_curves;
pub const default_ciphers = @import("context.zig").default_ciphers;
pub const HandshakeResult = connection.HandshakeResult;
pub const serverHandshake = connection.serverHandshake;

/// HelloRetryRequest (RFC 8446 4.1.4): serverHelloRetry emits the HRR when the client's group has no
/// key_share (null = no retry needed), serverHandshakeAfterRetry resumes on the second ClientHello.
pub const serverHelloRetry = connection.serverHelloRetry;
pub const serverHandshakeAfterRetry = connection.serverHandshakeAfterRetry;
pub const RetryState = connection.RetryState;
pub const RetryFlight = connection.RetryFlight;

pub const alertForError = connection.alertForError;
pub const alertRecordForError = connection.alertRecordForError;

/// The client-side handshakes (the mirror of the server). zix.Tls.Client = TLS 1.3,
/// zix.Tls.Client12 = TLS 1.2. Each exposes start / finish + a ClientConnection (sans-I/O).
pub const Client = @import("client.zig");
pub const Client12 = @import("tls12_client.zig");

/// The server-side TLS 1.2 handshake (RFC 5246, ECDHE-ECDSA): serverFlight1 answers the
/// ClientHello, serverFinish completes the handshake into a 1.2 Connection (sans-I/O).
pub const Server12 = @import("tls12_connection.zig");

/// Layer V: peer certificate verification (the trust step of mTLS).
/// verifyCertChain = chain + validity (RFC 5280). verifyCertHostname = identity (RFC 6125).
pub const verifyCertChain = @import("cert_verify.zig").verifyCertChain;
pub const verifyCertHostname = @import("cert_verify.zig").verifyCertHostname;
/// DNS-or-IP-SAN identity check (for the https misdirected-request 421 gate).
pub const verifyCertIdentity = @import("cert_verify.zig").verifyCertIdentity;

/// Multi-cert chain validation (RFC 5280 6.1): verify a [leaf, intermediate, ...] chain to an
/// anchor, enforcing cA / keyCertSign / pathLen / critical-ext beyond the per-link signature.
pub const verifyChain = @import("cert_verify.zig").verifyChain;

/// PEM to DER decode (a single block), for loading a cert / trust anchor from a .pem file.
pub const pemToDer = @import("pem.zig").pemToDer;

/// Check an RSA signature with std's verifier, the way a peer would (RFC 8017 8.1.2 and 8.2.2).
/// Independent of zix's own RSA code, and spelled the same on both supported Zig versions.
pub const verifyRsaPss = @import("std_rsa_verify.zig").verifyPss;
pub const verifyRsaPkcs1v15 = @import("std_rsa_verify.zig").verifyPkcs1v15;
/// False on a Zig whose own PSS verifier is broken, see std_rsa_verify.zig. Temporary, zig 0.17
/// only. zix signs and verifies PSS itself, so nothing it ships is affected.
pub const std_pss_verify_usable = @import("std_rsa_verify.zig").PSS_USABLE;

pub const Alpn = extensions.Alpn;
pub const Alert = alert.Alert;
pub const fatal_record_len = alert.fatal_record_len;

/// Inbound alert handling (RFC 8446 6): parseInboundAlert classifies a received alert body,
/// AlertInbound.isCloseNotify / isFatal decide whether the closure is clean or fatal.
pub const AlertInbound = alert.Inbound;
pub const parseInboundAlert = alert.parseInbound;
pub const ContentType = record.ContentType;
pub const CipherSuite = handshake.CipherSuite;
pub const NamedGroup = handshake.NamedGroup;

/// Record-layer bounds for a caller that owns its own socket loop: max_plaintext caps one
/// record's payload, max_record_wire sizes a full-record read buffer, sealedLen sizes the
/// sealed output for a given plaintext length.
pub const max_plaintext = record.max_plaintext;
pub const max_record_wire = record.max_record_wire;
pub const sealedLen = record.sealedLen;
