//! zix tls std rsa verify: std's RSA verify across both supported toolchains

const std = @import("std");

const ZIG_SEMVER = @import("../lib.zig").ZIG_SEMVER;

const StdRsa = std.crypto.Certificate.rsa;

/// Whether std takes an RSA signature as a pointer rather than by value.
///
/// Note:
/// - Zig 0.16 declares `sig: [modulus_len]u8`, zig 0.17 declares
///   `sig: *const [modulus_len]u8`. The branch this toolchain does not
///   have never reaches the compiler, the condition is comptime.
/// - Not temporary: it follows a real std API change, and stays until
///   this project drops zig 0.16.
const SIG_BY_POINTER: bool = ZIG_SEMVER.MINOR != 16;

/// Whether std's PSS verifier can be called at all on this toolchain.
///
/// Note:
/// - Zig 0.17 broke it twice: `verify` hands its by-value signature to a
///   `concatVerify` that now wants a pointer, and `EMSA_PSS_VERIFY`
///   memmoves 8 bytes into a 72-byte slice, so every call panics.
/// - Only the cross-checks against std are affected. zix signs and
///   verifies PSS itself, and std verifies chains without PSS.
/// - Temporary, zig 0.17 only. Delete this and its three call-site guards
///   when std is fixed, verifyPss below is already the correct call.
pub const PSS_USABLE: bool = ZIG_SEMVER.MINOR == 16;

/// Verify an RSASSA-PSS signature through std's verifier (rfc 8017 8.1.2).
///
/// Note:
/// - Independent of zix's own PSS code on purpose: it is what a peer runs
///   against a signature zix produced.
/// - Goes to `concatVerify` on both toolchains, because zig 0.17's
///   `verify` does not compile and never did anything else.
/// - Check PSS_USABLE first, std's verifier panics on zig 0.17.
///
/// Param:
/// modulus_len - usize (comptime, key size in bytes, 256 for RSA-2048)
/// sig - *const [modulus_len]u8 (the signature, exactly one modulus wide)
/// msg - []const u8 (the signed content)
/// public_key - StdRsa.PublicKey (the key to check against)
/// Hash - type (comptime, the PSS hash, i.e. std.crypto.hash.sha2.Sha256)
///
/// Return:
/// - void when the signature verifies
/// - error.InvalidSignature, or any std encrypt error
pub fn verifyPss(
    comptime modulus_len: usize,
    sig: *const [modulus_len]u8,
    msg: []const u8,
    public_key: StdRsa.PublicKey,
    comptime Hash: type,
) !void {
    if (SIG_BY_POINTER) return StdRsa.PSSSignature.concatVerify(modulus_len, sig, &.{msg}, public_key, Hash);

    return StdRsa.PSSSignature.concatVerify(modulus_len, sig.*, &.{msg}, public_key, Hash);
}

/// Verify an RSASSA-PKCS1-v1_5 signature through std's verifier (rfc 8017 8.2.2).
///
/// Note:
/// - Same purpose as verifyPss: the check a peer runs, not zix's own.
///
/// Param:
/// modulus_len - usize (comptime, key size in bytes, 256 for RSA-2048)
/// sig - *const [modulus_len]u8 (the signature, exactly one modulus wide)
/// msg - []const u8 (the signed content)
/// public_key - StdRsa.PublicKey (the key to check against)
/// Hash - type (comptime, the digest the signature names)
///
/// Return:
/// - void when the signature verifies
/// - error.InvalidSignature, or any std encrypt error
pub fn verifyPkcs1v15(
    comptime modulus_len: usize,
    sig: *const [modulus_len]u8,
    msg: []const u8,
    public_key: StdRsa.PublicKey,
    comptime Hash: type,
) !void {
    if (SIG_BY_POINTER) return StdRsa.PKCS1v1_5Signature.verify(modulus_len, sig, msg, public_key, Hash);

    return StdRsa.PKCS1v1_5Signature.verify(modulus_len, sig.*, msg, public_key, Hash);
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix tls: std rsa verify, both constants follow the running toolchain" {
    // Neither may be pinned: 0.16 takes the signature by value and can call
    // std's PSS verifier, 0.17 takes a pointer and cannot.
    const on_016 = ZIG_SEMVER.MINOR == 16;

    try std.testing.expectEqual(!on_016, SIG_BY_POINTER);
    try std.testing.expectEqual(on_016, PSS_USABLE);
}
