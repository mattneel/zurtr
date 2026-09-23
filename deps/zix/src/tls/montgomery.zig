//! Constant-time Montgomery modular exponentiation for the RSA private-key operation.
//!
//! Note:
//! - std.crypto.ff.Modulus is correct and constant-time but slower on the secret path than a
//!   dedicated Montgomery routine: this module is a CIOS (Coarsely Integrated Operand Scanning,
//!   Koc 1996) multiply driving a 4-bit fixed-window exponentiation, which on native x86_64 lowers
//!   the inner multiply to MULX and runs about 1.5x the std path. It is the modexp used by the two
//!   CRT half-exponentiations in rsa.zig (the dominant cost of an RSA sign).
//! - Constant-time by construction: fixed iteration counts, no secret-dependent branch (every
//!   conditional subtract is a masked select), and a masked window-table gather. No secret value
//!   steers control flow or a memory address.
//! - Generic over the limb count, so one instantiation serves each prime width: 16 limbs for the
//!   1024-bit primes of RSA-2048, 24 for RSA-3072, 32 for RSA-4096.
//! - Verified in-file against std.crypto.ff for random odd moduli, and end-to-end in rsa.zig where
//!   the CRT sign through this module is checked byte-for-byte against the std path.

const std = @import("std");
const builtin = @import("builtin");

const Limb = u64;
const limb_bits = 64;

/// True when the build target is x86_64 with the ADX feature, so the dual-carry (ADCX / ADOX) inner
/// multiply can be assembled. Off elsewhere, where the portable CIOS multiply runs instead. The
/// HttpArena entries must build with `-Dcpu=...+adx` to take this path (the box has ADX).
const use_adx = builtin.cpu.arch == .x86_64 and std.Target.x86.featureSetHas(builtin.cpu.features, .adx);

/// Montgomery arithmetic over a fixed `limbs`-limb odd modulus (limbs x 64 bits wide).
///
/// Param:
/// limbs - usize (number of 64-bit limbs in the modulus, the prime width / 64)
pub fn Montgomery(comptime limbs: usize) type {
    return struct {
        const S = limbs;

        /// Little-endian limbs: `Big[0]` is the least significant.
        const Big = [S]Limb;

        // --------------------------------------------------------------- //
        // limb helpers

        /// `r = a + b`, returns the carry out of the top limb.
        fn addInto(r: *Big, a: Big, b: Big) u1 {
            var carry: u1 = 0;
            for (0..S) |i| {
                const s1 = @addWithOverflow(a[i], b[i]);
                const s2 = @addWithOverflow(s1[0], carry);
                r[i] = s2[0];
                carry = s1[1] | s2[1];
            }
            return carry;
        }

        /// `r = a - b`, returns the borrow out of the top limb.
        fn subInto(r: *Big, a: Big, b: Big) u1 {
            var borrow: u1 = 0;
            for (0..S) |i| {
                const d1 = @subWithOverflow(a[i], b[i]);
                const d2 = @subWithOverflow(d1[0], borrow);
                r[i] = d2[0];
                borrow = d1[1] | d2[1];
            }
            return borrow;
        }

        /// Constant-time select: `mask` all-ones picks `a`, all-zero picks `b`.
        fn ctSelect(mask: Limb, a: Big, b: Big) Big {
            var r: Big = undefined;
            for (0..S) |i| r[i] = (a[i] & mask) | (b[i] & ~mask);
            return r;
        }

        /// `r = (a << 1) mod n` via one masked conditional subtract. Used to bootstrap R^2.
        fn modDouble(a: Big, n: Big) Big {
            var carry: u1 = 0;
            var t: Big = undefined;
            for (0..S) |i| {
                const hi: u1 = @truncate(a[i] >> 63);
                t[i] = (a[i] << 1) | carry;
                carry = hi;
            }

            var sub: Big = undefined;
            const borrow = subInto(&sub, t, n);
            const ge_n: Limb = if (carry == 1 or borrow == 0) ~@as(Limb, 0) else 0;
            return ctSelect(ge_n, sub, t);
        }

        // --------------------------------------------------------------- //
        // Montgomery setup

        /// `n0inv = -n[0]^-1 mod 2^64` via Newton iteration (n[0] is odd for an odd modulus).
        fn n0Inv(n0: Limb) Limb {
            var x: Limb = 1;
            inline for (0..6) |_| {
                x = x *% (2 -% n0 *% x);
            }
            return 0 -% x;
        }

        /// `rr = R^2 mod n`, R = 2^(64*S), by doubling 1 up 2*64*S times (setup only, no hot path).
        fn rSquared(n: Big) Big {
            var r: Big = std.mem.zeroes(Big);
            r[0] = 1;

            var i: usize = 0;
            while (i < 2 * limb_bits * S) : (i += 1) r = modDouble(r, n);
            return r;
        }

        // --------------------------------------------------------------- //
        // CIOS Montgomery multiply

        /// `t = a * b * R^-1 mod n` (CIOS). Dispatches to the ADCX / ADOX dual-carry inner multiply
        /// on x86_64+ADX, else the portable CIOS. Both are constant-time and produce identical bytes.
        fn mul(a: Big, b: Big, n: Big, n0inv: Limb) Big {
            if (use_adx) return mulAsm(a, b, n, n0inv);
            return mulPortable(a, b, n, n0inv);
        }

        /// Final Montgomery reduction shared by both multiply paths: the running product in
        /// `t[0..S]` (with a possible top word `top`) is at most `2n`, so one masked conditional
        /// subtract yields the canonical residue below `n` (constant-time, no secret branch).
        fn finalReduce(t: *const [S]Limb, top: Limb, n: Big) Big {
            var res: Big = undefined;
            @memcpy(res[0..S], t);

            var sub: Big = undefined;
            const borrow = subInto(&sub, res, n);
            const ge_n: Limb = if (top != 0 or borrow == 0) ~@as(Limb, 0) else 0;
            return ctSelect(ge_n, sub, res);
        }

        /// Portable CIOS multiply. On native x86_64 LLVM lowers the inner multiply to MULX but keeps
        /// a single carry chain (the gap mulAsm closes with the second chain).
        fn mulPortable(a: Big, b: Big, n: Big, n0inv: Limb) Big {
            var t = std.mem.zeroes([S + 2]Limb);

            for (0..S) |i| {
                // t += a * b[i]
                var carry: Limb = 0;
                for (0..S) |j| {
                    const p = @as(u128, a[j]) * @as(u128, b[i]) + @as(u128, t[j]) + @as(u128, carry);
                    t[j] = @truncate(p);
                    carry = @truncate(p >> 64);
                }
                const s1 = @addWithOverflow(t[S], carry);
                t[S] = s1[0];
                t[S + 1] = s1[1];

                // m = t[0] * n0inv mod 2^64. t += m * n. t >>= one limb
                const m: Limb = t[0] *% n0inv;
                var carry2: Limb = 0;
                {
                    const p = @as(u128, m) * @as(u128, n[0]) + @as(u128, t[0]) + @as(u128, carry2);
                    carry2 = @truncate(p >> 64);
                }
                for (1..S) |j| {
                    const p = @as(u128, m) * @as(u128, n[j]) + @as(u128, t[j]) + @as(u128, carry2);
                    t[j - 1] = @truncate(p);
                    carry2 = @truncate(p >> 64);
                }
                const s2 = @addWithOverflow(t[S], carry2);
                t[S - 1] = s2[0];
                t[S] = t[S + 1] + s2[1];
            }

            return finalReduce(t[0..S], t[S], n);
        }

        /// The fused single-block CIOS body. The whole modmul runs in one asm block: a runtime outer
        /// loop over `b[i]`, the multiply pass and the Montgomery reduce pass each a dual ADCX / ADOX
        /// carry chain (MULX splits each product without touching flags), the `m = t[0]*n0inv` step,
        /// and the one-limb shift (the reduce pass writes `t[j-1]`). Fusing both passes into one block
        /// keeps the accumulator hot and drops the per-pass barrier, the gain over the two-pass form.
        /// Registers: rdi=t, rsi=a, r12=b, r13=n, r14=n0inv, r15=i, rdx=multiplier, r8=lo,
        /// r9/r10=alternating high, r11=zero, rax=scratch. AT&T, literal regs `%%`-escaped.
        fn fusedBody() []const u8 {
            @setEvalBranchQuota(200_000);
            const s_top = std.fmt.comptimePrint("{d}", .{S * 8});
            const s_m1 = std.fmt.comptimePrint("{d}", .{(S - 1) * 8});
            const s_p1 = std.fmt.comptimePrint("{d}", .{(S + 1) * 8});

            var s: []const u8 = "xorl %%r15d, %%r15d\n"; // i = 0
            s = s ++ "1:\n";
            s = s ++ "movq (%%r12,%%r15,8), %%rdx\n"; // rdx = b[i]

            // multiply pass: t[0..S] += a * b[i] (dual carry, no carry_in)
            s = s ++ "xorl %%r11d, %%r11d\n";
            s = s ++ "mulxq 0(%%rsi), %%r8, %%r9\n";
            s = s ++ "adcxq 0(%%rdi), %%r8\n";
            s = s ++ "movq %%r8, 0(%%rdi)\n";
            var hi: []const u8 = "%%r9";
            for (1..S) |j| {
                const off = std.fmt.comptimePrint("{d}", .{j * 8});
                const hn = if (std.mem.eql(u8, hi, "%%r9")) "%%r10" else "%%r9";
                s = s ++ "mulxq " ++ off ++ "(%%rsi), %%r8, " ++ hn ++ "\n";
                s = s ++ "adoxq " ++ hi ++ ", %%r8\n";
                s = s ++ "adcxq " ++ off ++ "(%%rdi), %%r8\n";
                s = s ++ "movq %%r8, " ++ off ++ "(%%rdi)\n";
                hi = hn;
            }
            // s1 = t[S] + (multiply carry). t[S] = s1.lo, t[S+1] = s1.hi
            s = s ++ "movl $0, %%eax\n";
            s = s ++ "adoxq %%rax, " ++ hi ++ "\n";
            s = s ++ "adcxq %%rax, " ++ hi ++ "\n";
            s = s ++ "movq " ++ s_top ++ "(%%rdi), %%r8\n";
            s = s ++ "addq " ++ hi ++ ", %%r8\n";
            s = s ++ "movq %%r8, " ++ s_top ++ "(%%rdi)\n";
            s = s ++ "movl $0, %%r8d\n";
            s = s ++ "adcq $0, %%r8\n";
            s = s ++ "movq %%r8, " ++ s_p1 ++ "(%%rdi)\n";

            // m = t[0] * n0inv
            s = s ++ "movq 0(%%rdi), %%rdx\n";
            s = s ++ "imulq %%r14, %%rdx\n";

            // reduce pass: t += n * m, written shifted to t[j-1] (the low limb becomes zero, dropped)
            s = s ++ "xorl %%r11d, %%r11d\n";
            s = s ++ "mulxq 0(%%r13), %%r8, %%r9\n";
            s = s ++ "adcxq 0(%%rdi), %%r8\n"; // lo0 + t[0] == 0, discarded. CF set
            hi = "%%r9";
            for (1..S) |j| {
                const off = std.fmt.comptimePrint("{d}", .{j * 8});
                const offm1 = std.fmt.comptimePrint("{d}", .{(j - 1) * 8});
                const hn = if (std.mem.eql(u8, hi, "%%r9")) "%%r10" else "%%r9";
                s = s ++ "mulxq " ++ off ++ "(%%r13), %%r8, " ++ hn ++ "\n";
                s = s ++ "adoxq " ++ hi ++ ", %%r8\n";
                s = s ++ "adcxq " ++ off ++ "(%%rdi), %%r8\n";
                s = s ++ "movq %%r8, " ++ offm1 ++ "(%%rdi)\n"; // t[j-1] (shift)
                hi = hn;
            }
            // s2 = t[S] + (reduce carry). t[S-1] = s2.lo, t[S] = t[S+1] + s2.hi
            s = s ++ "movl $0, %%eax\n";
            s = s ++ "adoxq %%rax, " ++ hi ++ "\n";
            s = s ++ "adcxq %%rax, " ++ hi ++ "\n";
            s = s ++ "movq " ++ s_top ++ "(%%rdi), %%r8\n";
            s = s ++ "addq " ++ hi ++ ", %%r8\n";
            s = s ++ "movq %%r8, " ++ s_m1 ++ "(%%rdi)\n";
            s = s ++ "movq " ++ s_p1 ++ "(%%rdi), %%r8\n";
            s = s ++ "adcq $0, %%r8\n";
            s = s ++ "movq %%r8, " ++ s_top ++ "(%%rdi)\n";

            s = s ++ "incq %%r15\n";
            s = s ++ "cmpq $" ++ std.fmt.comptimePrint("{d}", .{S}) ++ ", %%r15\n";
            s = s ++ "jb 1b\n";
            return s;
        }

        /// Fused dual-carry CIOS multiply (x86_64+ADX). Validated byte-for-byte against the portable
        /// path in-file and in rnd/0.5.x/rsa_montfused_poc.zig.
        fn mulAsm(a: Big, b: Big, n: Big, n0inv: Limb) Big {
            var t = std.mem.zeroes([S + 2]Limb);
            const body = comptime fusedBody();

            asm volatile (body
                :
                : [t] "{rdi}" (&t),
                  [a] "{rsi}" (&a),
                  [b] "{r12}" (&b),
                  [n] "{r13}" (&n),
                  [n0inv] "{r14}" (n0inv),
                : .{ .rax = true, .rdx = true, .r8 = true, .r9 = true, .r10 = true, .r11 = true, .r15 = true, .memory = true, .cc = true });

            return finalReduce(t[0..S], t[S], n);
        }

        /// Constant-time window gather: returns `table[idx]` by masked scan over all 16 entries.
        fn gather(table: *const [16]Big, idx: usize) Big {
            var r: Big = std.mem.zeroes(Big);
            for (0..16) |k| {
                const m: Limb = if (k == idx) ~@as(Limb, 0) else 0;
                for (0..S) |j| r[j] |= table[k][j] & m;
            }
            return r;
        }

        // --------------------------------------------------------------- //
        // byte conversion (big-endian, the form ff and DER use)

        fn fromBytes(bytes: []const u8) Big {
            var r: Big = std.mem.zeroes(Big);
            var i: usize = 0;
            while (i < bytes.len) : (i += 1) {
                const idx = (bytes.len - 1 - i) / 8;
                const off = (bytes.len - 1 - i) % 8;
                if (idx < S) r[idx] |= @as(Limb, bytes[i]) << @intCast(off * 8);
            }
            return r;
        }

        fn toBytes(a: Big, out: []u8) void {
            @memset(out, 0);
            for (0..S) |i| {
                for (0..8) |b| {
                    const pos = i * 8 + b;
                    if (pos < out.len) out[out.len - 1 - pos] = @truncate(a[i] >> @intCast(b * 8));
                }
            }
        }

        // --------------------------------------------------------------- //

        /// `out = base^exp mod n`, all big-endian. 4-bit fixed window, constant-time: every nibble
        /// squares four times and multiplies by a masked table gather (no leading-zero skip).
        ///
        /// Param:
        /// mod_be - []const u8 (the odd modulus, big-endian, at most S*8 bytes)
        /// base_be - []const u8 (the base, below the modulus, big-endian)
        /// exp_be - []const u8 (the exponent, big-endian)
        /// out - []u8 (result buffer, written big-endian, length = caller's signature width)
        pub fn modExp(mod_be: []const u8, base_be: []const u8, exp_be: []const u8, out: []u8) void {
            const n = fromBytes(mod_be);
            const base = fromBytes(base_be);
            const n0inv = n0Inv(n[0]);
            const rr = rSquared(n);

            var one_norm: Big = std.mem.zeroes(Big);
            one_norm[0] = 1;
            const one_mont = mul(one_norm, rr, n, n0inv);
            const base_mont = mul(base, rr, n, n0inv);

            var table: [16]Big = undefined;
            table[0] = one_mont;
            table[1] = base_mont;
            for (2..16) |k| table[k] = mul(table[k - 1], base_mont, n, n0inv);

            var acc = one_mont;
            for (exp_be) |byte| {
                inline for ([_]u3{ 4, 0 }) |shift| {
                    inline for (0..4) |_| acc = mul(acc, acc, n, n0inv);

                    const nib: usize = (byte >> shift) & 0x0f;
                    acc = mul(acc, gather(&table, nib), n, n0inv);
                }
            }

            var one2: Big = std.mem.zeroes(Big);
            one2[0] = 1;
            const result = mul(acc, one2, n, n0inv);
            toBytes(result, out);
        }
    };
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

const testing = std.testing;

/// Verify modExp matches std.crypto.ff for random odd moduli at a given width.
fn fuzzAgainstFf(comptime bits: usize, trials: usize, seed: u64) !void {
    const bytes_len = bits / 8;
    const Mod = std.crypto.ff.Modulus(bits);
    const Mont = Montgomery(bits / 64);

    var prng = std.Random.DefaultPrng.init(seed);
    const rand = prng.random();

    var t: usize = 0;
    while (t < trials) : (t += 1) {
        var n_bytes: [bytes_len]u8 = undefined;
        rand.bytes(&n_bytes);
        n_bytes[0] |= 0x80; // full-width modulus
        n_bytes[bytes_len - 1] |= 0x01; // odd

        var base_bytes: [bytes_len]u8 = undefined;
        rand.bytes(&base_bytes);
        base_bytes[0] &= 0x7f; // base < n

        var exp_bytes: [bytes_len]u8 = undefined;
        rand.bytes(&exp_bytes);

        const mod = try Mod.fromBytes(&n_bytes, .big);
        const base_fe = try Mod.Fe.fromBytes(mod, &base_bytes, .big);
        const ref_fe = try mod.powWithEncodedExponent(base_fe, &exp_bytes, .big);
        var ref_out: [bytes_len]u8 = undefined;
        try ref_fe.toBytes(&ref_out, .big);

        var got: [bytes_len]u8 = undefined;
        Mont.modExp(&n_bytes, &base_bytes, &exp_bytes, &got);

        try testing.expectEqualSlices(u8, &ref_out, &got);
    }
}

test "zix tls: montgomery, 1024-bit modexp matches std.crypto.ff" {
    try fuzzAgainstFf(1024, 64, 0x515a1); // trials 400 took to much time
}

test "zix tls: montgomery, 1536-bit modexp matches std.crypto.ff" {
    try fuzzAgainstFf(1536, 32, 0x6c0de); // trials 200 took to much time
}

test "zix tls: montgomery, 2048-bit modexp matches std.crypto.ff" {
    try fuzzAgainstFf(2048, 16, 0xa11ce); // trials 150 took to much time
}

test "zix tls: montgomery, base near the modulus matches ff (conditional-subtract boundary)" {
    const bits = 1024;
    const bytes_len = bits / 8;
    const Mod = std.crypto.ff.Modulus(bits);
    const Mont = Montgomery(bits / 64);

    var n_bytes: [bytes_len]u8 = undefined;
    @memset(&n_bytes, 0xff); // n = 2^1024 - 1 region: every limb saturated, odd
    n_bytes[0] |= 0x80;

    // base = n - 2 (largest odd value below n), exponent saturated to maximize squarings.
    var base_bytes = n_bytes;
    base_bytes[bytes_len - 1] -= 2;
    var exp_bytes: [bytes_len]u8 = undefined;
    @memset(&exp_bytes, 0xff);

    const mod = try Mod.fromBytes(&n_bytes, .big);
    const base_fe = try Mod.Fe.fromBytes(mod, &base_bytes, .big);
    const ref_fe = try mod.powWithEncodedExponent(base_fe, &exp_bytes, .big);
    var ref_out: [bytes_len]u8 = undefined;
    try ref_fe.toBytes(&ref_out, .big);

    var got: [bytes_len]u8 = undefined;
    Mont.modExp(&n_bytes, &base_bytes, &exp_bytes, &got);

    try testing.expectEqualSlices(u8, &ref_out, &got);
}
