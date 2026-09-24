pragma circom 2.0.2;

/*
    Scalar decomposition for 2-dimensional fake-GLV on P-256.

    Finds (u, v) with u == s*v (mod n) and |u|, |v| < 2^128 by running the
    extended Euclidean algorithm on (n, s) and stopping at the first remainder
    below sqrt(n). Every step keeps r_i == t_i * s (mod n) and

        r_{i-1} * |t_i| + r_i * |t_{i-1}| == n,

    so at the stop r_{i-1} > sqrt(n) forces |t_i| < sqrt(n). u = r_i is never
    negative. The t_i alternate in sign -- t_1 = 1 and t_i < 0 for even i --
    so only magnitudes are carried:

        |t_{i+1}| = |t_{i-1}| + q_i * |t_i|

    Witness generation only; FakeGLV2ScalarMulVerify constrains the result.
    A decomposition minimising the Euclidean norm instead (Lagrange-Gauss)
    has no such bound: empirically, it exceeds 2^128 in one coordinate for
    2,152 of 200,000 random scalars.

    Requires s < n.
*/

include "./bigint_func.circom";
include "./signed_func.circom";
include "./p256_func.circom";

// Number of limbs up to the highest non-zero one, at least 1. long_div needs
// its divisor issued at that length.
function fake_glv2_len(K, a) {
    var len = 1;
    for (var i = 0; i < K; i++) {
        if (a[i] != 0) { len = i + 1; }
    }
    return len;
}

function p256_fake_glv2_decompose(s) {
    var N = 64;
    var K = 4;
    var ord[100] = get_p256_order(N, K);
    var stop[100] = get_p256_isqrt_order();

    var r0[100];
    var r1[100];
    var t0[100];
    var t1[100];
    for (var i = 0; i < 100; i++) {
        r0[i] = 0;
        r1[i] = 0;
        t0[i] = 0;
        t1[i] = 0;
    }
    for (var i = 0; i < K; i++) {
        r0[i] = ord[i];
        r1[i] = s[i];
    }
    t1[0] = 1;
    var steps = 0;

    var more = long_gt(N, K, r1, stop);
    while (more == 1) {
        var kb = fake_glv2_len(K, r1);
        var dr[2][100] = long_div(N, kb, K - kb, r0, r1);

        // long_div writes the quotient on 0..K-kb and the remainder on 0..kb
        var q[100];
        var r2[100];
        for (var i = 0; i < 100; i++) {
            q[i] = 0;
            r2[i] = 0;
        }
        for (var i = 0; i <= K - kb; i++) { q[i] = dr[0][i]; }
        for (var i = 0; i < kb; i++) { r2[i] = dr[1][i]; }

        // every |t| stays below n, so K limbs hold q * |t_i| and the sum
        var qt[100] = prod(N, K, q, t1);
        var t2[100] = sgn_long_add(N, K, t0, qt);

        for (var i = 0; i < K; i++) {
            r0[i] = r1[i];
            r1[i] = r2[i];
            t0[i] = t1[i];
            t1[i] = t2[i];
        }
        steps = steps + 1;
        more = long_gt(N, K, r1, stop);
    }

    var out[2][2];
    out[0][0] = r1[0] + r1[1] * (1 << 64);
    out[0][1] = t1[0] + t1[1] * (1 << 64);
    out[1][0] = 0;
    out[1][1] = steps % 2;
    return out;
}
