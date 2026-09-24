pragma circom 2.0.2;

/*
    Verifying Q == [s]P on P-256 with 2-dimensional fake-GLV.

    The prover supplies the result Q and two short scalars; the circuit checks
    a relation instead of computing [s]P. P-256 has no efficient
    endomorphism, so the 4-dimensional variant used on secp256k1 does not
    apply; the 2-dimensional one never needed the curve's structure.

    The technique follows the public description of rot256's (Mathias
    Hall-Andersen) submission to the zk.golf secp256k1 scalar multiplication
    challenge, reduced to two dimensions. No code was copied.

        (1)  u == s*v                (mod n)    -- the relation
        (2)  [u]P - [v]Q == O                   -- loop + terminal assertion
        (3)  |u|, |v| < 2^128                   -- Num2Bits(128)
        (4)  v != 0

    Soundness. Let t be such that Q = [t]P; it exists because Q is checked on
    the curve and the group is cyclic of prime order n. From (2),
    u == t*v (mod n); with (1), (t - s)*v == 0 (mod n). By (3) and (4),
    0 < |v| < 2^128 < n, so v != 0 (mod n), and n prime gives t == s.

    Scalars are four 64-bit limbs; points are eight 32-bit limbs per
    coordinate.

    The hint (u, v) is an input of this template, not of the circuit: whoever
    instantiates it computes the hint at witness generation time.

    Not handled: P at infinity, s = 0.
*/

include "./p256.circom";
include "./fake_glv2_straus.circom";
include "../../circomlib/circuits/comparators.circom";

template FakeGLV2ScalarMulVerify() {
    signal input scalar[4];   // s, in 64-bit limbs
    signal input P[2][8];     // the base, on the curve
    signal input Q[2][8];     // the claimed result, supplied by the prover

    // The hint: magnitudes (each < 2^128, one signal each) and signs.
    // Order: 0 = u, 1 = v.
    signal input mag[2];
    signal input sgn[2];

    var ordN[100] = get_p256_order(64, 4);
    var prime[100] = get_p256_prime(32, 8);

    signal ordSig[4];
    signal primeSig[8];
    for (var j = 0; j < 4; j++) { ordSig[j] <== ordN[j]; }
    for (var j = 0; j < 8; j++) { primeSig[j] <== prime[j]; }

    // ---------- 1. the hint: bits, range, canonical signs ----------
    component n2b[2];
    component isz[2];
    for (var i = 0; i < 2; i++) {
        sgn[i] * (sgn[i] - 1) === 0;

        // Checks mag[i] < 2^128 and yields the bits the loop consumes.
        n2b[i] = Num2Bits(128);
        n2b[i].in <== mag[i];

        // The sign of zero is pinned: n - 0 == n would leave [0, n).
        isz[i] = IsZero();
        isz[i].in <== mag[i];
        sgn[i] * isz[i].out === 0;
    }

    // (4) v != 0 -- without it the relation says nothing about Q.
    isz[1].out === 0;

    // ---------- 2. signed residues, in [0, n) ----------
    // mag < 2^128 is exactly two 64-bit limbs, read off its bits.
    signal magLimb[2][4];
    for (var i = 0; i < 2; i++) {
        var lo = 0;
        var hi = 0;
        for (var t = 0; t < 64; t++) {
            lo += n2b[i].out[t] * (1 << t);
            hi += n2b[i].out[64 + t] * (1 << t);
        }
        magLimb[i][0] <== lo;
        magLimb[i][1] <== hi;
        magLimb[i][2] <== 0;
        magLimb[i][3] <== 0;
    }

    component negm[2];
    signal r[2][4];
    for (var i = 0; i < 2; i++) {
        negm[i] = BigSub(64, 4);      // n - mag, no underflow: mag < 2^128 < n
        for (var j = 0; j < 4; j++) {
            negm[i].a[j] <== ordSig[j];
            negm[i].b[j] <== magLimb[i][j];
        }
        for (var j = 0; j < 4; j++) {
            r[i][j] <== magLimb[i][j] + sgn[i] * (negm[i].out[j] - magLimb[i][j]);
        }
    }

    // ---------- 3. s < n ----------
    component sLtN = BigLessThan(64, 4);
    for (var j = 0; j < 4; j++) {
        sLtN.a[j] <== scalar[j];
        sLtN.b[j] <== ordSig[j];
    }
    sLtN.out === 1;

    // ---------- 4. (1) u == s*v (mod n) ----------
    // Both sides are canonical residues, so equal limbs mean equal values.
    component sv = BigMultModP(64, 4);
    for (var j = 0; j < 4; j++) {
        sv.a[j] <== scalar[j];
        sv.b[j] <== r[1][j];
        sv.p[j] <== ordSig[j];
    }
    for (var j = 0; j < 4; j++) {
        sv.out[j] === r[0][j];
    }

    // ---------- 5. Q is on the curve ----------
    component qOn = P256PointOnCurve();
    for (var j = 0; j < 8; j++) {
        qOn.x[j] <== Q[0][j];
        qOn.y[j] <== Q[1][j];
    }

    // ---------- 6. the two bases, sign folded into the point ----------
    //   [u]P - [v]Q == O  as  [|u|](+-P) + [|v|](-+Q) == O
    component negPy = BigSub(32, 8);
    component negQy = BigSub(32, 8);
    for (var j = 0; j < 8; j++) {
        negPy.a[j] <== primeSig[j];
        negPy.b[j] <== P[1][j];
        negQy.a[j] <== primeSig[j];
        negQy.b[j] <== Q[1][j];
    }

    signal A[2][2][8];
    for (var j = 0; j < 8; j++) {
        A[0][0][j] <== P[0][j];
        A[1][0][j] <== Q[0][j];
        A[0][1][j] <== P[1][j] + sgn[0] * (negPy.out[j] - P[1][j]);
        A[1][1][j] <== negQy.out[j] + sgn[1] * (Q[1][j] - negQy.out[j]);
    }

    // ---------- 7. (2) the loop + the terminal assertion ----------
    component loop = FakeGLV2StrausLoop(128);
    for (var i = 0; i < 2; i++) {
        for (var b = 0; b < 128; b++) {
            loop.bits[i][b] <== n2b[i].out[b];
        }
        for (var c = 0; c < 2; c++) {
            for (var j = 0; j < 8; j++) {
                loop.A[i][c][j] <== A[i][c][j];
            }
        }
    }
}
