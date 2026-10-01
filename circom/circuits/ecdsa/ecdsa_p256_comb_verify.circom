/*
    ECDSA verification on secp256r1 (P-256).

    R == [u1]G + [u2]Q is rearranged as [u2]Q == R - [u1]G: the right-hand side
    is computed with a fixed-base comb, the left-hand side is verified with
    2-dimensional fake-GLV. One variable-base multiplication instead of two.

    R is witnessed and constrained on-curve. Its x coordinate is reduced modulo
    the group order and compared with public r. The sign of y is pinned by the
    verification equation, since -R would require R of order 2.

    The public key is validated and r, s must lie in [1, n-1]. The circuit
    accepts both representatives of s. There is no `result` output; an invalid
    signature fails witness generation.

    Public inputs and scalars are four 64-bit limbs; points are eight 32-bit
    limbs per coordinate, converted at the boundary.

    The fake-GLV table and accumulator use complete group operations and
    an explicit infinity flag. Equality selectors consume canonical coordinates.
*/
pragma circom 2.0.2;

include "./comb_fixed_p256.circom";
include "./fake_glv2_scalarmul.circom";
include "./lattice2_func.circom";
include "./p256_scalarmul_func.circom";
include "../../circomlib/circuits/comparators.circom";

template ECDSAP256CombVerify() {
    signal input r[4];
    signal input s[4];
    signal input msghash[4];
    signal input pubkey[2][4];

    // Witness-only values: the inverse of s, the coordinates of R, and the
    // decomposition of u2. Each is constrained before it is consumed.
    signal sinv[4];
    signal Rx[8];
    signal Ry[8];
    signal mag[2];
    signal sgn[2];

    var ordN[100] = get_p256_order(64, 4);
    var prime[100] = get_p256_prime(32, 8);

    signal ordSig[4];
    signal primeSig[8];
    for (var j = 0; j < 4; j++) { ordSig[j] <== ordN[j]; }
    for (var j = 0; j < 8; j++) { primeSig[j] <== prime[j]; }

    // ---------- 1. canonical public inputs; r, s in [1, n-1] ----------
    component rRange[4];
    component sRange[4];
    component hashRange[4];
    for (var j = 0; j < 4; j++) {
        rRange[j] = Num2Bits(64);
        rRange[j].in <== r[j];
        sRange[j] = Num2Bits(64);
        sRange[j].in <== s[j];
        hashRange[j] = Num2Bits(64);
        hashRange[j].in <== msghash[j];
    }

    component rLtN = BigLessThan(64, 4);
    component sLtN = BigLessThan(64, 4);
    for (var j = 0; j < 4; j++) {
        rLtN.a[j] <== r[j];
        rLtN.b[j] <== ordSig[j];
        sLtN.a[j] <== s[j];
        sLtN.b[j] <== ordSig[j];
    }
    rLtN.out === 1;
    sLtN.out === 1;

    // Four limbs below 2^64 sum to less than 2^66, so the sum fits in the
    // BN254 field and is zero exactly when every limb is zero.
    component rZero = IsZero();
    component sZero = IsZero();
    rZero.in <== r[0] + r[1] + r[2] + r[3];
    sZero.in <== s[0] + s[1] + s[2] + s[3];
    rZero.out === 0;
    sZero.out === 0;

    // ---------- 2. the public key is canonical and on the curve ----------
    // Each 64-bit limb is split into two 32-bit limbs; the range check below
    // bounds both halves, which makes the split unique and bounds the
    // 64-bit limb as well.
    component qConv[2];
    component qRange[2];
    signal q32[2][8];
    for (var c = 0; c < 2; c++) {
        qConv[c] = P256Limbs64To32();
        for (var j = 0; j < 4; j++) { qConv[c].in[j] <== pubkey[c][j]; }
        qRange[c] = CheckInRangeP256();
        for (var j = 0; j < 8; j++) {
            q32[c][j] <== qConv[c].out[j];
            qRange[c].in[j] <== q32[c][j];
        }
    }

    component qOn = P256PointOnCurve();
    for (var j = 0; j < 8; j++) {
        qOn.x[j] <== q32[0][j];
        qOn.y[j] <== q32[1][j];
    }

    // ---------- 3. sinv computed, checked with one multiplication ----------
    var sv[100];
    var ov[100];
    for (var j = 0; j < 100; j++) {
        sv[j] = 0;
        ov[j] = 0;
    }
    for (var j = 0; j < 4; j++) {
        sv[j] = s[j];
        ov[j] = ordN[j];
    }
    var sinvVal[100] = mod_inv(64, 4, sv, ov);
    for (var j = 0; j < 4; j++) {
        sinv[j] <-- sinvVal[j];
    }

    component sinvRange[4];
    for (var j = 0; j < 4; j++) {
        sinvRange[j] = Num2Bits(64);
        sinvRange[j].in <== sinv[j];
    }
    component sinvCheck = BigMultModP(64, 4);
    for (var j = 0; j < 4; j++) {
        sinvCheck.a[j] <== sinv[j];
        sinvCheck.b[j] <== s[j];
        sinvCheck.p[j] <== ordSig[j];
    }
    sinvCheck.out[0] === 1;
    for (var j = 1; j < 4; j++) {
        sinvCheck.out[j] === 0;
    }

    // ---------- 4. u1 = h*sinv, u2 = r*sinv (mod n) ----------
    component u1c = BigMultModP(64, 4);
    component u2c = BigMultModP(64, 4);
    for (var j = 0; j < 4; j++) {
        u1c.a[j] <== msghash[j];
        u1c.b[j] <== sinv[j];
        u1c.p[j] <== ordSig[j];
        u2c.a[j] <== r[j];
        u2c.b[j] <== sinv[j];
        u2c.p[j] <== ordSig[j];
    }

    // R = [u1]G + [u2]Q, computed off-constraint and constrained below by the
    // curve equation, R.x mod n == r, and the verification equation. The
    // witness-time arithmetic runs in 64-bit limbs; R is split for the circuit.
    var u1v[100];
    var u2v[100];
    var qxv[100];
    var qyv[100];
    for (var j = 0; j < 100; j++) {
        u1v[j] = 0;
        u2v[j] = 0;
        qxv[j] = 0;
        qyv[j] = 0;
    }
    for (var j = 0; j < 4; j++) {
        u1v[j] = u1c.out[j];
        u2v[j] = u2c.out[j];
        qxv[j] = pubkey[0][j];
        qyv[j] = pubkey[1][j];
    }
    var Rval[2][100] = p256_ecdsa_R_func(64, 4, u1v, u2v, qxv, qyv);
    var Rx32[100] = p256_split64to32(Rval[0]);
    var Ry32[100] = p256_split64to32(Rval[1]);
    for (var j = 0; j < 8; j++) {
        Rx[j] <-- Rx32[j];
        Ry[j] <-- Ry32[j];
    }

    // ---------- 5. R is canonical, on-curve, and R.x mod n == r ----------
    component rCoordRange[2];
    for (var c = 0; c < 2; c++) {
        rCoordRange[c] = CheckInRangeP256();
        for (var j = 0; j < 8; j++) {
            if (c == 0) {
                rCoordRange[c].in[j] <== Rx[j];
            } else {
                rCoordRange[c].in[j] <== Ry[j];
            }
        }
    }

    component rOn = P256PointOnCurve();
    for (var j = 0; j < 8; j++) {
        rOn.x[j] <== Rx[j];
        rOn.y[j] <== Ry[j];
    }

    component rx64 = P256Limbs32To64();
    for (var j = 0; j < 8; j++) { rx64.in[j] <== Rx[j]; }

    component rxModN = BigMod(64, 4);
    for (var j = 0; j < 8; j++) {
        if (j < 4) {
            rxModN.a[j] <== rx64.out[j];
        } else {
            rxModN.a[j] <== 0;
        }
    }
    for (var j = 0; j < 4; j++) {
        rxModN.b[j] <== ordSig[j];
    }
    for (var j = 0; j < 4; j++) {
        rxModN.mod[j] === r[j];
    }

    // ---------- 6. [u1]G, fixed base, via the width-12 comb ----------
    // The comb has only finite affine outputs and cannot represent [0]G. Zero
    // is mapped to one for this call and the zero result is selected at step 7.
    component u1Zero = IsZero();
    u1Zero.in <== u1c.out[0] + u1c.out[1] + u1c.out[2] + u1c.out[3];

    component u1G = CombFixedBaseP256();
    u1G.k[0] <== u1c.out[0] + u1Zero.out;
    for (var j = 1; j < 4; j++) { u1G.k[j] <== u1c.out[j]; }

    // ---------- 7a. classify the equal-x subtraction case ----------
    // Load-bearing: P256AddUnequal leaves its output unconstrained when the
    // operands coincide. A prover who supplies R.x = ([u1]G).x and
    // R.y = p - ([u1]G).y gets a free S, sets it equal to [u2]Q for an
    // arbitrary Q, and verifies without the private key.
    //
    // Equal limbs mean equal values only for canonical representations:
    // [u1]G leaves the table through a one-hot selector and the range-checked
    // additions, and Rx is range checked above.
    component xSame[8];
    signal xSameAcc[8];
    for (var j = 0; j < 8; j++) {
        xSame[j] = IsZero();
        xSame[j].in <== Rx[j] - u1G.out[0][j];
    }
    xSameAcc[0] <== xSame[0].out;
    for (var j = 1; j < 8; j++) { xSameAcc[j] <== xSameAcc[j - 1] * xSame[j].out; }

    component ySame[8];
    signal ySameAcc[8];
    for (var j = 0; j < 8; j++) {
        ySame[j] = IsZero();
        ySame[j].in <== Ry[j] - u1G.out[1][j];
    }
    ySameAcc[0] <== ySame[0].out;
    for (var j = 1; j < 8; j++) { ySameAcc[j] <== ySameAcc[j - 1] * ySame[j].out; }

    // For nonzero u1 and equal x, R = [u1]G would make R - [u1]G the point at
    // infinity, which cannot equal [u2]Q since u2 and Q are nonzero in the
    // prime-order group. The other equal-x case is R = -[u1]G, for which the
    // subtraction is the valid doubling 2R.
    signal nonzeroU1SameX;
    nonzeroU1SameX <== (1 - u1Zero.out) * xSameAcc[7];
    nonzeroU1SameX * ySameAcc[7] === 0;

    signal skipSub;
    skipSub <== u1Zero.out + xSameAcc[7] - u1Zero.out * xSameAcc[7];

    // ---------- 7. S = R - [u1]G ----------
    component negU1Gy = BigSub(32, 8);
    for (var j = 0; j < 8; j++) {
        negU1Gy.a[j] <== primeSig[j];
        negU1Gy.b[j] <== u1G.out[1][j];
    }

    // The subtraction needs sound distinct-x inputs even when its output is
    // ignored, so both operands are replaced by fixed curve points in the zero
    // and equal-x branches.
    var dummy[2][100] = get_p256_dummy_point(32, 8);
    var gx[100] = get_p256_gx(32, 8);
    var gy[100] = get_p256_gy(32, 8);
    var negGy[100] = long_sub(32, 8, prime, gy);
    component Ssub = P256AddUnequal();
    for (var j = 0; j < 8; j++) {
        Ssub.a[0][j] <== Rx[j] + skipSub * (dummy[0][j] - Rx[j]);
        Ssub.a[1][j] <== Ry[j] + skipSub * (dummy[1][j] - Ry[j]);
        Ssub.b[0][j] <== u1G.out[0][j] + skipSub * (gx[j] - u1G.out[0][j]);
        Ssub.b[1][j] <== negU1Gy.out[j] + skipSub * (negGy[j] - negU1Gy.out[j]);
    }

    component Sdouble = P256Double();
    for (var j = 0; j < 8; j++) {
        Sdouble.in[0][j] <== Rx[j];
        Sdouble.in[1][j] <== Ry[j];
    }

    // S = R for u1 = 0, S = 2R for the valid nonzero equal-x case, and the
    // ordinary affine subtraction otherwise.
    signal Snonzero[2][8];
    signal S[2][8];
    for (var j = 0; j < 8; j++) {
        Snonzero[0][j] <== Ssub.out[0][j]
            + nonzeroU1SameX * (Sdouble.out[0][j] - Ssub.out[0][j]);
        Snonzero[1][j] <== Ssub.out[1][j]
            + nonzeroU1SameX * (Sdouble.out[1][j] - Ssub.out[1][j]);
        S[0][j] <== Snonzero[0][j] + u1Zero.out * (Rx[j] - Snonzero[0][j]);
        S[1][j] <== Snonzero[1][j] + u1Zero.out * (Ry[j] - Snonzero[1][j]);
    }

    // The decomposition of u2. FakeGLV2ScalarMulVerify constrains it fully, so
    // a wrong one cannot pass; computing it here only spares the caller the
    // reduction.
    var hint[2][2] = p256_fake_glv2_decompose(u2v);
    for (var i = 0; i < 2; i++) {
        mag[i] <-- hint[0][i];
        sgn[i] <-- hint[1][i];
    }

    // ---------- 8. [u2]Q == S, via 2-dimensional fake-GLV ----------
    component glv = FakeGLV2ScalarMulVerify();
    for (var j = 0; j < 4; j++) {
        glv.scalar[j] <== u2c.out[j];
    }
    for (var j = 0; j < 8; j++) {
        glv.P[0][j] <== q32[0][j];
        glv.P[1][j] <== q32[1][j];
        glv.Q[0][j] <== S[0][j];
        glv.Q[1][j] <== S[1][j];
    }
    for (var i = 0; i < 2; i++) {
        glv.mag[i] <== mag[i];
        glv.sgn[i] <== sgn[i];
    }
}
