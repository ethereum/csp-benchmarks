pragma circom 2.2.0;

include "comb.circom";
include "fake_glv.circom";

// Verifies a private ECDSA signature for a public 256-bit prehash and public
// key. Scalars and coordinates are little-endian arrays of 32 constrained bytes.
template KbEcdsaVerify(p256) {
    var p[22] = ecdsa_prime(p256);
    var n[22] = ecdsa_order(p256);
    var g[2][22] = ecdsa_generator(p256);
    signal input msghash[32];
    signal input pubkey[2][32];
    signal input r[32];
    signal input s[32];
    signal input result[2][22];
    signal input mag[4][11];
    signal input sgn[4];

    component digestLimbs = KbPackBytes();
    component rLimbs = KbPackBytes();
    component sLimbs = KbPackBytes();
    component keyLimbs[2];
    for (var c = 0; c < 2; c++) keyLimbs[c] = KbPackBytes();
    for (var i = 0; i < 32; i++) {
        digestLimbs.in[i] <== msghash[i];
        rLimbs.in[i] <== r[i];
        sLimbs.in[i] <== s[i];
        for (var c = 0; c < 2; c++) keyLimbs[c].in[i] <== pubkey[c][i];
    }

    component rCanonical = KbCanonical(n);
    component sCanonical = KbCanonical(n);
    component digestBytes[22];
    component keyCanonical[2];
    component rZero = BigIsEqual(22);
    component sZero = BigIsEqual(22);
    for (var c = 0; c < 2; c++) keyCanonical[c] = KbCanonical(p);
    for (var i = 0; i < 22; i++) {
        rCanonical.in[i] <== rLimbs.out[i]; sCanonical.in[i] <== sLimbs.out[i];
        rZero.in[0][i] <== rLimbs.out[i]; rZero.in[1][i] <== 0;
        sZero.in[0][i] <== sLimbs.out[i]; sZero.in[1][i] <== 0;
        digestBytes[i] = Num2Bits(12);
        digestBytes[i].in <== digestLimbs.out[i];
        for (var c = 0; c < 2; c++) keyCanonical[c].in[i] <== keyLimbs[c].out[i];
    }
    rZero.out === 0;
    sZero.out === 0;
    component onCurve = KbPointOnCurve(p256);
    for (var c = 0; c < 2; c++) {
        for (var i = 0; i < 22; i++) onCurve.in[c][i] <== keyLimbs[c].out[i];
    }

    component inverseS = BigModInv(12, 22);
    for (var i = 0; i < 22; i++) {
        inverseS.in[i] <== sLimbs.out[i]; inverseS.p[i] <== n[i];
    }
    component inverseCanonical = KbCanonical(n);
    component u1 = KbMul(n);
    component u2 = KbMul(n);
    for (var i = 0; i < 22; i++) {
        inverseCanonical.in[i] <== inverseS.out[i];
        u1.a[i] <== digestLimbs.out[i]; u1.b[i] <== inverseS.out[i];
        u2.a[i] <== rLimbs.out[i]; u2.b[i] <== inverseS.out[i];
    }
    // R is a private witness. Its finite canonical coordinates, curve
    // equation, x-coordinate reduction, and the group relation constrain it.
    component resultCanonical[2];
    component resultOnCurve = KbPointOnCurve(p256);
    for (var c = 0; c < 2; c++) {
        resultCanonical[c] = KbCanonical(p);
        for (var i = 0; i < 22; i++) {
            resultCanonical[c].in[i] <== result[c][i];
            resultOnCurve.in[c][i] <== result[c][i];
        }
    }
    component rx = BigMod(12, 22);
    for (var i = 0; i < 44; i++) {
        if (i < 22) rx.a[i] <== result[0][i];
        else rx.a[i] <== 0;
    }
    for (var i = 0; i < 22; i++) rx.b[i] <== n[i];
    for (var i = 0; i < 22; i++) rx.mod[i] === rLimbs.out[i];

    component fixed = KbCombFixedBase(p256);
    for (var i = 0; i < 22; i++) fixed.k[i] <== u1.out[i];
    component negateFixedY = KbSub(p);
    for (var i = 0; i < 22; i++) {
        negateFixedY.a[i] <== 0;
        negateFixedY.b[i] <== fixed.out[1][i];
    }
    // S = R - [u1]G. Complete subtraction includes u1=0 and R=-[u1]G.
    // Since u2 != 0 and the public key is finite, S must also be finite.
    component subtraction = KbPointAdd(p256);
    subtraction.aInf <== 0;
    subtraction.bInf <== fixed.outInf;
    for (var i = 0; i < 22; i++) {
        subtraction.a[0][i] <== result[0][i];
        subtraction.a[1][i] <== result[1][i];
        subtraction.b[0][i] <== fixed.out[0][i];
        subtraction.b[1][i] <== negateFixedY.out[i];
    }
    subtraction.outInf === 0;
    component variable = KbFakeGlvVerify(p256);
    for (var i = 0; i < 22; i++) {
        variable.scalar[i] <== u2.out[i];
        for (var c = 0; c < 2; c++) {
            variable.P[c][i] <== keyLimbs[c].out[i];
            variable.Q[c][i] <== subtraction.out[c][i];
        }
    }
    for (var d = 0; d < 4; d++) {
        variable.sgn[d] <== sgn[d];
        for (var i = 0; i < 11; i++) variable.mag[d][i] <== mag[d][i];
    }
}
