pragma circom 2.0.2;

include "./secp256k1_32.circom";
include "./scalarmul_func.circom";

// Flagged points use canonical affine coordinates in eight 32-bit limbs when
// finite and (0,0) when isInf = 1. Arithmetic templates assume valid input
// points. Their outputs preserve this invariant by the group formulas and
// muxes.
//
// secp256k1 has prime order, so no finite point has y = 0: the tangent
// denominator 2*y is never zero and the double of a finite point is finite.

// Returns [slope, x, y] of a+b, for distinct x (tangent = 0) or a = b
// (tangent = 1). Witness generation only.
function secp256k1_slope_add_func(n, k, x1, y1, x2, y2, tangent) {
    var p[100] = get_secp256k1_prime(n, k);
    var a[2][100];
    var b[2][100];
    for (var i = 0; i < 100; i++) {
        a[0][i] = 0; a[1][i] = 0; b[0][i] = 0; b[1][i] = 0;
    }
    for (var i = 0; i < k; i++) {
        a[0][i] = x1[i]; a[1][i] = y1[i]; b[0][i] = x2[i]; b[1][i] = y2[i];
    }
    var num[100];
    var den[100];
    if (tangent == 1) {
        var three[100];
        var two[100];
        for (var i = 0; i < 100; i++) {
            three[i] = i == 0 ? 3 : 0;
            two[i] = i == 0 ? 2 : 0;
        }
        var xsq[100] = prod_mod_p(n, k, a[0], a[0], p);
        num = prod_mod_p(n, k, xsq, three, p);
        den = prod_mod_p(n, k, a[1], two, p);
    } else {
        num = long_sub_mod_p(n, k, b[1], a[1], p);
        den = long_sub_mod_p(n, k, b[0], a[0], p);
    }
    var denInv[100] = mod_inv(n, k, den, p);
    var lambda[100] = prod_mod_p(n, k, num, denInv, p);
    var lsq[100] = prod_mod_p(n, k, lambda, lambda, p);
    var xPre[100] = long_sub_mod_p(n, k, lsq, a[0], p);
    var x3[100] = long_sub_mod_p(n, k, xPre, b[0], p);
    var dx[100] = long_sub_mod_p(n, k, a[0], x3, p);
    var ldx[100] = prod_mod_p(n, k, lambda, dx, p);
    var y3[100] = long_sub_mod_p(n, k, ldx, a[1], p);
    var out[3][100];
    for (var i = 0; i < 100; i++) {
        out[0][i] = lambda[i]; out[1][i] = x3[i]; out[2][i] = y3[i];
    }
    return out;
}

/*
    Complete a+b with a shared witnessed slope. The disjoint tangent
    (2*l*y = 3*x^2) and chord residuals share one modular certificate. The
    inverse branch pins slope and candidate coordinates to zero; input
    infinity uses safe finite operands internally and selects the other input
    in the output muxes.

    Equality selectors compare limbs, so finite inputs must be canonical.
    Products of 32-bit limbs have registers below 8*2^64 = 2^67. In absolute
    value the slope residual is below 3*2^67 < 2^69 (2*l*y below 2^68, 3*x^2
    below 3*2^67), the x and y residuals below 2^69.
*/
template Secp256k1AddComplete() {
    signal input a[2][8];
    signal input b[2][8];
    signal input aInf;
    signal input bInf;
    signal output out[2][8];
    signal output outInf;
    aInf * (aInf - 1) === 0;
    bInf * (bInf - 1) === 0;
    var gx[100] = p256_split64to32(get_gx64());
    var gy[100] = p256_split64to32(get_gy64());
    signal ax[8]; signal ay[8]; signal bx[8]; signal by[8];
    for (var j = 0; j < 8; j++) {
        ax[j] <== a[0][j] + aInf * (gx[j] - a[0][j]);
        ay[j] <== a[1][j] + aInf * (gy[j] - a[1][j]);
        bx[j] <== b[0][j] + bInf * (ax[j] - b[0][j]);
        by[j] <== b[1][j] + bInf * (ay[j] - b[1][j]);
    }
    component sameX = BigIsEqual(8);
    component sameY = BigIsEqual(8);
    for (var j = 0; j < 8; j++) {
        sameX.in[0][j] <== ax[j]; sameX.in[1][j] <== bx[j];
        sameY.in[0][j] <== ay[j]; sameY.in[1][j] <== by[j];
    }
    signal tangent;
    signal cancel;
    signal active;
    signal finiteCancel;
    tangent <== sameX.out * sameY.out;
    cancel <== sameX.out - tangent;
    active <== 1 - cancel;
    // bInf makes b equal to the safe a operand, hence cancel = 0.
    finiteCancel <== (1 - aInf) * cancel;
    outInf <== aInf * bInf + finiteCancel;

    // Witness generation branches only choose values; the selectors and
    // modular equations below independently establish the group relation.
    var xAv[8]; var yAv[8]; var xBv[8]; var yBv[8];
    for (var j = 0; j < 8; j++) {
        xAv[j] = ax[j]; yAv[j] = ay[j]; xBv[j] = bx[j]; yBv[j] = by[j];
    }
    var result[3][100];
    for (var c = 0; c < 3; c++) {
        for (var j = 0; j < 100; j++) { result[c][j] = 0; }
    }
    if (tangent == 1) {
        result = secp256k1_slope_add_func(64, 4, secp256k1_join32(xAv), secp256k1_join32(yAv),
            secp256k1_join32(xAv), secp256k1_join32(yAv), 1);
    } else if (cancel == 0) {
        result = secp256k1_slope_add_func(64, 4, secp256k1_join32(xAv), secp256k1_join32(yAv),
            secp256k1_join32(xBv), secp256k1_join32(yBv), 0);
    }
    var lambdav[100] = p256_split64to32(result[0]);
    var candxv[100] = p256_split64to32(result[1]);
    var candyv[100] = p256_split64to32(result[2]);
    signal lambda[8];
    signal candidate[2][8];
    component lambdaRange[8];
    component candidateRange[2];
    for (var c = 0; c < 2; c++) { candidateRange[c] = CheckInRangeSecp256k1Limbs32(); }
    for (var j = 0; j < 8; j++) {
        lambda[j] <-- lambdav[j];
        candidate[0][j] <-- candxv[j]; candidate[1][j] <-- candyv[j];
        lambdaRange[j] = Num2Bits(32); lambdaRange[j].in <== lambda[j];
        cancel * lambda[j] === 0;
        for (var c = 0; c < 2; c++) {
            candidateRange[c].in[j] <== candidate[c][j];
            cancel * candidate[c][j] === 0;
        }
    }
    component xasq = P256Mul();
    component lay = P256Mul(); component lax = P256Mul(); component lbx = P256Mul();
    component lsq = P256Mul(); component loutx = P256Mul();
    for (var j = 0; j < 8; j++) {
        xasq.a[j] <== ax[j]; xasq.b[j] <== ax[j];
        lay.a[j] <== lambda[j]; lay.b[j] <== ay[j];
        lax.a[j] <== lambda[j]; lax.b[j] <== ax[j];
        lbx.a[j] <== lambda[j]; lbx.b[j] <== bx[j];
        lsq.a[j] <== lambda[j]; lsq.b[j] <== lambda[j];
        loutx.a[j] <== lambda[j]; loutx.b[j] <== candidate[0][j];
    }
    signal tangentResidual[15];
    signal chordResidual[15];
    component slopeCheck = Secp256k1CheckQuadraticModPIsZero69();
    component xCheck = Secp256k1CheckQuadraticModPIsZero69();
    component yCheck = Secp256k1CheckQuadraticModPIsZero69();
    for (var i = 0; i < 15; i++) {
        tangentResidual[i] <== tangent * (2 * lay.out[i] - 3 * xasq.out[i]);
        if (i < 8) {
            chordResidual[i] <== (1 - sameX.out) * (lbx.out[i] - lax.out[i] - by[i] + ay[i]);
            xCheck.in[i] <== active * (lsq.out[i] - ax[i] - bx[i] - candidate[0][i]);
            yCheck.in[i] <== active * (loutx.out[i] - lax.out[i] + candidate[1][i] + ay[i]);
        } else {
            chordResidual[i] <== (1 - sameX.out) * (lbx.out[i] - lax.out[i]);
            xCheck.in[i] <== active * lsq.out[i];
            yCheck.in[i] <== active * (loutx.out[i] - lax.out[i]);
        }
        slopeCheck.in[i] <== tangentResidual[i] + chordResidual[i];
    }
    signal withBInf[2][8];
    for (var c = 0; c < 2; c++) {
        for (var j = 0; j < 8; j++) {
            withBInf[c][j] <== candidate[c][j] + bInf * (a[c][j] - candidate[c][j]);
            out[c][j] <== withBInf[c][j] + aInf * (b[c][j] - withBInf[c][j]);
        }
    }
}

// Complete 2*a. Infinity doubles to infinity through the safe operand G;
// a finite input has a finite double.
template Secp256k1DoubleComplete() {
    signal input in[2][8];
    signal input inInf;
    signal output out[2][8];
    signal output outInf;
    inInf * (inInf - 1) === 0;
    var gx[100] = p256_split64to32(get_gx64());
    var gy[100] = p256_split64to32(get_gy64());
    component dbl = Secp256k1Double32();
    for (var j = 0; j < 8; j++) {
        dbl.in[0][j] <== in[0][j] + inInf * (gx[j] - in[0][j]);
        dbl.in[1][j] <== in[1][j] + inInf * (gy[j] - in[1][j]);
    }
    for (var c = 0; c < 2; c++) {
        for (var j = 0; j < 8; j++) {
            out[c][j] <== dbl.out[c][j] - inInf * dbl.out[c][j];
        }
    }
    outInf <== inInf;
}
