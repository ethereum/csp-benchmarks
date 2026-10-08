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

/*
    Complete 2*a+b, one Straus step, computed as a + (a + b) without the y
    of S = a + b (Eisentraeger-Lauter-Montgomery):

        S = a + b      l1 and xS witnessed, yS = l1*(xa - xS) - ya implicit
        out = a + S    l2 = -l1 - 2*ya/(xS - xa), checked as
                       (l1 + l2)*(xS - xa) + 2*ya == 0

    This is the second half of P256QuadAddComplete, applied to the
    accumulator itself rather than to its double.

    The input a has a canonical x and a y in 32-bit limbs, a point modulo p;
    the output has the same form, and b is a canonical table entry. Infinity
    is (0,0) with flag 1; a = O runs on the safe operand G and selects b.

    Exceptional cases, with a and b finite unless stated:
      b = O          S = 2a by the tangent, out = S, l2 = l1
      a = b          S = 2a by the tangent, out = a + S
      a = -b         S = O, out = a with y = -yb modulo p
      a + b = -a     xS = xa, out = O
    On equal x, equalY is a witnessed Boolean pinned by ya == (2*equalY-1)*yb
    modulo p, since ya is not canonical; yb != 0 fixes exactly one sign.
    xS == xa means S = -a: S = a would need b = O, handled above.

    Every residual is quadratic with registers below 2^69 in absolute value.
*/
template Secp256k1DoubleAddComplete() {
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
    signal ax[8]; signal ay[8]; signal bx[8];
    for (var j = 0; j < 8; j++) {
        ax[j] <== a[0][j] + aInf * (gx[j] - a[0][j]);
        ay[j] <== a[1][j] + aInf * (gy[j] - a[1][j]);
        bx[j] <== b[0][j] + bInf * (ax[j] - b[0][j]);
    }
    component sameX = BigIsEqual(8);
    for (var j = 0; j < 8; j++) {
        sameX.in[0][j] <== ax[j]; sameX.in[1][j] <== bx[j];
    }

    // Witness values: ya reduced modulo p, b as given.
    var prime[100] = get_secp256k1_prime32();
    var xAv[8]; var yAraw[8]; var xBv[8]; var yBv[8];
    for (var j = 0; j < 8; j++) {
        xAv[j] = ax[j]; yAraw[j] = ay[j]; xBv[j] = bx[j]; yBv[j] = b[1][j];
    }
    var yAv[100] = p256_load(32, 8, yAraw, prime);

    signal sameFiniteX;
    signal equalY;
    signal tangent1;
    signal cancel;
    signal active1;
    sameFiniteX <== (1 - bInf) * sameX.out;
    var yEqual = 1;
    for (var j = 0; j < 8; j++) { if (yAv[j] != yBv[j]) { yEqual = 0; } }
    equalY <-- sameFiniteX * yEqual;
    equalY * (equalY - 1) === 0;
    (1 - sameFiniteX) * equalY === 0;
    tangent1 <== bInf + equalY;
    cancel <== sameFiniteX - equalY;
    active1 <== 1 - cancel;
    signal signedBY[8];
    for (var j = 0; j < 8; j++) { signedBY[j] <== b[1][j] - 2 * equalY * b[1][j]; }
    component signCheck = Secp256k1CheckQuadraticModPIsZero69();
    for (var i = 0; i < 15; i++) {
        if (i < 8) { signCheck.in[i] <== sameFiniteX * (ay[i] + signedBY[i]); }
        else { signCheck.in[i] <== 0; }
    }

    // Witness generation branches only choose values; the selectors and
    // modular equations below independently establish the group relation.
    var first[3][100];
    for (var c = 0; c < 3; c++) {
        for (var j = 0; j < 100; j++) { first[c][j] = 0; }
    }
    if (tangent1 == 1) {
        first = secp256k1_slope_add_func(64, 4, secp256k1_join32(xAv), secp256k1_join32(yAv),
            secp256k1_join32(xAv), secp256k1_join32(yAv), 1);
    } else if (cancel == 0) {
        first = secp256k1_slope_add_func(64, 4, secp256k1_join32(xAv), secp256k1_join32(yAv),
            secp256k1_join32(xBv), secp256k1_join32(yBv), 0);
    }
    var l1v[100] = p256_split64to32(first[0]);
    var xSv[100] = p256_split64to32(first[1]);
    var ySv[100] = p256_split64to32(first[2]);
    signal l1[8]; signal xS[8];
    for (var j = 0; j < 8; j++) {
        l1[j] <-- l1v[j]; xS[j] <-- xSv[j];
        cancel * l1[j] === 0;
        cancel * xS[j] === 0;
    }
    component secondSameX = BigIsEqual(8);
    for (var j = 0; j < 8; j++) {
        secondSameX.in[0][j] <== ax[j]; secondSameX.in[1][j] <== xS[j];
    }
    signal noBInf;
    signal ordinary2;
    signal zeroOut;
    signal finite2;
    noBInf <== (1 - bInf) * active1;
    ordinary2 <== noBInf * (1 - secondSameX.out);
    zeroOut <== noBInf * secondSameX.out;
    finite2 <== ordinary2 + bInf;
    // bInf forces equalY = 0 and cancel = 0. The two terms are disjoint.
    var last[3][100];
    for (var c = 0; c < 3; c++) {
        for (var j = 0; j < 100; j++) { last[c][j] = 0; }
    }
    if (bInf == 1) {
        last = first;
    } else if (cancel == 1) {
        var axJoined[100] = secp256k1_join32(xAv);
        var ayJoined[100] = secp256k1_join32(yAv);
        for (var j = 0; j < 100; j++) { last[1][j] = axJoined[j]; last[2][j] = ayJoined[j]; }
    } else if (ordinary2 == 1) {
        var sx[8]; var sy[8];
        for (var j = 0; j < 8; j++) { sx[j] = xSv[j]; sy[j] = ySv[j]; }
        last = secp256k1_slope_add_func(64, 4, secp256k1_join32(xAv), secp256k1_join32(yAv),
            secp256k1_join32(sx), secp256k1_join32(sy), 0);
    }
    var l2v[100] = p256_split64to32(last[0]);
    var outxv[100] = p256_split64to32(last[1]);
    var outyv[100] = p256_split64to32(last[2]);
    signal l2[8]; signal candidate[2][8]; signal xSe[8];
    for (var j = 0; j < 8; j++) {
        l2[j] <-- l2v[j];
        candidate[0][j] <-- outxv[j]; candidate[1][j] <-- outyv[j];
        (1 - finite2) * l2[j] === 0;
        (1 - finite2 - cancel) * candidate[0][j] === 0;
        cancel * (candidate[0][j] - ax[j]) === 0;
        (1 - finite2 - cancel) * candidate[1][j] === 0;
        xSe[j] <== xS[j] + bInf * (ax[j] - xS[j]);
        bInf * (l2[j] - l1[j]) === 0;
    }
    // Equality consumes the canonical ax, bx and xS. The output x is
    // canonical because the next step compares it; the output y is consumed
    // modulo p and needs only 32-bit limb bounds. Callers comparing raw y
    // coordinates must pin them to an exact canonical target as Straus does.
    component xSRange = CheckInRangeSecp256k1Limbs32();
    component outXRange = CheckInRangeSecp256k1Limbs32();
    component outYRange[8];
    component slopeRanges[2][8];
    for (var j = 0; j < 8; j++) {
        xSRange.in[j] <== xS[j];
        outXRange.in[j] <== candidate[0][j];
        outYRange[j] = Num2Bits(32); outYRange[j].in <== candidate[1][j];
        slopeRanges[0][j] = Num2Bits(32); slopeRanges[0][j].in <== l1[j];
        slopeRanges[1][j] = Num2Bits(32); slopeRanges[1][j].in <== l2[j];
    }

    component axsq = P256Mul();
    component l1ay = P256Mul(); component l1ax = P256Mul(); component l1bx = P256Mul();
    component l1sq = P256Mul(); component l1xS = P256Mul();
    component l2ax = P256Mul(); component l2xS = P256Mul();
    component l2sq = P256Mul(); component l2outx = P256Mul();
    for (var j = 0; j < 8; j++) {
        axsq.a[j] <== ax[j]; axsq.b[j] <== ax[j];
        l1ay.a[j] <== l1[j]; l1ay.b[j] <== ay[j];
        l1ax.a[j] <== l1[j]; l1ax.b[j] <== ax[j];
        l1bx.a[j] <== l1[j]; l1bx.b[j] <== bx[j];
        l1sq.a[j] <== l1[j]; l1sq.b[j] <== l1[j];
        l1xS.a[j] <== l1[j]; l1xS.b[j] <== xS[j];
        l2ax.a[j] <== l2[j]; l2ax.b[j] <== ax[j];
        l2xS.a[j] <== l2[j]; l2xS.b[j] <== xS[j];
        l2sq.a[j] <== l2[j]; l2sq.b[j] <== l2[j];
        l2outx.a[j] <== l2[j]; l2outx.b[j] <== candidate[0][j];
    }
    signal tangentResidual[15];
    signal chordResidual[15];
    signal lineResidual[15];
    signal cancelLine[15];
    component slopeCheck1 = Secp256k1CheckQuadraticModPIsZero69();
    component chord1 = Secp256k1CheckQuadraticModPIsZero69();
    component slopeCheck2 = Secp256k1CheckQuadraticModPIsZero69();
    component chord2 = Secp256k1CheckQuadraticModPIsZero69();
    component line2 = Secp256k1CheckQuadraticModPIsZero69();
    for (var i = 0; i < 15; i++) {
        tangentResidual[i] <== tangent1 * (2 * l1ay.out[i] - 3 * axsq.out[i]);
        if (i < 8) {
            chordResidual[i] <== (1 - sameX.out) * (l1bx.out[i] - l1ax.out[i] - b[1][i] + ay[i]);
            chord1.in[i] <== active1 * (l1sq.out[i] - ax[i] - bx[i] - xS[i]);
            slopeCheck2.in[i] <== ordinary2 * (l1xS.out[i] - l1ax.out[i] + l2xS.out[i] - l2ax.out[i] + 2 * ay[i]);
            chord2.in[i] <== finite2 * (l2sq.out[i] - ax[i] - xSe[i] - candidate[0][i]);
            lineResidual[i] <== finite2 * (l2outx.out[i] - l2ax.out[i] + candidate[1][i] + ay[i]);
            cancelLine[i] <== cancel * (candidate[1][i] + b[1][i]);
        } else {
            chordResidual[i] <== (1 - sameX.out) * (l1bx.out[i] - l1ax.out[i]);
            chord1.in[i] <== active1 * l1sq.out[i];
            slopeCheck2.in[i] <== ordinary2 * (l1xS.out[i] - l1ax.out[i] + l2xS.out[i] - l2ax.out[i]);
            chord2.in[i] <== finite2 * l2sq.out[i];
            lineResidual[i] <== finite2 * (l2outx.out[i] - l2ax.out[i]);
            cancelLine[i] <== 0;
        }
        slopeCheck1.in[i] <== tangentResidual[i] + chordResidual[i];
        line2.in[i] <== lineResidual[i] + cancelLine[i];
    }
    outInf <== zeroOut + aInf * (bInf - zeroOut);
    for (var c = 0; c < 2; c++) {
        for (var j = 0; j < 8; j++) {
            out[c][j] <== candidate[c][j] + aInf * (b[c][j] - candidate[c][j]);
        }
    }
}
