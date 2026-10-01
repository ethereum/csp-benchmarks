pragma circom 2.0.2;

include "./p256.circom";

// Flagged points use canonical affine coordinates when finite and (0,0)
// when isInf = 1. Arithmetic templates assume valid input points. Their
// basic outputs preserve this invariant by the group formulas and muxes.
// P256QuadAddComplete uses bounded coordinates modulo p for its accumulator.

// Complete a+b with a shared witnessed slope. The disjoint chord and
// tangent residuals share one modular certificate. The inverse branch pins
// slope and candidate coordinates to zero; input infinity uses safe finite
// operands internally and selects the other input in the output muxes.
template P256AddComplete() {
    signal input a[2][8];
    signal input b[2][8];
    signal input aInf;
    signal input bInf;
    signal output out[2][8];
    signal output outInf;
    aInf * (aInf - 1) === 0;
    bInf * (bInf - 1) === 0;
    var gx[100] = get_p256_gx(32, 8);
    var gy[100] = get_p256_gy(32, 8);
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
    signal finiteBoth;
    signal finiteCancel;
    tangent <== sameX.out * sameY.out;
    cancel <== sameX.out - tangent;
    active <== 1 - cancel;
    finiteBoth <== (1 - aInf) * (1 - bInf);
    finiteCancel <== finiteBoth * cancel;
    outInf <== aInf * bInf + finiteCancel;

    var xAv[8]; var yAv[8]; var xBv[8]; var yBv[8];
    for (var j = 0; j < 8; j++) {
        xAv[j] = ax[j]; yAv[j] = ay[j]; xBv[j] = bx[j]; yBv[j] = by[j];
    }
    var result[3][100];
    for (var c = 0; c < 3; c++) {
        for (var j = 0; j < 100; j++) { result[c][j] = 0; }
    }
    if (tangent == 1) {
        result = p256_double_slope_func(32, 8, xAv, yAv);
    } else if (cancel == 0) {
        var sum[2][100] = p256_addunequal_func(32, 8, xAv, yAv, xBv, yBv);
        var prime[100] = get_p256_prime(32, 8);
        var xA[100] = p256_load(32, 8, xAv, prime);
        var yA[100] = p256_load(32, 8, yAv, prime);
        var xB[100] = p256_load(32, 8, xBv, prime);
        var yB[100] = p256_load(32, 8, yBv, prime);
        var dx[100] = sm_sub_mod(32, 8, xB, xA, prime);
        var dy[100] = sm_sub_mod(32, 8, yB, yA, prime);
        var dxInv[100] = mod_inv(32, 8, dx, prime);
        var slope[100] = prod_mod_p(32, 8, dy, dxInv, prime);
        for (var j = 0; j < 100; j++) {
            result[0][j] = slope[j]; result[1][j] = sum[0][j]; result[2][j] = sum[1][j];
        }
    }
    signal lambda[8];
    signal candidate[2][8];
    component lambdaRange[8];
    component candidateRange[2];
    for (var c = 0; c < 2; c++) { candidateRange[c] = CheckInRangeP256(); }
    for (var j = 0; j < 8; j++) {
        lambda[j] <-- result[0][j];
        candidate[0][j] <-- result[1][j]; candidate[1][j] <-- result[2][j];
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
    component slopeCheck = P256CheckQuadraticModPIsZero69();
    component xCheck = P256CheckQuadraticModPIsZero69();
    component yCheck = P256CheckQuadraticModPIsZero69();
    for (var i = 0; i < 15; i++) {
        var constant = 0;
        if (i == 0) { constant = 3; }
        tangentResidual[i] <== tangent * (2 * lay.out[i] - 3 * xasq.out[i] + constant);
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
    Complete 4*a+b. The input a and output are bounded 32-bit-limb
    coordinates representing finite points modulo p, or zero coordinates
    with infinity flag 1. The table operand b must be canonical when finite.
    This template's output feeds only itself in the Straus accumulator;
    P256AddComplete requires canonical inputs.

    The step uses implicit yD=l0*(xR-xD)-yR. Canonical xD and xS
    determine the two x collisions. On an equal finite x, equalY is a
    boolean selector constrained by yD=(2*equalY-1)*yB modulo p. Nonzero
    yD fixes exactly one sign. The second tangent reuses l1 when b is
    infinity. Cancellation returns -b through the final line certificate.

    The tangent product l1*yD uses signed registers below 2^67+2^32.
    Its 22 coefficients, doubled and combined with 3*xD^2, stay below
    2^104 in absolute value; the other residuals have the 2^69 bound.
*/
template P256QuadAddComplete() {
    signal input a[2][8];
    signal input b[2][8];
    signal input aInf;
    signal input bInf;
    signal output out[2][8];
    signal output outInf;
    aInf * (aInf - 1) === 0;
    bInf * (bInf - 1) === 0;

    var gx[100] = get_p256_gx(32, 8);
    var gy[100] = get_p256_gy(32, 8);
    signal rx[8]; signal ry[8];
    for (var j = 0; j < 8; j++) {
        rx[j] <== a[0][j] + aInf * (gx[j] - a[0][j]);
        ry[j] <== a[1][j] + aInf * (gy[j] - a[1][j]);
    }
    var rXv[8]; var rYv[8];
    for (var j = 0; j < 8; j++) { rXv[j] = rx[j]; rYv[j] = ry[j]; }
    var initial[3][100] = p256_double_slope_func(32, 8, rXv, rYv);
    signal l0[8]; signal ax[8]; signal bx[8];
    for (var j = 0; j < 8; j++) {
        l0[j] <-- initial[0][j]; ax[j] <-- initial[1][j];
        bx[j] <== b[0][j] + bInf * (ax[j] - b[0][j]);
    }
    component l0Range[8];
    component axRange = CheckInRangeP256();
    component l0ry = P256Mul(); component rxsq = P256Mul(); component l0sq = P256Mul();
    component l0rx = P256Mul(); component l0ax = P256Mul();
    for (var j = 0; j < 8; j++) {
        l0Range[j] = Num2Bits(32); l0Range[j].in <== l0[j];
        axRange.in[j] <== ax[j];
        l0ry.a[j] <== l0[j]; l0ry.b[j] <== ry[j];
        rxsq.a[j] <== rx[j]; rxsq.b[j] <== rx[j];
        l0sq.a[j] <== l0[j]; l0sq.b[j] <== l0[j];
        l0rx.a[j] <== l0[j]; l0rx.b[j] <== rx[j];
        l0ax.a[j] <== l0[j]; l0ax.b[j] <== ax[j];
    }
    // Signed registers represent yD=l0*(xR-xD)-yR modulo p. Each is
    // bounded by 8*(2^32-1)^2+(2^32-1) < 2^67+2^32.
    signal ay[15];
    component initialTangent = P256CheckQuadraticModPIsZero69();
    component initialChord = P256CheckQuadraticModPIsZero69();
    for (var i = 0; i < 15; i++) {
        var constant = 0;
        if (i == 0) { constant = 3; }
        initialTangent.in[i] <== 2 * l0ry.out[i] - 3 * rxsq.out[i] + constant;
        if (i < 8) {
            ay[i] <== l0rx.out[i] - l0ax.out[i] - ry[i];
            initialChord.in[i] <== l0sq.out[i] - 2 * rx[i] - ax[i];
        } else {
            ay[i] <== l0rx.out[i] - l0ax.out[i];
            initialChord.in[i] <== l0sq.out[i];
        }
    }
    component sameX = BigIsEqual(8);
    for (var j = 0; j < 8; j++) {
        sameX.in[0][j] <== ax[j]; sameX.in[1][j] <== bx[j];
    }
    signal sameFiniteX;
    signal equalY;
    signal tangent1;
    signal cancel;
    signal active1;
    sameFiniteX <== (1 - bInf) * sameX.out;
    var yEqual = 1;
    for (var j = 0; j < 8; j++) { if (initial[2][j] != b[1][j]) { yEqual = 0; } }
    equalY <-- sameFiniteX * yEqual;
    equalY * (equalY - 1) === 0;
    (1 - sameFiniteX) * equalY === 0;
    tangent1 <== bInf + equalY;
    cancel <== sameFiniteX - equalY;
    active1 <== 1 - cancel;
    signal signedBY[8];
    for (var j = 0; j < 8; j++) { signedBY[j] <== b[1][j] - 2 * equalY * b[1][j]; }
    component signCheck = P256CheckQuadraticModPIsZero69();
    for (var i = 0; i < 15; i++) {
        if (i < 8) { signCheck.in[i] <== sameFiniteX * (ay[i] + signedBY[i]); }
        else { signCheck.in[i] <== sameFiniteX * ay[i]; }
    }

    // Witness generation branches only choose values; the selectors and
    // modular equations below independently establish the group relation.
    var xAv[8]; var yAv[8]; var xBv[8]; var yBv[8];
    for (var j = 0; j < 8; j++) {
        xAv[j] = ax[j]; yAv[j] = initial[2][j];
        xBv[j] = bx[j]; yBv[j] = b[1][j];
    }
    var first[3][100];
    for (var c = 0; c < 3; c++) {
        for (var j = 0; j < 100; j++) { first[c][j] = 0; }
    }
    if (tangent1 == 1) {
        first = p256_double_slope_func(32, 8, xAv, yAv);
    } else if (cancel == 0) {
        var sum[2][100] = p256_addunequal_func(32, 8, xAv, yAv, xBv, yBv);
        var prime[100] = get_p256_prime(32, 8);
        var xA[100] = p256_load(32, 8, xAv, prime);
        var yA[100] = p256_load(32, 8, yAv, prime);
        var xB[100] = p256_load(32, 8, xBv, prime);
        var yB[100] = p256_load(32, 8, yBv, prime);
        var dx[100] = sm_sub_mod(32, 8, xB, xA, prime);
        var dy[100] = sm_sub_mod(32, 8, yB, yA, prime);
        var inv[100] = mod_inv(32, 8, dx, prime);
        var slope[100] = prod_mod_p(32, 8, dy, inv, prime);
        for (var j = 0; j < 100; j++) {
            first[0][j] = slope[j]; first[1][j] = sum[0][j]; first[2][j] = sum[1][j];
        }
    }
    signal l1[8]; signal xS[8];
    for (var j = 0; j < 8; j++) {
        l1[j] <-- first[0][j]; xS[j] <-- first[1][j];
        cancel * l1[j] === 0;
        cancel * xS[j] === 0;
    }
    component secondSameX = BigIsEqual(8);
    for (var j = 0; j < 8; j++) {
        secondSameX.in[0][j] <== ax[j]; secondSameX.in[1][j] <== xS[j];
    }
    signal ordinary2;
    signal zeroOut;
    signal finite2;
    signal noBInf;
    noBInf <== (1 - bInf) * active1;
    ordinary2 <== noBInf * (1 - secondSameX.out);
    zeroOut <== noBInf * secondSameX.out;
    finite2 <== ordinary2 + bInf;
    // bInf forces equalY=0 and cancel=0. The two terms are disjoint.
    var last[3][100];
    for (var c = 0; c < 3; c++) {
        for (var j = 0; j < 100; j++) { last[c][j] = 0; }
    }
    if (bInf == 1) {
        last = first;
    } else if (cancel == 1) {
        for (var j = 0; j < 100; j++) { last[1][j] = initial[1][j]; last[2][j] = initial[2][j]; }
    } else if (ordinary2 == 1) {
        var sx[8]; var sy[8];
        for (var j = 0; j < 8; j++) { sx[j] = first[1][j]; sy[j] = first[2][j]; }
        var sum2[2][100] = p256_addunequal_func(32, 8, xAv, yAv, sx, sy);
        var prime2[100] = get_p256_prime(32, 8);
        var xA2[100] = p256_load(32, 8, xAv, prime2);
        var yA2[100] = p256_load(32, 8, yAv, prime2);
        var xB2[100] = p256_load(32, 8, sx, prime2);
        var yB2[100] = p256_load(32, 8, sy, prime2);
        var dx2[100] = sm_sub_mod(32, 8, xB2, xA2, prime2);
        var dy2[100] = sm_sub_mod(32, 8, yB2, yA2, prime2);
        var inv2[100] = mod_inv(32, 8, dx2, prime2);
        var slope2[100] = prod_mod_p(32, 8, dy2, inv2, prime2);
        for (var j = 0; j < 100; j++) {
            last[0][j] = slope2[j]; last[1][j] = sum2[0][j]; last[2][j] = sum2[1][j];
        }
    }
    signal l2[8]; signal candidate[2][8]; signal xSe[8];
    for (var j = 0; j < 8; j++) {
        l2[j] <-- last[0][j];
        candidate[0][j] <-- last[1][j]; candidate[1][j] <-- last[2][j];
        (1 - finite2) * l2[j] === 0;
        (1 - finite2 - cancel) * candidate[0][j] === 0;
        cancel * (candidate[0][j] - ax[j]) === 0;
        (1 - finite2 - cancel) * candidate[1][j] === 0;
        xSe[j] <== xS[j] + bInf * (ax[j] - xS[j]);
        bInf * (l2[j] - l1[j]) === 0;
    }
    // Equality consumes only canonical ax and xS, and the canonical table
    // operand b. The accumulator output is consumed modulo p by the next
    // step, so its coordinates need only 32-bit limb bounds. Infinity has
    // zero coordinates. Callers comparing raw coordinates must canonicalize
    // them or pin them to an exact canonical target as Straus does.
    component xSRange = CheckInRangeP256();
    component candidateRanges[2][8];
    component slopeRanges[2][8];
    for (var j = 0; j < 8; j++) {
        xSRange.in[j] <== xS[j];
        for (var c = 0; c < 2; c++) {
            candidateRanges[c][j] = Num2Bits(32);
            candidateRanges[c][j].in <== candidate[c][j];
        }
        slopeRanges[0][j] = Num2Bits(32); slopeRanges[0][j].in <== l1[j];
        slopeRanges[1][j] = Num2Bits(32); slopeRanges[1][j].in <== l2[j];
    }

    component axsq = P256Mul();
    component l1ay = P256MultNoCarry(69, 32, 15, 8); component l1ax = P256Mul(); component l1bx = P256Mul();
    component l1sq = P256Mul(); component l1xS = P256Mul();
    component l2ax = P256Mul(); component l2xS = P256Mul();
    component l2sq = P256Mul(); component l2outx = P256Mul();
    for (var j = 0; j < 8; j++) {
        axsq.a[j] <== ax[j]; axsq.b[j] <== ax[j];
        l1ay.b[j] <== l1[j];
        l1ax.a[j] <== l1[j]; l1ax.b[j] <== ax[j];
        l1bx.a[j] <== l1[j]; l1bx.b[j] <== bx[j];
        l1sq.a[j] <== l1[j]; l1sq.b[j] <== l1[j];
        l1xS.a[j] <== l1[j]; l1xS.b[j] <== xS[j];
        l2ax.a[j] <== l2[j]; l2ax.b[j] <== ax[j];
        l2xS.a[j] <== l2[j]; l2xS.b[j] <== xS[j];
        l2sq.a[j] <== l2[j]; l2sq.b[j] <== l2[j];
        l2outx.a[j] <== l2[j]; l2outx.b[j] <== candidate[0][j];
    }
    for (var i = 0; i < 15; i++) { l1ay.a[i] <== ay[i]; }
    signal tangentResidual[22];
    signal chordResidual[15];
    signal lineResidual[15];
    signal cancelLine[15];
    component slopeCheck1 = P256CheckCubicModPIsZero104();
    component chord1 = P256CheckQuadraticModPIsZero69();
    component slopeCheck2 = P256CheckQuadraticModPIsZero69();
    for (var i = 0; i < 22; i++) {
        var constant = 0;
        if (i == 0) { constant = 3; }
        if (i < 15) { tangentResidual[i] <== tangent1 * (2 * l1ay.out[i] - 3 * axsq.out[i] + constant); }
        else { tangentResidual[i] <== tangent1 * (2 * l1ay.out[i]); }
    }
    component chord2 = P256CheckQuadraticModPIsZero69();
    component line2 = P256CheckQuadraticModPIsZero69();
    for (var i = 0; i < 15; i++) {
        if (i < 8) {
            chordResidual[i] <== (1 - sameX.out) * (l1bx.out[i] - l1ax.out[i] - b[1][i] + ay[i]);
            chord1.in[i] <== active1 * (l1sq.out[i] - ax[i] - bx[i] - xS[i]);
            slopeCheck2.in[i] <== ordinary2 * (l1xS.out[i] - l1ax.out[i] + l2xS.out[i] - l2ax.out[i] + 2 * ay[i]);
            chord2.in[i] <== finite2 * (l2sq.out[i] - ax[i] - xSe[i] - candidate[0][i]);
            lineResidual[i] <== finite2 * (l2outx.out[i] - l2ax.out[i] + candidate[1][i] + ay[i]);
        } else {
            chordResidual[i] <== (1 - sameX.out) * (l1bx.out[i] - l1ax.out[i] + ay[i]);
            chord1.in[i] <== active1 * l1sq.out[i];
            slopeCheck2.in[i] <== ordinary2 * (l1xS.out[i] - l1ax.out[i] + l2xS.out[i] - l2ax.out[i] + 2 * ay[i]);
            chord2.in[i] <== finite2 * l2sq.out[i];
            lineResidual[i] <== finite2 * (l2outx.out[i] - l2ax.out[i] + ay[i]);
        }
        if (i < 8) { cancelLine[i] <== cancel * (candidate[1][i] + b[1][i]); }
        else { cancelLine[i] <== 0; }
        line2.in[i] <== lineResidual[i] + cancelLine[i];
    }
    for (var i = 0; i < 22; i++) {
        if (i < 15) { slopeCheck1.in[i] <== tangentResidual[i] + chordResidual[i]; }
        else { slopeCheck1.in[i] <== tangentResidual[i]; }
    }
    outInf <== zeroOut + aInf * (bInf - zeroOut);
    for (var c = 0; c < 2; c++) {
        for (var j = 0; j < 8; j++) {
            out[c][j] <== candidate[c][j] + aInf * (b[c][j] - candidate[c][j]);
        }
    }
}
