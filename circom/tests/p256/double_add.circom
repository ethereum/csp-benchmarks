pragma circom 2.0.2;
include "../../circuits/ecdsa/p256_complete.circom";

// Test-only ELM operation used to check the slope-chain exceptional cases.
/*
    Complete 2*a+b using the Eisentraeger-Lauter-Montgomery slope chain.
    The y coordinate of a+b is omitted. Canonical xS makes the second
    collision selector an equality modulo p. The infinity representation
    is (0,0,1); finite coordinates are canonical and slopes have 32-bit limbs.

    Stage 1 uses a tangent for b=a and a chord for distinct x. For b=-a,
    the output is a and the inactive stage is pinned to zero. Stage 2 uses
    a tangent when b is infinity. Otherwise (l1+l2)*(xS-xA)=-2*yA
    determines l2. If xS=xA, the result is infinity and stage 2 is pinned
    to zero. For a=infinity, safe operands G are used and the result is b.

    Each modular residual is gated after its products have been computed.
    Inactive residuals are zero, and inactive witnessed values are pinned.
    Every register is bounded by 2^69.

    Algebra and exception classes follow rot256's FusedStep at
    https://zk.golf/submissions/899ee03a-0e6c-4154-8571-648c30353840
    with the P-256 tangent numerator 3*x^2-3.
*/
template P256DoubleAddComplete() {
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
    signal tangent1;
    signal cancel;
    signal active1;
    tangent1 <== sameX.out * sameY.out;
    cancel <== sameX.out - tangent1;
    active1 <== 1 - cancel;

    // Witness generation branches only choose values; the selectors and
    // modular equations below independently establish the group relation.
    var xAv[8]; var yAv[8]; var xBv[8]; var yBv[8];
    for (var j = 0; j < 8; j++) {
        xAv[j] = ax[j]; yAv[j] = ay[j];
        xBv[j] = bx[j]; yBv[j] = by[j];
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
    // bInf makes bx=ax, by=ay, hence cancel=0. The two terms are disjoint.
    outInf <== zeroOut + aInf * (bInf - zeroOut);

    var last[3][100];
    for (var c = 0; c < 3; c++) {
        for (var j = 0; j < 100; j++) { last[c][j] = 0; }
    }
    if (bInf == 1) {
        last = p256_double_slope_func(32, 8, xAv, yAv);
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
        (1 - finite2) * candidate[0][j] === 0;
        (1 - finite2) * candidate[1][j] === 0;
        xSe[j] <== xS[j] + bInf * (ax[j] - xS[j]);
    }
    // Input validity guarantees canonical ax. Only coordinates consumed by
    // equality selectors or returned to callers need canonical reduction;
    // slopes are used modulo p and only need the product-register bounds.
    component ranges[3];
    component slopeRanges[2][8];
    for (var c = 0; c < 3; c++) { ranges[c] = CheckInRangeP256(); }
    for (var j = 0; j < 8; j++) {
        ranges[0].in[j] <== xS[j];
        ranges[1].in[j] <== candidate[0][j]; ranges[2].in[j] <== candidate[1][j];
        slopeRanges[0][j] = Num2Bits(32); slopeRanges[0][j].in <== l1[j];
        slopeRanges[1][j] = Num2Bits(32); slopeRanges[1][j].in <== l2[j];
    }

    component axsq = P256Mul();
    component l1ay = P256Mul(); component l1ax = P256Mul(); component l1bx = P256Mul();
    component l1sq = P256Mul(); component l1xS = P256Mul();
    component l2ay = P256Mul(); component l2ax = P256Mul(); component l2xS = P256Mul();
    component l2sq = P256Mul(); component l2outx = P256Mul();
    for (var j = 0; j < 8; j++) {
        axsq.a[j] <== ax[j]; axsq.b[j] <== ax[j];
        l1ay.a[j] <== l1[j]; l1ay.b[j] <== ay[j];
        l1ax.a[j] <== l1[j]; l1ax.b[j] <== ax[j];
        l1bx.a[j] <== l1[j]; l1bx.b[j] <== bx[j];
        l1sq.a[j] <== l1[j]; l1sq.b[j] <== l1[j];
        l1xS.a[j] <== l1[j]; l1xS.b[j] <== xS[j];
        l2ay.a[j] <== l2[j]; l2ay.b[j] <== ay[j];
        l2ax.a[j] <== l2[j]; l2ax.b[j] <== ax[j];
        l2xS.a[j] <== l2[j]; l2xS.b[j] <== xS[j];
        l2sq.a[j] <== l2[j]; l2sq.b[j] <== l2[j];
        l2outx.a[j] <== l2[j]; l2outx.b[j] <== candidate[0][j];
    }
    signal tangentResidual[2][15];
    signal chordResidual[2][15];
    component slopeCheck1 = P256CheckQuadraticModPIsZero69();
    component chord1 = P256CheckQuadraticModPIsZero69();
    component slopeCheck2 = P256CheckQuadraticModPIsZero69();
    component chord2 = P256CheckQuadraticModPIsZero69();
    component line2 = P256CheckQuadraticModPIsZero69();
    for (var i = 0; i < 15; i++) {
        var constant = 0;
        if (i == 0) { constant = 3; }
        tangentResidual[0][i] <== tangent1 * (2 * l1ay.out[i] - 3 * axsq.out[i] + constant);
        tangentResidual[1][i] <== bInf * (2 * l2ay.out[i] - 3 * axsq.out[i] + constant);
        if (i < 8) {
            chordResidual[0][i] <== (1 - sameX.out) * (l1bx.out[i] - l1ax.out[i] - by[i] + ay[i]);
            chord1.in[i] <== active1 * (l1sq.out[i] - ax[i] - bx[i] - xS[i]);
            chordResidual[1][i] <== ordinary2 * (l1xS.out[i] - l1ax.out[i] + l2xS.out[i] - l2ax.out[i] + 2 * ay[i]);
            chord2.in[i] <== finite2 * (l2sq.out[i] - ax[i] - xSe[i] - candidate[0][i]);
            line2.in[i] <== finite2 * (l2outx.out[i] - l2ax.out[i] + candidate[1][i] + ay[i]);
        } else {
            chordResidual[0][i] <== (1 - sameX.out) * (l1bx.out[i] - l1ax.out[i]);
            chord1.in[i] <== active1 * l1sq.out[i];
            chordResidual[1][i] <== ordinary2 * (l1xS.out[i] - l1ax.out[i] + l2xS.out[i] - l2ax.out[i]);
            chord2.in[i] <== finite2 * l2sq.out[i];
            line2.in[i] <== finite2 * (l2outx.out[i] - l2ax.out[i]);
        }
        // Each pair is disjoint: exactly one residual is active in a finite
        // slope branch. Their sum has the same 2^69 register bound.
        slopeCheck1.in[i] <== tangentResidual[0][i] + chordResidual[0][i];
        slopeCheck2.in[i] <== tangentResidual[1][i] + chordResidual[1][i];
    }
    signal withCancel[2][8];
    for (var j = 0; j < 8; j++) {
        withCancel[0][j] <== candidate[0][j] + cancel * (ax[j] - candidate[0][j]);
        withCancel[1][j] <== candidate[1][j] + cancel * (ay[j] - candidate[1][j]);
    }
    for (var c = 0; c < 2; c++) {
        for (var j = 0; j < 8; j++) {
            out[c][j] <== withCancel[c][j] + aInf * (b[c][j] - withCancel[c][j]);
        }
    }
}
