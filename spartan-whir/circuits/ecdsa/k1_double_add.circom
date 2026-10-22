pragma circom 2.2.0;

include "fused_arithmetic.circom";

// These helpers only produce witnesses. The five modular certificates below
// independently establish every slope and output coordinate.
function kb_k1_slope_add_hint12(xa, ya, xb, yb, tangent) {
    var p[22] = ecdsa_prime(0);
    var numerator[100];
    var denominator[100];
    if (tangent == 1) {
        var square[100] = prod(12, 22, xa, xa);
        var squareQR[2][100] = long_div(12, 22, 22, square, p);
        var twice[2][100] = kb_add_sub_hint(squareQR[1], squareQR[1], p, 0);
        var thrice[2][100] = kb_add_sub_hint(twice[0], squareQR[1], p, 0);
        var den[2][100] = kb_add_sub_hint(ya, ya, p, 0);
        numerator = thrice[0]; denominator = den[0];
    } else {
        var num[2][100] = kb_add_sub_hint(yb, ya, p, 1);
        var den[2][100] = kb_add_sub_hint(xb, xa, p, 1);
        numerator = num[0]; denominator = den[0];
    }
    var slope[100] = kb_divide(numerator, denominator, p);
    var slopeSquared[100] = prod(12, 22, slope, slope);
    var slopeQR[2][100] = long_div(12, 22, 22, slopeSquared, p);
    var minusXa[2][100] = kb_add_sub_hint(slopeQR[1], xa, p, 1);
    var resultX[2][100] = kb_add_sub_hint(minusXa[0], xb, p, 1);
    var deltaX[2][100] = kb_add_sub_hint(xa, resultX[0], p, 1);
    var line[100] = prod(12, 22, slope, deltaX[0]);
    var lineQR[2][100] = long_div(12, 22, 22, line, p);
    var resultY[2][100] = kb_add_sub_hint(lineQR[1], ya, p, 1);
    var out[3][100];
    for (var j = 0; j < 100; j++) {
        out[0][j] = 0; out[1][j] = 0; out[2][j] = 0;
    }
    for (var j = 0; j < 22; j++) {
        out[0][j] = slope[j]; out[1][j] = resultX[0][j]; out[2][j] = resultY[0][j];
    }
    return out;
}

function kb_k1_double_add_hints12(a, b, bInf) {
    var g[2][22] = ecdsa_generator(0);
    var sameX = 1;
    var sameY = 1;
    for (var j = 0; j < 22; j++) {
        if (a[0][j] != b[0][j]) sameX = 0;
        if (a[1][j] != b[1][j]) sameY = 0;
    }
    var tangent = sameX*sameY;
    var cancel = sameX*(1-sameY);
    var first[3][100];
    for (var c = 0; c < 3; c++) {
        for (var j = 0; j < 100; j++) first[c][j] = 0;
    }
    if (tangent == 1) first = kb_k1_slope_add_hint12(a[0], a[1], a[0], a[1], 1);
    else if (cancel == 0) first = kb_k1_slope_add_hint12(a[0], a[1], b[0], b[1], 0);
    var secondSameX = 1;
    for (var j = 0; j < 22; j++) {
        if (first[1][j] != a[0][j]) secondSameX = 0;
    }
    var last[3][100];
    for (var c = 0; c < 3; c++) {
        for (var j = 0; j < 100; j++) last[c][j] = 0;
    }
    if (bInf == 1) last = first;
    else if (cancel == 1) {
        for (var j = 0; j < 22; j++) { last[1][j] = a[0][j]; last[2][j] = a[1][j]; }
    } else if (secondSameX == 1) {
        for (var j = 0; j < 22; j++) { last[1][j] = g[0][j]; last[2][j] = g[1][j]; }
    } else last = kb_k1_slope_add_hint12(a[0], a[1], first[1], first[2], 0);
    var out[5][100];
    out[0] = kb_fused_12to11(first[0]); out[1] = kb_fused_12to11(first[1]);
    out[2] = kb_fused_12to11(last[0]); out[3] = kb_fused_12to11(last[1]);
    out[4] = kb_fused_12to11(last[2]);
    return out;
}

// Complete 2A+B as A+(A+B), with the intermediate y coordinate omitted.
// Inputs are canonical finite curve coordinates, or the caller's fixed
// generator encoding of infinity. The caller validates curve membership.
// All limbs are bounded here; xS and outputs remain canonical for later
// equality tests. Slopes represent a residue modulo p in 256 bounded bits;
// their highest limb has three bits and the other limbs have eleven.
//
// Each convolution coefficient is <=24*2047^2=100565016. The largest
// residual, 2*l1*yA-3*xA^2, has magnitude <=502825080. The common signed
// certificate bounds every full carry equality by 1677656211 < 2130706433.
template KbK1DoubleAdd() {
    var g12[2][22] = ecdsa_generator(0);
    var g[2][100];
    g[0] = kb_fused_12to11(g12[0]); g[1] = kb_fused_12to11(g12[1]);
    signal input a[2][22];
    signal input b[2][22];
    signal input aInf;
    signal input bInf;
    signal output out[2][22];
    signal output outInf;
    aInf*(aInf-1) === 0;
    bInf*(bInf-1) === 0;
    signal aa[2][22];
    signal bb[2][22];
    component a11[2];
    component b11[2];
    for (var c = 0; c < 2; c++) {
        a11[c] = KbFusedTo11(); b11[c] = KbFusedTo11();
        for (var j = 0; j < 22; j++) {
            aa[c][j] <== a[c][j]+aInf*(g12[c][j]-a[c][j]);
            bb[c][j] <== b[c][j]+bInf*(aa[c][j]-b[c][j]);
            a11[c].in[j] <== aa[c][j]; b11[c].in[j] <== bb[c][j];
        }
    }
    var hint[5][100] = kb_k1_double_add_hints12(aa, bb, bInf);
    // Rows: first slope, xS, second slope, xout, yout.
    signal value[5][24];
    component slopeRange[2][24];
    component canonical[3];
    for (var row = 0; row < 5; row++) {
        for (var j = 0; j < 24; j++) value[row][j] <-- hint[row][j];
        if (row == 0 || row == 2) {
            for (var j = 0; j < 24; j++) {
                if (j == 23) slopeRange[row \ 2][j] = Num2Bits(3);
                else slopeRange[row \ 2][j] = Num2Bits(11);
                slopeRange[row \ 2][j].in <== value[row][j];
            }
        } else {
            var index = row-1;
            if (row > 2) index = row-2;
            canonical[index] = KbFusedCanonical11For(0);
            for (var j = 0; j < 24; j++) canonical[index].in[j] <== value[row][j];
        }
    }
    component sameX = BigIsEqual(24);
    component sameY = BigIsEqual(24);
    component secondSameX = BigIsEqual(24);
    for (var j = 0; j < 24; j++) {
        sameX.in[0][j] <== a11[0].out[j]; sameX.in[1][j] <== b11[0].out[j];
        sameY.in[0][j] <== a11[1].out[j]; sameY.in[1][j] <== b11[1].out[j];
        secondSameX.in[0][j] <== a11[0].out[j]; secondSameX.in[1][j] <== value[1][j];
    }
    signal tangent;
    signal cancel;
    signal active;
    signal noBInf;
    signal ordinary2;
    signal zeroOut;
    signal finite2;
    tangent <== sameX.out*sameY.out;
    cancel <== sameX.out*(1-sameY.out);
    active <== 1-cancel;
    noBInf <== (1-bInf)*active;
    ordinary2 <== noBInf*(1-secondSameX.out);
    zeroOut <== noBInf*secondSameX.out;
    finite2 <== ordinary2+bInf;
    signal effectiveXs[24];
    for (var j = 0; j < 24; j++) {
        cancel*value[0][j] === 0;
        cancel*value[1][j] === 0;
        (1-finite2)*value[2][j] === 0;
        bInf*(value[2][j]-value[0][j]) === 0;
        cancel*(value[3][j]-a11[0].out[j]) === 0;
        (1-finite2-cancel)*(value[3][j]-g[0][j]) === 0;
        (1-finite2-cancel)*(value[4][j]-g[1][j]) === 0;
        effectiveXs[j] <== value[1][j]+bInf*(a11[0].out[j]-value[1][j]);
    }
    component ax2 = KbFusedConvolution11(24,24);
    component l1ay = KbFusedConvolution11(24,24);
    component l1ax = KbFusedConvolution11(24,24);
    component l1bx = KbFusedConvolution11(24,24);
    component l12 = KbFusedConvolution11(24,24);
    component l1xs = KbFusedConvolution11(24,24);
    component l2ax = KbFusedConvolution11(24,24);
    component l2xs = KbFusedConvolution11(24,24);
    component l22 = KbFusedConvolution11(24,24);
    component l2out = KbFusedConvolution11(24,24);
    for (var j = 0; j < 24; j++) {
        ax2.a[j] <== a11[0].out[j]; ax2.b[j] <== a11[0].out[j];
        l1ay.a[j] <== value[0][j]; l1ay.b[j] <== a11[1].out[j];
        l1ax.a[j] <== value[0][j]; l1ax.b[j] <== a11[0].out[j];
        l1bx.a[j] <== value[0][j]; l1bx.b[j] <== b11[0].out[j];
        l12.a[j] <== value[0][j]; l12.b[j] <== value[0][j];
        l1xs.a[j] <== value[0][j]; l1xs.b[j] <== value[1][j];
        l2ax.a[j] <== value[2][j]; l2ax.b[j] <== a11[0].out[j];
        l2xs.a[j] <== value[2][j]; l2xs.b[j] <== value[1][j];
        l22.a[j] <== value[2][j]; l22.b[j] <== value[2][j];
        l2out.a[j] <== value[2][j]; l2out.b[j] <== value[3][j];
    }
    component firstSlope = KbFusedModZero11For(47,0);
    component firstChord = KbFusedModZero11For(47,0);
    component secondSlope = KbFusedModZero11For(47,0);
    component secondChord = KbFusedModZero11For(47,0);
    component finalLine = KbFusedModZero11For(47,0);
    signal tangentResidual[47];
    signal chordResidual[47];
    signal finiteLine[47];
    signal cancelLine[47];
    for (var i = 0; i < 47; i++) {
        tangentResidual[i] <== tangent*(2*l1ay.out[i]-3*ax2.out[i]);
        var cr = l1bx.out[i]-l1ax.out[i];
        var x1 = l12.out[i];
        var s2 = l1xs.out[i]-l1ax.out[i]+l2xs.out[i]-l2ax.out[i];
        var x2 = l22.out[i];
        var yr = l2out.out[i]-l2ax.out[i];
        if (i < 24) {
            cr += a11[1].out[i]-b11[1].out[i];
            x1 -= a11[0].out[i]+b11[0].out[i]+value[1][i];
            s2 += 2*a11[1].out[i];
            x2 -= a11[0].out[i]+effectiveXs[i]+value[3][i];
            yr += value[4][i]+a11[1].out[i];
            cancelLine[i] <== cancel*(value[4][i]+b11[1].out[i]);
        } else cancelLine[i] <== 0;
        chordResidual[i] <== (1-sameX.out)*cr;
        firstSlope.in[i] <== tangentResidual[i]+chordResidual[i];
        firstChord.in[i] <== active*x1;
        secondSlope.in[i] <== ordinary2*s2;
        secondChord.in[i] <== finite2*x2;
        finiteLine[i] <== finite2*yr;
        finalLine.in[i] <== finiteLine[i]+cancelLine[i];
    }
    outInf <== zeroOut+aInf*(bInf-zeroOut);
    for (var c = 0; c < 2; c++) {
        for (var j = 0; j < 22; j++) out[c][j] <== canonical[1+c].out12[j]+aInf*(b[c][j]-canonical[1+c].out12[j]);
    }
}
