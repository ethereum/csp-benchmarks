pragma circom 2.2.0;

include "fused_arithmetic.circom";

// Witness helpers use the existing bounded 12-bit arithmetic. Constraints
// independently establish all slopes, coordinates, and branch selections.
function kb_quad_slope_add_hint12(xa, ya, xb, yb, tangent) {
    var p[22] = ecdsa_prime(1);
    var numerator[100];
    var denominator[100];
    if (tangent == 1) {
        var square[100] = prod(12, 22, xa, xa);
        var squareQR[2][100] = long_div(12, 22, 22, square, p);
        var twice[2][100] = kb_add_sub_hint(squareQR[1], squareQR[1], p, 0);
        var thrice[2][100] = kb_add_sub_hint(twice[0], squareQR[1], p, 0);
        var three[22];
        for (var j = 0; j < 22; j++) three[j] = 0;
        three[0] = 3;
        var num[2][100] = kb_add_sub_hint(thrice[0], three, p, 1);
        var den[2][100] = kb_add_sub_hint(ya, ya, p, 0);
        numerator = num[0]; denominator = den[0];
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

function kb_quad_hints12(a, b, bInf) {
    var g[2][22] = ecdsa_generator(1);
    var initial[3][100] = kb_quad_slope_add_hint12(a[0], a[1], a[0], a[1], 1);
    var sameX = 1;
    var sameY = 1;
    for (var j = 0; j < 22; j++) {
        if (initial[1][j] != b[0][j]) sameX = 0;
        if (initial[2][j] != b[1][j]) sameY = 0;
    }
    var equalY = (1-bInf)*sameX*sameY;
    var cancel = (1-bInf)*sameX*(1-sameY);
    var first[3][100];
    for (var c = 0; c < 3; c++) {
        for (var j = 0; j < 100; j++) first[c][j] = 0;
    }
    if (bInf == 1 || equalY == 1) {
        first = kb_quad_slope_add_hint12(initial[1], initial[2], initial[1], initial[2], 1);
    } else if (cancel == 0) {
        first = kb_quad_slope_add_hint12(initial[1], initial[2], b[0], b[1], 0);
    }
    var secondSameX = 1;
    for (var j = 0; j < 22; j++) {
        if (initial[1][j] != first[1][j]) secondSameX = 0;
    }
    var last[3][100];
    for (var c = 0; c < 3; c++) {
        for (var j = 0; j < 100; j++) last[c][j] = 0;
    }
    if (bInf == 1) last = first;
    else if (cancel == 1) {
        for (var j = 0; j < 22; j++) {
            last[1][j] = initial[1][j]; last[2][j] = initial[2][j];
        }
    } else if (secondSameX == 1) {
        for (var j = 0; j < 22; j++) {
            last[1][j] = g[0][j]; last[2][j] = g[1][j];
        }
    } else {
        last = kb_quad_slope_add_hint12(initial[1], initial[2], first[1], first[2], 0);
    }
    var out[8][100];
    for (var row = 0; row < 8; row++) {
        for (var j = 0; j < 100; j++) out[row][j] = 0;
    }
    out[0] = kb_fused_12to11(initial[0]);
    out[1] = kb_fused_12to11(initial[1]);
    out[2] = kb_fused_12to11(first[0]);
    out[3] = kb_fused_12to11(first[1]);
    out[4] = kb_fused_12to11(last[0]);
    out[5] = kb_fused_12to11(last[1]);
    out[6] = kb_fused_12to11(last[2]);
    out[7][0] = equalY;
    return out;
}

// Complete 4A+B using three slopes and direct modular certificates. For
// D=2A and S=D+B, yD is an unreduced 48-limb integer, and yS is omitted.
// Every polynomial coefficient is staged in 11-bit digits. The largest
// residual is 2*l1*yD-3*xD^2+3, bounded by 5*24*2047^2+3; the modular
// certificate proves its full signed carry equations below KoalaBear.
template KbP256QuadAdd() {
    var p[24] = kb_fused_prime11();
    var g12[2][22] = ecdsa_generator(1);
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
    signal safeA[2][22];
    component a11[2];
    component b11[2];
    for (var c = 0; c < 2; c++) {
        a11[c] = KbFusedTo11(); b11[c] = KbFusedTo11();
        for (var j = 0; j < 22; j++) {
            safeA[c][j] <== a[c][j]+aInf*(g12[c][j]-a[c][j]);
            a11[c].in[j] <== safeA[c][j]; b11[c].in[j] <== b[c][j];
        }
    }
    var hint[8][100] = kb_quad_hints12(safeA, b, bInf);
    // Rows: initial slope, xD, first fused slope, xS, final slope, xout,yout.
    signal value[7][24];
    component canonical[7];
    component slopeRange[3][24];
    for (var row = 0; row < 7; row++) {
        if (row == 1 || row == 3 || row >= 5) canonical[row] = KbFusedCanonical11();
        for (var j = 0; j < 24; j++) {
            value[row][j] <-- hint[row][j];
            if (row == 0 || row == 2 || row == 4) {
                // Slopes use 256 bounded bits: three in the highest limb,
                // eleven elsewhere. The convolution and signed carry bounds
                // hold; coordinate equality still uses canonical rows.
                if (j == 23) slopeRange[row \ 2][j] = Num2Bits(3);
                else slopeRange[row \ 2][j] = Num2Bits(11);
                slopeRange[row \ 2][j].in <== value[row][j];
            } else canonical[row].in[j] <== value[row][j];
        }
    }
    component l0y = KbFusedConvolution11(24,24);
    component rx2 = KbFusedConvolution11(24,24);
    component l02 = KbFusedConvolution11(24,24);
    component l0rx = KbFusedConvolution11(24,24);
    component l0xd = KbFusedConvolution11(24,24);
    for (var j = 0; j < 24; j++) {
        l0y.a[j] <== value[0][j]; l0y.b[j] <== a11[1].out[j];
        rx2.a[j] <== a11[0].out[j]; rx2.b[j] <== a11[0].out[j];
        l02.a[j] <== value[0][j]; l02.b[j] <== value[0][j];
        l0rx.a[j] <== value[0][j]; l0rx.b[j] <== a11[0].out[j];
        l0xd.a[j] <== value[0][j]; l0xd.b[j] <== value[1][j];
    }
    component initialTangent = KbFusedModZero11(47);
    component initialChord = KbFusedModZero11(47);
    component yWide = KbFusedNormalize11(48);
    for (var i = 0; i < 48; i++) {
        var tangent = 0;
        if (i == 0) tangent = 3;
        if (i < 47) {
            initialTangent.in[i] <== 2*l0y.out[i]-3*rx2.out[i]+tangent;
            if (i < 24) initialChord.in[i] <== l02.out[i]-2*a11[0].out[i]-value[1][i];
            else initialChord.in[i] <== l02.out[i];
        }
        var offset = 0;
        if (i >= 24) offset = p[i-24];
        var yCoefficient = offset;
        if (i < 47) yCoefficient += l0rx.out[i]-l0xd.out[i];
        if (i < 24) yCoefficient -= a11[1].out[i];
        yWide.in[i] <== yCoefficient;
    }

    signal bx[24];
    component sameX = BigIsEqual(24);
    for (var j = 0; j < 24; j++) {
        bx[j] <== b11[0].out[j]+bInf*(value[1][j]-b11[0].out[j]);
        sameX.in[0][j] <== value[1][j]; sameX.in[1][j] <== bx[j];
    }
    signal sameFiniteX;
    signal equalY;
    signal tangent1;
    signal cancel;
    signal active;
    sameFiniteX <== (1-bInf)*sameX.out;
    equalY <-- hint[7][0];
    equalY*(equalY-1) === 0;
    (1-sameFiniteX)*equalY === 0;
    tangent1 <== bInf+equalY;
    cancel <== sameFiniteX-equalY;
    active <== 1-cancel;
    signal signedBy[24];
    for (var j = 0; j < 24; j++) signedBy[j] <== b11[1].out[j]-2*equalY*b11[1].out[j];
    component signCheck = KbFusedModZero11(48);
    for (var i = 0; i < 48; i++) {
        if (i < 24) signCheck.in[i] <== sameFiniteX*(yWide.out[i]+signedBy[i]);
        else signCheck.in[i] <== sameFiniteX*yWide.out[i];
    }
    component xd2 = KbFusedConvolution11(24,24);
    component l1yd = KbFusedConvolution11(24,48);
    component l1xd = KbFusedConvolution11(24,24);
    component l1bx = KbFusedConvolution11(24,24);
    component l12 = KbFusedConvolution11(24,24);
    component l1xs = KbFusedConvolution11(24,24);
    component l2xd = KbFusedConvolution11(24,24);
    component l2xs = KbFusedConvolution11(24,24);
    component l22 = KbFusedConvolution11(24,24);
    component l2out = KbFusedConvolution11(24,24);
    for (var j = 0; j < 24; j++) {
        xd2.a[j] <== value[1][j]; xd2.b[j] <== value[1][j];
        l1yd.a[j] <== value[2][j];
        l1xd.a[j] <== value[2][j]; l1xd.b[j] <== value[1][j];
        l1bx.a[j] <== value[2][j]; l1bx.b[j] <== bx[j];
        l12.a[j] <== value[2][j]; l12.b[j] <== value[2][j];
        l1xs.a[j] <== value[2][j]; l1xs.b[j] <== value[3][j];
        l2xd.a[j] <== value[4][j]; l2xd.b[j] <== value[1][j];
        l2xs.a[j] <== value[4][j]; l2xs.b[j] <== value[3][j];
        l22.a[j] <== value[4][j]; l22.b[j] <== value[4][j];
        l2out.a[j] <== value[4][j]; l2out.b[j] <== value[5][j];
    }
    for (var i = 0; i < 48; i++) l1yd.b[i] <== yWide.out[i];
    component firstSlope = KbFusedModZero11(71);
    signal tangentResidual[71];
    signal chordResidual[71];
    component firstChord = KbFusedModZero11(47);
    for (var i = 0; i < 71; i++) {
        var tr = 2*l1yd.out[i];
        if (i < 47) tr -= 3*xd2.out[i];
        if (i == 0) tr += 3;
        tangentResidual[i] <== tangent1*tr;
        var cr = 0;
        if (i < 47) cr += l1bx.out[i]-l1xd.out[i];
        if (i < 48) cr += yWide.out[i];
        if (i < 24) cr -= b11[1].out[i];
        chordResidual[i] <== (1-sameX.out)*cr;
        firstSlope.in[i] <== tangentResidual[i]+chordResidual[i];
        if (i < 47) {
            var xr = l12.out[i];
            if (i < 24) xr -= value[1][i]+bx[i]+value[3][i];
            firstChord.in[i] <== active*xr;
        }
    }
    for (var j = 0; j < 24; j++) {
        cancel*value[2][j] === 0;
        cancel*value[3][j] === 0;
    }
    component secondSameX = BigIsEqual(24);
    for (var j = 0; j < 24; j++) {
        secondSameX.in[0][j] <== value[1][j]; secondSameX.in[1][j] <== value[3][j];
    }
    signal noBInf;
    signal ordinary2;
    signal zeroOut;
    signal finite2;
    noBInf <== (1-bInf)*active;
    ordinary2 <== noBInf*(1-secondSameX.out);
    zeroOut <== noBInf*secondSameX.out;
    finite2 <== ordinary2+bInf;
    signal effectiveXs[24];
    for (var j = 0; j < 24; j++) {
        (1-finite2)*value[4][j] === 0;
        bInf*(value[4][j]-value[2][j]) === 0;
        cancel*(value[5][j]-value[1][j]) === 0;
        (1-finite2-cancel)*(value[5][j]-g[0][j]) === 0;
        (1-finite2-cancel)*(value[6][j]-g[1][j]) === 0;
        effectiveXs[j] <== value[3][j]+bInf*(value[1][j]-value[3][j]);
    }
    component secondSlope = KbFusedModZero11(48);
    component secondChord = KbFusedModZero11(47);
    component finalLine = KbFusedModZero11(48);
    signal finiteLine[48];
    signal cancelLine[48];
    for (var i = 0; i < 48; i++) {
        var sr = 2*yWide.out[i];
        if (i < 47) sr += l1xs.out[i]-l1xd.out[i]+l2xs.out[i]-l2xd.out[i];
        secondSlope.in[i] <== ordinary2*sr;
        if (i < 47) {
            var xr = l22.out[i];
            if (i < 24) xr -= value[1][i]+effectiveXs[i]+value[5][i];
            secondChord.in[i] <== finite2*xr;
        }
        var yr = yWide.out[i];
        if (i < 47) yr += l2out.out[i]-l2xd.out[i];
        if (i < 24) yr += value[6][i];
        finiteLine[i] <== finite2*yr;
        if (i < 24) cancelLine[i] <== cancel*(value[6][i]+b11[1].out[i]);
        else cancelLine[i] <== 0;
        finalLine.in[i] <== finiteLine[i]+cancelLine[i];
    }
    outInf <== zeroOut+aInf*(bInf-zeroOut);
    for (var c = 0; c < 2; c++) {
        for (var j = 0; j < 22; j++) out[c][j] <== canonical[5+c].out12[j]+aInf*(b[c][j]-canonical[5+c].out12[j]);
    }
}
