pragma circom 2.2.0;

include "curve.circom";
include "p256_quad.circom";
include "k1_double_add.circom";

function kb_fused_second_slope(l1, twiceY, delta, p, ordinary, bInf) {
    var out[100];
    for (var j = 0; j < 100; j++) out[j] = 0;
    if (bInf == 1) {
        for (var j = 0; j < 22; j++) out[j] = l1[j];
    } else if (ordinary == 1) {
        var quotient[100] = kb_divide(twiceY, delta, p);
        var zero[22];
        for (var j = 0; j < 22; j++) zero[j] = 0;
        var negative[2][100] = kb_add_sub_hint(zero, l1, p, 1);
        var difference[2][100] = kb_add_sub_hint(negative[0], quotient, p, 1);
        out = difference[0];
    }
    return out;
}

// Complete 2*a+b using a+(a+b), with the y coordinate of a+b omitted.
// For S=a+b, the second slope obeys
//     (l1+l2)*(xS-xa) = -2*ya (mod p).
// Canonical coordinates make the exceptional-case equality tests exact.
// Infinity, a=b, a=-b, and a+b=-a have explicit constrained branches.
template KbPointDoubleAddReduced(p256) {
    var p[22] = ecdsa_prime(p256);
    var g[2][22] = ecdsa_generator(p256);
    signal input a[2][22];
    signal input b[2][22];
    signal input aInf;
    signal input bInf;
    signal output out[2][22];
    signal output outInf;
    aInf * (aInf-1) === 0;
    bInf * (bInf-1) === 0;

    // With a=O, compute on G and select b afterwards. With b=O the first
    // addition is a tangent and the final output is exactly that doubling.
    signal aa[2][22];
    signal bb[2][22];
    for (var c = 0; c < 2; c++) {
        for (var j = 0; j < 22; j++) {
            aa[c][j] <== a[c][j] + aInf*(g[c][j]-a[c][j]);
            bb[c][j] <== b[c][j] + bInf*(aa[c][j]-b[c][j]);
        }
    }
    component eqX = BigIsEqual(22);
    component eqY = BigIsEqual(22);
    component chordX = KbSub(p);
    component chordY = KbSub(p);
    component twiceY = KbAdd(p);
    component x2 = KbMul(p);
    for (var j = 0; j < 22; j++) {
        eqX.in[0][j] <== aa[0][j]; eqX.in[1][j] <== bb[0][j];
        eqY.in[0][j] <== aa[1][j]; eqY.in[1][j] <== bb[1][j];
        chordX.a[j] <== bb[0][j]; chordX.b[j] <== aa[0][j];
        chordY.a[j] <== bb[1][j]; chordY.b[j] <== aa[1][j];
        twiceY.a[j] <== aa[1][j]; twiceY.b[j] <== aa[1][j];
        x2.a[j] <== aa[0][j]; x2.b[j] <== aa[0][j];
    }
    signal tangent;
    signal cancel;
    signal active;
    tangent <== eqX.out*eqY.out;
    cancel <== eqX.out*(1-eqY.out);
    active <== 1-cancel;
    component twiceX2 = KbAdd(p);
    for (var j = 0; j < 22; j++) {
        twiceX2.a[j] <== x2.out[j]; twiceX2.b[j] <== x2.out[j];
    }
    component thriceX2 = KbAdd(p);
    for (var j = 0; j < 22; j++) {
        thriceX2.a[j] <== twiceX2.out[j]; thriceX2.b[j] <== x2.out[j];
    }
    signal tangentNumerator[22];
    if (p256 == 1) {
        component subtractThree = KbSub(p);
        for (var j = 0; j < 22; j++) {
            subtractThree.a[j] <== thriceX2.out[j];
            if (j == 0) subtractThree.b[j] <== 3;
            else subtractThree.b[j] <== 0;
        }
        for (var j = 0; j < 22; j++) tangentNumerator[j] <== subtractThree.out[j];
    } else {
        for (var j = 0; j < 22; j++) tangentNumerator[j] <== thriceX2.out[j];
    }
    signal selectedNumerator[22];
    signal selectedDenominator[22];
    signal numerator1[22];
    signal denominator1[22];
    for (var j = 0; j < 22; j++) {
        selectedNumerator[j] <== chordY.out[j]+tangent*(tangentNumerator[j]-chordY.out[j]);
        selectedDenominator[j] <== chordX.out[j]+tangent*(twiceY.out[j]-chordX.out[j]);
        numerator1[j] <== active*selectedNumerator[j];
        if (j == 0) denominator1[j] <== 1+active*(selectedDenominator[j]-1);
        else denominator1[j] <== active*selectedDenominator[j];
    }
    var slope1[100] = kb_divide(numerator1, denominator1, p);
    signal l1[22];
    component slope1Range = KbCanonical(p);
    component slope1Check = KbMul(p);
    component slope1Square = KbMul(p);
    for (var j = 0; j < 22; j++) {
        l1[j] <-- slope1[j];
        slope1Range.in[j] <== l1[j];
        slope1Check.a[j] <== l1[j]; slope1Check.b[j] <== denominator1[j];
        slope1Square.a[j] <== l1[j]; slope1Square.b[j] <== l1[j];
    }
    for (var j = 0; j < 22; j++) slope1Check.out[j] === numerator1[j];
    component minusAx = KbSub(p);
    for (var j = 0; j < 22; j++) {
        minusAx.a[j] <== slope1Square.out[j]; minusAx.b[j] <== aa[0][j];
    }
    component sX = KbSub(p);
    for (var j = 0; j < 22; j++) {
        sX.a[j] <== minusAx.out[j]; sX.b[j] <== bb[0][j];
    }
    signal xS[22];
    component secondEqX = BigIsEqual(22);
    component delta = KbSub(p);
    for (var j = 0; j < 22; j++) {
        xS[j] <== g[0][j]+active*(sX.out[j]-g[0][j]);
        secondEqX.in[0][j] <== xS[j]; secondEqX.in[1][j] <== aa[0][j];
        delta.a[j] <== xS[j]; delta.b[j] <== aa[0][j];
    }
    signal noBInf;
    signal ordinary2;
    signal zeroOut;
    signal finite2;
    noBInf <== (1-bInf)*active;
    ordinary2 <== noBInf*(1-secondEqX.out);
    zeroOut <== noBInf*secondEqX.out;
    finite2 <== ordinary2+bInf;
    var slope2[100] = kb_fused_second_slope(l1, twiceY.out, delta.out, p, ordinary2, bInf);
    signal l2[22];
    component slope2Range = KbCanonical(p);
    for (var j = 0; j < 22; j++) {
        l2[j] <-- slope2[j];
        slope2Range.in[j] <== l2[j];
        (1-finite2)*l2[j] === 0;
        bInf*(l2[j]-l1[j]) === 0;
    }
    component slopeSum = KbAdd(p);
    component negativeTwiceY = KbSub(p);
    for (var j = 0; j < 22; j++) {
        slopeSum.a[j] <== l1[j]; slopeSum.b[j] <== l2[j];
        negativeTwiceY.a[j] <== 0; negativeTwiceY.b[j] <== twiceY.out[j];
    }
    component slope2Check = KbMul(p);
    component slope2Square = KbMul(p);
    for (var j = 0; j < 22; j++) {
        slope2Check.a[j] <== slopeSum.out[j]; slope2Check.b[j] <== delta.out[j];
        slope2Square.a[j] <== l2[j]; slope2Square.b[j] <== l2[j];
    }
    for (var j = 0; j < 22; j++) ordinary2*(slope2Check.out[j]-negativeTwiceY.out[j]) === 0;
    component outputMinusAx = KbSub(p);
    for (var j = 0; j < 22; j++) {
        outputMinusAx.a[j] <== slope2Square.out[j]; outputMinusAx.b[j] <== aa[0][j];
    }
    signal effectiveSx[22];
    component outputX = KbSub(p);
    for (var j = 0; j < 22; j++) {
        effectiveSx[j] <== xS[j]+bInf*(aa[0][j]-xS[j]);
        outputX.a[j] <== outputMinusAx.out[j]; outputX.b[j] <== effectiveSx[j];
    }
    component outputDelta = KbSub(p);
    for (var j = 0; j < 22; j++) {
        outputDelta.a[j] <== aa[0][j]; outputDelta.b[j] <== outputX.out[j];
    }
    component outputLine = KbMul(p);
    for (var j = 0; j < 22; j++) {
        outputLine.a[j] <== l2[j]; outputLine.b[j] <== outputDelta.out[j];
    }
    component outputY = KbSub(p);
    for (var j = 0; j < 22; j++) {
        outputY.a[j] <== outputLine.out[j]; outputY.b[j] <== aa[1][j];
    }
    signal finiteCandidate[2][22];
    signal candidate[2][22];
    for (var j = 0; j < 22; j++) {
        finiteCandidate[0][j] <== g[0][j]+finite2*(outputX.out[j]-g[0][j]);
        finiteCandidate[1][j] <== g[1][j]+finite2*(outputY.out[j]-g[1][j]);
        for (var c = 0; c < 2; c++) {
            candidate[c][j] <== finiteCandidate[c][j]+cancel*(aa[c][j]-finiteCandidate[c][j]);
            out[c][j] <== candidate[c][j]+aInf*(b[c][j]-candidate[c][j]);
        }
    }
    outInf <== zeroOut+aInf*(bInf-zeroOut);
}

// Select the combined five-equation implementation for secp256k1.
template KbPointDoubleAdd(p256) {
    signal input a[2][22];
    signal input b[2][22];
    signal input aInf;
    signal input bInf;
    signal output out[2][22];
    signal output outInf;
    if (p256 == 0) {
        component k1Fused = KbK1DoubleAdd();
        k1Fused.aInf <== aInf; k1Fused.bInf <== bInf;
        for (var c = 0; c < 2; c++) {
            for (var j = 0; j < 22; j++) {
                k1Fused.a[c][j] <== a[c][j]; k1Fused.b[c][j] <== b[c][j];
            }
        }
        outInf <== k1Fused.outInf;
        for (var c = 0; c < 2; c++) {
            for (var j = 0; j < 22; j++) out[c][j] <== k1Fused.out[c][j];
        }
    }
    else {
        component p256Fused = KbPointDoubleAddReduced(p256);
        p256Fused.aInf <== aInf; p256Fused.bInf <== bInf;
        for (var c = 0; c < 2; c++) {
            for (var j = 0; j < 22; j++) {
                p256Fused.a[c][j] <== a[c][j]; p256Fused.b[c][j] <== b[c][j];
            }
        }
        outInf <== p256Fused.outInf;
        for (var c = 0; c < 2; c++) {
            for (var j = 0; j < 22; j++) out[c][j] <== p256Fused.out[c][j];
        }
    }
}

// Complete 4*a+b. P-256 uses the combined modular equations with an
// unreduced first-doubling y; secp256k1 uses a doubling and fused 2*a+b.
template KbPointQuadAdd(p256) {
    signal input a[2][22];
    signal input b[2][22];
    signal input aInf;
    signal input bInf;
    signal output out[2][22];
    signal output outInf;
    if (p256 == 1) {
        component quad = KbP256QuadAdd();
        quad.aInf <== aInf; quad.bInf <== bInf;
        for (var c = 0; c < 2; c++) {
            for (var j = 0; j < 22; j++) {
                quad.a[c][j] <== a[c][j]; quad.b[c][j] <== b[c][j];
            }
        }
        outInf <== quad.outInf;
        for (var c = 0; c < 2; c++) {
            for (var j = 0; j < 22; j++) out[c][j] <== quad.out[c][j];
        }
    } else {
        component twice = KbPointDouble(p256);
        component fused = KbPointDoubleAdd(p256);
        twice.inInf <== aInf;
        fused.bInf <== bInf;
        for (var c = 0; c < 2; c++) {
            for (var j = 0; j < 22; j++) {
                twice.in[c][j] <== a[c][j];
                fused.b[c][j] <== b[c][j];
            }
        }
        fused.aInf <== twice.outInf;
        for (var c = 0; c < 2; c++) {
            for (var j = 0; j < 22; j++) fused.a[c][j] <== twice.out[c][j];
        }
        outInf <== fused.outInf;
        for (var c = 0; c < 2; c++) {
            for (var j = 0; j < 22; j++) out[c][j] <== fused.out[c][j];
        }
    }
}
