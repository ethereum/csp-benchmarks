pragma circom 2.2.0;

include "../nonnative/modular.circom";
include "constants.circom";

template KbPointOnCurve(p256) {
    var p[22] = ecdsa_prime(p256);
    var b[22] = ecdsa_b(p256);
    signal input in[2][22];
    component x2 = KbMul(p);
    component y2 = KbMul(p);
    for (var i = 0; i < 22; i++) {
        x2.a[i] <== in[0][i]; x2.b[i] <== in[0][i];
        y2.a[i] <== in[1][i]; y2.b[i] <== in[1][i];
    }
    component x3 = KbMul(p);
    for (var i = 0; i < 22; i++) {
        x3.a[i] <== x2.out[i]; x3.b[i] <== in[0][i];
    }
    signal rhs[22];
    if (p256 == 1) {
        component twiceX = KbAdd(p);
        for (var i = 0; i < 22; i++) {
            twiceX.a[i] <== in[0][i]; twiceX.b[i] <== in[0][i];
        }
        component thriceX = KbAdd(p);
        for (var i = 0; i < 22; i++) {
            thriceX.a[i] <== twiceX.out[i]; thriceX.b[i] <== in[0][i];
        }
        component ax = KbSub(p);
        for (var i = 0; i < 22; i++) {
            ax.a[i] <== x3.out[i]; ax.b[i] <== thriceX.out[i];
        }
        for (var i = 0; i < 22; i++) rhs[i] <== ax.out[i];
    } else {
        for (var i = 0; i < 22; i++) rhs[i] <== x3.out[i];
    }
    component addB = KbAdd(p);
    for (var i = 0; i < 22; i++) {
        addB.a[i] <== rhs[i]; addB.b[i] <== b[i];
    }
    for (var i = 0; i < 22; i++) y2.out[i] === addB.out[i];
}

// Add canonical finite curve points supplied by the caller. The x-coordinate
// inequality is constrained, so the chord denominator is nonzero. Equal and
// inverse points must use the complete addition component instead.
template KbPointAddUnequal(p256) {
    var p[22] = ecdsa_prime(p256);
    signal input a[2][22];
    signal input b[2][22];
    signal output out[2][22];
    component equalX = BigIsEqual(22);
    component chordX = KbSub(p);
    component chordY = KbSub(p);
    for (var i = 0; i < 22; i++) {
        equalX.in[0][i] <== a[0][i]; equalX.in[1][i] <== b[0][i];
        chordX.a[i] <== b[0][i]; chordX.b[i] <== a[0][i];
        chordY.a[i] <== b[1][i]; chordY.b[i] <== a[1][i];
    }
    equalX.out === 0;

    signal lambda[22];
    var slope[100] = kb_divide(chordY.out, chordX.out, p);
    component lambdaCanonical = KbCanonical(p);
    component slopeCheck = KbMul(p);
    component lambda2 = KbMul(p);
    for (var i = 0; i < 22; i++) {
        lambda[i] <-- slope[i];
        lambdaCanonical.in[i] <== lambda[i];
        slopeCheck.a[i] <== lambda[i]; slopeCheck.b[i] <== chordX.out[i];
        lambda2.a[i] <== lambda[i]; lambda2.b[i] <== lambda[i];
    }
    for (var i = 0; i < 22; i++) slopeCheck.out[i] === chordY.out[i];

    component minusX1 = KbSub(p);
    for (var i = 0; i < 22; i++) {
        minusX1.a[i] <== lambda2.out[i]; minusX1.b[i] <== a[0][i];
    }
    component x3 = KbSub(p);
    for (var i = 0; i < 22; i++) {
        x3.a[i] <== minusX1.out[i]; x3.b[i] <== b[0][i];
    }
    component deltaX = KbSub(p);
    for (var i = 0; i < 22; i++) {
        deltaX.a[i] <== a[0][i]; deltaX.b[i] <== x3.out[i];
    }
    component lambdaDeltaX = KbMul(p);
    for (var i = 0; i < 22; i++) {
        lambdaDeltaX.a[i] <== lambda[i]; lambdaDeltaX.b[i] <== deltaX.out[i];
    }
    component y3 = KbSub(p);
    for (var i = 0; i < 22; i++) {
        y3.a[i] <== lambdaDeltaX.out[i]; y3.b[i] <== a[1][i];
    }
    for (var i = 0; i < 22; i++) {
        out[0][i] <== x3.out[i]; out[1][i] <== y3.out[i];
    }
}

// Finite coordinates are canonical curve points. Infinity uses the generator
// coordinates with an explicit flag. Active additions use a nonzero chord or
// tangent denominator; inactive arithmetic uses denominator one and slope zero.
template KbPointAddCore(p256, knownDouble) {
    var p[22] = ecdsa_prime(p256);
    var g[2][22] = ecdsa_generator(p256);
    signal input a[2][22];
    signal input b[2][22];
    signal input aInf;
    signal input bInf;
    signal output out[2][22];
    signal output outInf;
    aInf * (aInf - 1) === 0;
    bInf * (bInf - 1) === 0;

    signal doubling;
    signal inverse;
    signal finite;
    signal active;
    signal chordXOut[22];
    signal chordYOut[22];
    if (knownDouble == 1) {
        doubling <== 1;
        inverse <== 0;
        for (var i = 0; i < 22; i++) {
            chordXOut[i] <== 0; chordYOut[i] <== 0;
        }
    } else {
        component eqX = BigIsEqual(22);
        component eqY = BigIsEqual(22);
        component chordX = KbSub(p);
        component chordY = KbSub(p);
        for (var i = 0; i < 22; i++) {
            eqX.in[0][i] <== a[0][i]; eqX.in[1][i] <== b[0][i];
            eqY.in[0][i] <== a[1][i]; eqY.in[1][i] <== b[1][i];
            chordX.a[i] <== b[0][i]; chordX.b[i] <== a[0][i];
            chordY.a[i] <== b[1][i]; chordY.b[i] <== a[1][i];
        }
        doubling <== eqX.out * eqY.out;
        inverse <== eqX.out * (1 - eqY.out);
        for (var i = 0; i < 22; i++) {
            chordXOut[i] <== chordX.out[i]; chordYOut[i] <== chordY.out[i];
        }
    }
    finite <== (1 - aInf) * (1 - bInf);
    active <== finite * (1 - inverse);

    component twiceY = KbAdd(p);
    component x2 = KbMul(p);
    for (var i = 0; i < 22; i++) {
        twiceY.a[i] <== a[1][i]; twiceY.b[i] <== a[1][i];
        x2.a[i] <== a[0][i]; x2.b[i] <== a[0][i];
    }
    component twiceX2 = KbAdd(p);
    for (var i = 0; i < 22; i++) {
        twiceX2.a[i] <== x2.out[i]; twiceX2.b[i] <== x2.out[i];
    }
    component thriceX2 = KbAdd(p);
    for (var i = 0; i < 22; i++) {
        thriceX2.a[i] <== twiceX2.out[i]; thriceX2.b[i] <== x2.out[i];
    }
    signal tangent[22];
    if (p256 == 1) {
        component minusThree = KbSub(p);
        for (var i = 0; i < 22; i++) {
            minusThree.a[i] <== thriceX2.out[i];
            if (i == 0) minusThree.b[i] <== 3;
            else minusThree.b[i] <== 0;
        }
        for (var i = 0; i < 22; i++) tangent[i] <== minusThree.out[i];
    } else {
        for (var i = 0; i < 22; i++) tangent[i] <== thriceX2.out[i];
    }
    signal denominator[22];
    signal numerator[22];
    signal selectedDenominator[22];
    signal selectedNumerator[22];
    for (var i = 0; i < 22; i++) {
        selectedDenominator[i] <== chordXOut[i] + doubling * (twiceY.out[i] - chordXOut[i]);
        selectedNumerator[i] <== chordYOut[i] + doubling * (tangent[i] - chordYOut[i]);
        if (i == 0) denominator[i] <== 1 + active * (selectedDenominator[i] - 1);
        else denominator[i] <== active * selectedDenominator[i];
        numerator[i] <== active * selectedNumerator[i];
    }

    signal lambda[22];
    var slope[100] = kb_divide(numerator, denominator, p);
    for (var i = 0; i < 22; i++) lambda[i] <-- slope[i];
    component lambdaCanonical = KbCanonical(p);
    component slopeCheck = KbMul(p);
    component lambda2 = KbMul(p);
    for (var i = 0; i < 22; i++) {
        lambdaCanonical.in[i] <== lambda[i];
        slopeCheck.a[i] <== lambda[i]; slopeCheck.b[i] <== denominator[i];
        lambda2.a[i] <== lambda[i]; lambda2.b[i] <== lambda[i];
    }
    for (var i = 0; i < 22; i++) slopeCheck.out[i] === numerator[i];

    component minusX1 = KbSub(p);
    for (var i = 0; i < 22; i++) {
        minusX1.a[i] <== lambda2.out[i]; minusX1.b[i] <== a[0][i];
    }
    component x3 = KbSub(p);
    for (var i = 0; i < 22; i++) {
        x3.a[i] <== minusX1.out[i]; x3.b[i] <== b[0][i];
    }
    component deltaX = KbSub(p);
    for (var i = 0; i < 22; i++) {
        deltaX.a[i] <== a[0][i]; deltaX.b[i] <== x3.out[i];
    }
    component lambdaDeltaX = KbMul(p);
    for (var i = 0; i < 22; i++) {
        lambdaDeltaX.a[i] <== lambda[i]; lambdaDeltaX.b[i] <== deltaX.out[i];
    }
    component y3 = KbSub(p);
    for (var i = 0; i < 22; i++) {
        y3.a[i] <== lambdaDeltaX.out[i]; y3.b[i] <== a[1][i];
    }

    signal bothInf;
    signal inverseInf;
    bothInf <== aInf * bInf;
    inverseInf <== finite * inverse;
    outInf <== bothInf + inverseInf;
    signal candidate[2][22];
    signal leftSelected[2][22];
    for (var i = 0; i < 22; i++) {
        candidate[0][i] <== g[0][i] + active * (x3.out[i] - g[0][i]);
        candidate[1][i] <== g[1][i] + active * (y3.out[i] - g[1][i]);
        for (var c = 0; c < 2; c++) {
            leftSelected[c][i] <== candidate[c][i] + aInf * (b[c][i] - candidate[c][i]);
            out[c][i] <== leftSelected[c][i] + bInf * (a[c][i] - leftSelected[c][i]);
        }
    }
}

template KbPointAdd(p256) {
    signal input a[2][22];
    signal input b[2][22];
    signal input aInf;
    signal input bInf;
    signal output out[2][22];
    signal output outInf;
    component add = KbPointAddCore(p256, 0);
    add.aInf <== aInf; add.bInf <== bInf;
    for (var c = 0; c < 2; c++) {
        for (var i = 0; i < 22; i++) {
            add.a[c][i] <== a[c][i]; add.b[c][i] <== b[c][i];
        }
    }
    outInf <== add.outInf;
    for (var c = 0; c < 2; c++) {
        for (var i = 0; i < 22; i++) out[c][i] <== add.out[c][i];
    }
}

template KbPointDouble(p256) {
    signal input in[2][22];
    signal input inInf;
    signal output out[2][22];
    signal output outInf;
    component add = KbPointAddCore(p256, 1);
    add.aInf <== inInf; add.bInf <== inInf;
    for (var c = 0; c < 2; c++) {
        for (var i = 0; i < 22; i++) {
            add.a[c][i] <== in[c][i]; add.b[c][i] <== in[c][i];
        }
    }
    outInf <== add.outInf;
    for (var c = 0; c < 2; c++) {
        for (var i = 0; i < 22; i++) out[c][i] <== add.out[c][i];
    }
}
