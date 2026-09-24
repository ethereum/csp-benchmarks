pragma circom 2.0.2;

/*
    Point operations on secp256r1 (P-256), y^2 = x^3 - 3x + b, in 64-bit
    limbs with k = 4. The constraint shapes are those of the circom-ecdsa
    secp256k1 templates; the curve enters through the reduction modulo p and
    through the a = -3 terms, which are linear and cost no constraints.
*/

include "../../circomlib/circuits/bitify.circom";
include "./bigint.circom";
include "./bigint_4x64_mult.circom";
include "./bigint_func.circom";
include "./p256_func.circom";
include "./p256_utils.circom";

// x1 + x2 + x3 - lambda^2 == 0 mod p for the chord through (x1, y1), (x2, y2),
// multiplied out:
// x1^3 + x2^3 - x1^2x2 - x1x2^2 + x2^2x3 + x1^2x3 - 2x1x2x3 - y2^2 + 2y1y2 - y1^2 == 0
// The chord does not involve a.
template P256AddUnequalCubicConstraint() {
    signal input x1[4];
    signal input y1[4];
    signal input x2[4];
    signal input y2[4];
    signal input x3[4];
    signal input y3[4];

    signal x13[10];
    component x13Comp = A3NoCarry();
    for (var i = 0; i < 4; i++) { x13Comp.a[i] <== x1[i]; }
    for (var i = 0; i < 10; i++) { x13[i] <== x13Comp.a3[i]; }

    signal x23[10];
    component x23Comp = A3NoCarry();
    for (var i = 0; i < 4; i++) { x23Comp.a[i] <== x2[i]; }
    for (var i = 0; i < 10; i++) { x23[i] <== x23Comp.a3[i]; }

    signal x12x2[10];
    component x12x2Comp = A2B1NoCarry();
    for (var i = 0; i < 4; i++) { x12x2Comp.a[i] <== x1[i]; }
    for (var i = 0; i < 4; i++) { x12x2Comp.b[i] <== x2[i]; }
    for (var i = 0; i < 10; i++) { x12x2[i] <== x12x2Comp.a2b1[i]; }

    signal x1x22[10];
    component x1x22Comp = A2B1NoCarry();
    for (var i = 0; i < 4; i++) { x1x22Comp.a[i] <== x2[i]; }
    for (var i = 0; i < 4; i++) { x1x22Comp.b[i] <== x1[i]; }
    for (var i = 0; i < 10; i++) { x1x22[i] <== x1x22Comp.a2b1[i]; }

    signal x22x3[10];
    component x22x3Comp = A2B1NoCarry();
    for (var i = 0; i < 4; i++) { x22x3Comp.a[i] <== x2[i]; }
    for (var i = 0; i < 4; i++) { x22x3Comp.b[i] <== x3[i]; }
    for (var i = 0; i < 10; i++) { x22x3[i] <== x22x3Comp.a2b1[i]; }

    signal x12x3[10];
    component x12x3Comp = A2B1NoCarry();
    for (var i = 0; i < 4; i++) { x12x3Comp.a[i] <== x1[i]; }
    for (var i = 0; i < 4; i++) { x12x3Comp.b[i] <== x3[i]; }
    for (var i = 0; i < 10; i++) { x12x3[i] <== x12x3Comp.a2b1[i]; }

    signal x1x2x3[10];
    component x1x2x3Comp = A1B1C1NoCarry();
    for (var i = 0; i < 4; i++) { x1x2x3Comp.a[i] <== x1[i]; }
    for (var i = 0; i < 4; i++) { x1x2x3Comp.b[i] <== x2[i]; }
    for (var i = 0; i < 4; i++) { x1x2x3Comp.c[i] <== x3[i]; }
    for (var i = 0; i < 10; i++) { x1x2x3[i] <== x1x2x3Comp.a1b1c1[i]; }

    signal y12[7];
    component y12Comp = A2NoCarry();
    for (var i = 0; i < 4; i++) { y12Comp.a[i] <== y1[i]; }
    for (var i = 0; i < 7; i++) { y12[i] <== y12Comp.a2[i]; }

    signal y22[7];
    component y22Comp = A2NoCarry();
    for (var i = 0; i < 4; i++) { y22Comp.a[i] <== y2[i]; }
    for (var i = 0; i < 7; i++) { y22[i] <== y22Comp.a2[i]; }

    signal y1y2[7];
    component y1y2Comp = BigMultNoCarry(64, 64, 64, 4, 4);
    for (var i = 0; i < 4; i++) { y1y2Comp.a[i] <== y1[i]; }
    for (var i = 0; i < 4; i++) { y1y2Comp.b[i] <== y2[i]; }
    for (var i = 0; i < 7; i++) { y1y2[i] <== y1y2Comp.out[i]; }

    component zeroCheck = P256CheckCubicModPIsZero(200);
    for (var i = 0; i < 10; i++) {
        if (i < 7) {
            zeroCheck.in[i] <== x13[i] + x23[i] - x12x2[i] - x1x22[i] + x22x3[i] + x12x3[i]
                - 2 * x1x2x3[i] - y12[i] + 2 * y1y2[i] - y22[i];
        } else {
            zeroCheck.in[i] <== x13[i] + x23[i] - x12x2[i] - x1x22[i] + x22x3[i] + x12x3[i]
                - 2 * x1x2x3[i];
        }
    }
}

// x3y2 + x2y3 + x2y1 - x3y1 - x1y2 - x1y3 == 0 mod p:
// (x1, y1), (x2, y2) and (x3, -y3) are collinear.
template P256PointOnLine() {
    signal input x1[4];
    signal input y1[4];
    signal input x2[4];
    signal input y2[4];
    signal input x3[4];
    signal input y3[4];

    signal x3y2[7];
    component x3y2Comp = BigMultNoCarry(64, 64, 64, 4, 4);
    for (var i = 0; i < 4; i++) { x3y2Comp.a[i] <== x3[i]; }
    for (var i = 0; i < 4; i++) { x3y2Comp.b[i] <== y2[i]; }
    for (var i = 0; i < 7; i++) { x3y2[i] <== x3y2Comp.out[i]; }

    signal x3y1[7];
    component x3y1Comp = BigMultNoCarry(64, 64, 64, 4, 4);
    for (var i = 0; i < 4; i++) { x3y1Comp.a[i] <== x3[i]; }
    for (var i = 0; i < 4; i++) { x3y1Comp.b[i] <== y1[i]; }
    for (var i = 0; i < 7; i++) { x3y1[i] <== x3y1Comp.out[i]; }

    signal x2y3[7];
    component x2y3Comp = BigMultNoCarry(64, 64, 64, 4, 4);
    for (var i = 0; i < 4; i++) { x2y3Comp.a[i] <== x2[i]; }
    for (var i = 0; i < 4; i++) { x2y3Comp.b[i] <== y3[i]; }
    for (var i = 0; i < 7; i++) { x2y3[i] <== x2y3Comp.out[i]; }

    signal x2y1[7];
    component x2y1Comp = BigMultNoCarry(64, 64, 64, 4, 4);
    for (var i = 0; i < 4; i++) { x2y1Comp.a[i] <== x2[i]; }
    for (var i = 0; i < 4; i++) { x2y1Comp.b[i] <== y1[i]; }
    for (var i = 0; i < 7; i++) { x2y1[i] <== x2y1Comp.out[i]; }

    signal x1y3[7];
    component x1y3Comp = BigMultNoCarry(64, 64, 64, 4, 4);
    for (var i = 0; i < 4; i++) { x1y3Comp.a[i] <== x1[i]; }
    for (var i = 0; i < 4; i++) { x1y3Comp.b[i] <== y3[i]; }
    for (var i = 0; i < 7; i++) { x1y3[i] <== x1y3Comp.out[i]; }

    signal x1y2[7];
    component x1y2Comp = BigMultNoCarry(64, 64, 64, 4, 4);
    for (var i = 0; i < 4; i++) { x1y2Comp.a[i] <== x1[i]; }
    for (var i = 0; i < 4; i++) { x1y2Comp.b[i] <== y2[i]; }
    for (var i = 0; i < 7; i++) { x1y2[i] <== x1y2Comp.out[i]; }

    component zeroCheck = P256CheckQuadraticModPIsZero(132);
    for (var i = 0; i < 7; i++) {
        zeroCheck.in[i] <== x3y2[i] + x2y3[i] + x2y1[i] - x3y1[i] - x1y2[i] - x1y3[i];
    }
}

// The tangent at (x1, y1) passes through (x3, -y3):
// 2*y1*(y1 + y3) == (3*x1^2 + a)*(x1 - x3), i.e. with a = -3
// 2y1^2 + 2y1y3 - 3x1^3 + 3x1^2x3 + 3x1 - 3x3 == 0 mod p
template P256PointOnTangent() {
    signal input x1[4];
    signal input y1[4];
    signal input x3[4];
    signal input y3[4];

    signal y12[7];
    component y12Comp = A2NoCarry();
    for (var i = 0; i < 4; i++) { y12Comp.a[i] <== y1[i]; }
    for (var i = 0; i < 7; i++) { y12[i] <== y12Comp.a2[i]; }

    signal y1y3[7];
    component y1y3Comp = BigMultNoCarry(64, 64, 64, 4, 4);
    for (var i = 0; i < 4; i++) { y1y3Comp.a[i] <== y1[i]; }
    for (var i = 0; i < 4; i++) { y1y3Comp.b[i] <== y3[i]; }
    for (var i = 0; i < 7; i++) { y1y3[i] <== y1y3Comp.out[i]; }

    signal x13[10];
    component x13Comp = A3NoCarry();
    for (var i = 0; i < 4; i++) { x13Comp.a[i] <== x1[i]; }
    for (var i = 0; i < 10; i++) { x13[i] <== x13Comp.a3[i]; }

    signal x12x3[10];
    component x12x3Comp = A2B1NoCarry();
    for (var i = 0; i < 4; i++) { x12x3Comp.a[i] <== x1[i]; }
    for (var i = 0; i < 4; i++) { x12x3Comp.b[i] <== x3[i]; }
    for (var i = 0; i < 10; i++) { x12x3[i] <== x12x3Comp.a2b1[i]; }

    component zeroCheck = P256CheckCubicModPIsZero(199);
    for (var i = 0; i < 10; i++) {
        if (i < 4) {
            zeroCheck.in[i] <== 2 * y12[i] + 2 * y1y3[i] - 3 * x13[i] + 3 * x12x3[i]
                + 3 * x1[i] - 3 * x3[i];
        } else if (i < 7) {
            zeroCheck.in[i] <== 2 * y12[i] + 2 * y1y3[i] - 3 * x13[i] + 3 * x12x3[i];
        } else {
            zeroCheck.in[i] <== -3 * x13[i] + 3 * x12x3[i];
        }
    }
}

// x^3 - 3x + b - y^2 == 0 mod p
template P256PointOnCurve() {
    signal input x[4];
    signal input y[4];

    signal x3[10];
    component x3Comp = A3NoCarry();
    for (var i = 0; i < 4; i++) { x3Comp.a[i] <== x[i]; }
    for (var i = 0; i < 10; i++) { x3[i] <== x3Comp.a3[i]; }

    signal y2[7];
    component y2Comp = A2NoCarry();
    for (var i = 0; i < 4; i++) { y2Comp.a[i] <== y[i]; }
    for (var i = 0; i < 7; i++) { y2[i] <== y2Comp.a2[i]; }

    var bl[100] = get_p256_b(64, 4);
    component zeroCheck = P256CheckCubicModPIsZero(197);
    for (var i = 0; i < 10; i++) {
        if (i < 4) {
            zeroCheck.in[i] <== x3[i] - y2[i] - 3 * x[i] + bl[i];
        } else if (i < 7) {
            zeroCheck.in[i] <== x3[i] - y2[i];
        } else {
            zeroCheck.in[i] <== x3[i];
        }
    }
}

// a + b for points with distinct x. The output is left unconstrained when the
// operands coincide; P256AddStrict closes that gap where it matters.
template P256AddUnequal(n, k) {
    assert(n == 64 && k == 4);

    signal input a[2][k];
    signal input b[2][k];
    signal output out[2][k];

    var x1[4];
    var y1[4];
    var x2[4];
    var y2[4];
    for (var i = 0; i < 4; i++) {
        x1[i] = a[0][i];
        y1[i] = a[1][i];
        x2[i] = b[0][i];
        y2[i] = b[1][i];
    }

    var tmp[2][100] = p256_addunequal_func(n, k, x1, y1, x2, y2);
    for (var i = 0; i < k; i++) {
        out[0][i] <-- tmp[0][i];
        out[1][i] <-- tmp[1][i];
    }

    component cubic = P256AddUnequalCubicConstraint();
    for (var i = 0; i < k; i++) {
        cubic.x1[i] <== a[0][i];
        cubic.y1[i] <== a[1][i];
        cubic.x2[i] <== b[0][i];
        cubic.y2[i] <== b[1][i];
        cubic.x3[i] <== out[0][i];
        cubic.y3[i] <== out[1][i];
    }

    component onLine = P256PointOnLine();
    for (var i = 0; i < k; i++) {
        onLine.x1[i] <== a[0][i];
        onLine.y1[i] <== a[1][i];
        onLine.x2[i] <== b[0][i];
        onLine.y2[i] <== b[1][i];
        onLine.x3[i] <== out[0][i];
        onLine.y3[i] <== out[1][i];
    }

    component xRange = CheckInRangeP256();
    component yRange = CheckInRangeP256();
    for (var i = 0; i < k; i++) {
        xRange.in[i] <== out[0][i];
        yRange.in[i] <== out[1][i];
    }
}

// 2 * in. P-256 has prime order, so no finite point has y == 0.
template P256Double(n, k) {
    assert(n == 64 && k == 4);

    signal input in[2][k];
    signal output out[2][k];

    var x1[4];
    var y1[4];
    for (var i = 0; i < 4; i++) {
        x1[i] = in[0][i];
        y1[i] = in[1][i];
    }

    var tmp[2][100] = p256_double_func(n, k, x1, y1);
    for (var i = 0; i < k; i++) {
        out[0][i] <-- tmp[0][i];
        out[1][i] <-- tmp[1][i];
    }

    component onTangent = P256PointOnTangent();
    for (var i = 0; i < k; i++) {
        onTangent.x1[i] <== in[0][i];
        onTangent.y1[i] <== in[1][i];
        onTangent.x3[i] <== out[0][i];
        onTangent.y3[i] <== out[1][i];
    }

    component onCurve = P256PointOnCurve();
    for (var i = 0; i < k; i++) {
        onCurve.x[i] <== out[0][i];
        onCurve.y[i] <== out[1][i];
    }

    component xRange = CheckInRangeP256();
    component yRange = CheckInRangeP256();
    for (var i = 0; i < k; i++) {
        xRange.in[i] <== out[0][i];
        yRange.in[i] <== out[1][i];
    }

    // The tangent meets the curve at in (twice) and at -out; x3 != x1 picks
    // the latter.
    component sameX = BigIsEqual(4);
    for (var i = 0; i < k; i++) {
        sameX.in[0][i] <== out[0][i];
        sameX.in[1][i] <== in[0][i];
    }
    sameX.out === 0;
}

/*
    P256AddUnequal with its precondition checked rather than assumed.

    When the operands coincide, the chord and collinearity constraints both
    reduce to 0 == 0 and the output is free. Inside a loop over adversarial
    points that is a forgery, not incompleteness: an adversary drives one
    step into that state and then walks the accumulator to the expected
    constant. Distinct x pins the slope. An honest prover meets equal x with
    negligible probability.
*/
template P256AddStrict() {
    signal input a[2][4];
    signal input b[2][4];
    signal output out[2][4];

    component same = BigIsEqual(4);
    for (var j = 0; j < 4; j++) {
        same.in[0][j] <== a[0][j];
        same.in[1][j] <== b[0][j];
    }
    same.out === 0;

    component add = P256AddUnequal(64, 4);
    for (var c = 0; c < 2; c++) {
        for (var j = 0; j < 4; j++) {
            add.a[c][j] <== a[c][j];
            add.b[c][j] <== b[c][j];
        }
    }
    for (var c = 0; c < 2; c++) {
        for (var j = 0; j < 4; j++) {
            out[c][j] <== add.out[c][j];
        }
    }
}
