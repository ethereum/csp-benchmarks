pragma circom 2.0.2;

/*
    Point operations on secp256r1 (P-256), y^2 = x^3 - 3x + b, on points of
    eight 32-bit limbs per coordinate. The constraint shapes are those of the
    circom-ecdsa secp256k1 templates; the curve enters through the reduction
    modulo p and through the a = -3 terms, which are linear and cost no
    constraints.

    Products go through P256MultNoCarry: 8 x 8 limbs give 15 registers below
    2^67, and a further factor gives 22. Squares and x1 * x2 are computed once
    and reused across the terms that share them.
*/

include "../../circomlib/circuits/bitify.circom";
include "./bigint.circom";
include "./bigint_func.circom";
include "./p256_func.circom";
include "./p256_utils.circom";

// a * b: 8 x 8 registers -> 15, each below 2^67
template P256Mul() {
    signal input a[8];
    signal input b[8];
    signal output out[15];
    component m = P256MultNoCarry(32, 32, 8, 8);
    for (var i = 0; i < 8; i++) { m.a[i] <== a[i]; m.b[i] <== b[i]; }
    for (var i = 0; i < 15; i++) { out[i] <== m.out[i]; }
}

// (15 registers below 2^67) * (8 registers) -> 22
template P256Mul3() {
    signal input a[15];
    signal input b[8];
    signal output out[22];
    component m = P256MultNoCarry(67, 32, 15, 8);
    for (var i = 0; i < 15; i++) { m.a[i] <== a[i]; }
    for (var i = 0; i < 8; i++) { m.b[i] <== b[i]; }
    for (var i = 0; i < 22; i++) { out[i] <== m.out[i]; }
}

// x1 + x2 + x3 - lambda^2 == 0 mod p for the chord through (x1, y1), (x2, y2),
// multiplied out:
// x1^3 + x2^3 - x1^2x2 - x1x2^2 + x2^2x3 + x1^2x3 - 2x1x2x3 - y2^2 + 2y1y2 - y1^2 == 0
// The chord does not involve a. Each side of the sign stays below 4 * 48 * 2^96 < 2^104.
template P256AddUnequalCubicConstraint() {
    signal input x1[8];
    signal input y1[8];
    signal input x2[8];
    signal input y2[8];
    signal input x3[8];
    signal input y3[8];

    component x1sq = P256Mul();
    component x2sq = P256Mul();
    component y1sq = P256Mul();
    component y2sq = P256Mul();
    component y1y2 = P256Mul();
    component x1x2 = P256Mul();
    for (var i = 0; i < 8; i++) {
        x1sq.a[i] <== x1[i]; x1sq.b[i] <== x1[i];
        x2sq.a[i] <== x2[i]; x2sq.b[i] <== x2[i];
        y1sq.a[i] <== y1[i]; y1sq.b[i] <== y1[i];
        y2sq.a[i] <== y2[i]; y2sq.b[i] <== y2[i];
        y1y2.a[i] <== y1[i]; y1y2.b[i] <== y2[i];
        x1x2.a[i] <== x1[i]; x1x2.b[i] <== x2[i];
    }

    component x13 = P256Mul3();
    component x23 = P256Mul3();
    component x12x2 = P256Mul3();
    component x1x22 = P256Mul3();
    component x22x3 = P256Mul3();
    component x12x3 = P256Mul3();
    component x1x2x3 = P256Mul3();
    for (var i = 0; i < 15; i++) {
        x13.a[i] <== x1sq.out[i];
        x23.a[i] <== x2sq.out[i];
        x12x2.a[i] <== x1sq.out[i];
        x1x22.a[i] <== x2sq.out[i];
        x22x3.a[i] <== x2sq.out[i];
        x12x3.a[i] <== x1sq.out[i];
        x1x2x3.a[i] <== x1x2.out[i];
    }
    for (var i = 0; i < 8; i++) {
        x13.b[i] <== x1[i];
        x23.b[i] <== x2[i];
        x12x2.b[i] <== x2[i];
        x1x22.b[i] <== x1[i];
        x22x3.b[i] <== x3[i];
        x12x3.b[i] <== x3[i];
        x1x2x3.b[i] <== x3[i];
    }

    component zeroCheck = P256CheckCubicModPIsZero104();
    for (var i = 0; i < 22; i++) {
        if (i < 15) {
            zeroCheck.in[i] <== x13.out[i] + x23.out[i] - x12x2.out[i] - x1x22.out[i]
                + x22x3.out[i] + x12x3.out[i] - 2 * x1x2x3.out[i]
                - y1sq.out[i] + 2 * y1y2.out[i] - y2sq.out[i];
        } else {
            zeroCheck.in[i] <== x13.out[i] + x23.out[i] - x12x2.out[i] - x1x22.out[i]
                + x22x3.out[i] + x12x3.out[i] - 2 * x1x2x3.out[i];
        }
    }
}

// x3y2 + x2y3 + x2y1 - x3y1 - x1y2 - x1y3 == 0 mod p:
// (x1, y1), (x2, y2) and (x3, -y3) are collinear. Each side below 3 * 8 * 2^64 < 2^69.
template P256PointOnLine() {
    signal input x1[8];
    signal input y1[8];
    signal input x2[8];
    signal input y2[8];
    signal input x3[8];
    signal input y3[8];

    component x3y2 = P256Mul();
    component x3y1 = P256Mul();
    component x2y3 = P256Mul();
    component x2y1 = P256Mul();
    component x1y3 = P256Mul();
    component x1y2 = P256Mul();
    for (var i = 0; i < 8; i++) {
        x3y2.a[i] <== x3[i]; x3y2.b[i] <== y2[i];
        x3y1.a[i] <== x3[i]; x3y1.b[i] <== y1[i];
        x2y3.a[i] <== x2[i]; x2y3.b[i] <== y3[i];
        x2y1.a[i] <== x2[i]; x2y1.b[i] <== y1[i];
        x1y3.a[i] <== x1[i]; x1y3.b[i] <== y3[i];
        x1y2.a[i] <== x1[i]; x1y2.b[i] <== y2[i];
    }

    component zeroCheck = P256CheckQuadraticModPIsZero69();
    for (var i = 0; i < 15; i++) {
        zeroCheck.in[i] <== x3y2.out[i] + x2y3.out[i] + x2y1.out[i]
            - x3y1.out[i] - x1y2.out[i] - x1y3.out[i];
    }
}

// The tangent at (x1, y1) passes through (x3, -y3):
// 2*y1*(y1 + y3) == (3*x1^2 + a)*(x1 - x3), i.e. with a = -3
// 2y1^2 + 2y1y3 - 3x1^3 + 3x1^2x3 + 3x1 - 3x3 == 0 mod p
// Each side below 3 * 48 * 2^96 + 2^70 < 2^104.
template P256PointOnTangent() {
    signal input x1[8];
    signal input y1[8];
    signal input x3[8];
    signal input y3[8];

    component y12 = P256Mul();
    component y1y3 = P256Mul();
    component x1sq = P256Mul();
    for (var i = 0; i < 8; i++) {
        y12.a[i] <== y1[i]; y12.b[i] <== y1[i];
        y1y3.a[i] <== y1[i]; y1y3.b[i] <== y3[i];
        x1sq.a[i] <== x1[i]; x1sq.b[i] <== x1[i];
    }
    component x13 = P256Mul3();
    component x12x3 = P256Mul3();
    for (var i = 0; i < 15; i++) {
        x13.a[i] <== x1sq.out[i];
        x12x3.a[i] <== x1sq.out[i];
    }
    for (var i = 0; i < 8; i++) {
        x13.b[i] <== x1[i];
        x12x3.b[i] <== x3[i];
    }

    component zeroCheck = P256CheckCubicModPIsZero104();
    for (var i = 0; i < 22; i++) {
        if (i < 8) {
            zeroCheck.in[i] <== 2 * y12.out[i] + 2 * y1y3.out[i] - 3 * x13.out[i]
                + 3 * x12x3.out[i] + 3 * x1[i] - 3 * x3[i];
        } else if (i < 15) {
            zeroCheck.in[i] <== 2 * y12.out[i] + 2 * y1y3.out[i] - 3 * x13.out[i]
                + 3 * x12x3.out[i];
        } else {
            zeroCheck.in[i] <== -3 * x13.out[i] + 3 * x12x3.out[i];
        }
    }
}

// x^3 - 3x + b - y^2 == 0 mod p. Each side below 48 * 2^96 + 2^70 < 2^102.
template P256PointOnCurve() {
    signal input x[8];
    signal input y[8];

    component xsq = P256Mul();
    component ysq = P256Mul();
    for (var i = 0; i < 8; i++) {
        xsq.a[i] <== x[i]; xsq.b[i] <== x[i];
        ysq.a[i] <== y[i]; ysq.b[i] <== y[i];
    }
    component x3 = P256Mul3();
    for (var i = 0; i < 15; i++) { x3.a[i] <== xsq.out[i]; }
    for (var i = 0; i < 8; i++) { x3.b[i] <== x[i]; }

    var bl[100] = get_p256_b(32, 8);
    component zeroCheck = P256CheckCubicModPIsZero102();
    for (var i = 0; i < 22; i++) {
        if (i < 8) {
            zeroCheck.in[i] <== x3.out[i] - ysq.out[i] - 3 * x[i] + bl[i];
        } else if (i < 15) {
            zeroCheck.in[i] <== x3.out[i] - ysq.out[i];
        } else {
            zeroCheck.in[i] <== x3.out[i];
        }
    }
}

// a + b for points with distinct x. The output is left unconstrained when the
// operands coincide; P256AddStrict closes that gap where it matters.
template P256AddUnequal() {
    signal input a[2][8];
    signal input b[2][8];
    signal output out[2][8];

    var x1[8];
    var y1[8];
    var x2[8];
    var y2[8];
    for (var i = 0; i < 8; i++) {
        x1[i] = a[0][i];
        y1[i] = a[1][i];
        x2[i] = b[0][i];
        y2[i] = b[1][i];
    }

    var tmp[2][100] = p256_addunequal_func(32, 8, x1, y1, x2, y2);
    for (var i = 0; i < 8; i++) {
        out[0][i] <-- tmp[0][i];
        out[1][i] <-- tmp[1][i];
    }

    component cubic = P256AddUnequalCubicConstraint();
    component onLine = P256PointOnLine();
    for (var i = 0; i < 8; i++) {
        cubic.x1[i] <== a[0][i];
        cubic.y1[i] <== a[1][i];
        cubic.x2[i] <== b[0][i];
        cubic.y2[i] <== b[1][i];
        cubic.x3[i] <== out[0][i];
        cubic.y3[i] <== out[1][i];
        onLine.x1[i] <== a[0][i];
        onLine.y1[i] <== a[1][i];
        onLine.x2[i] <== b[0][i];
        onLine.y2[i] <== b[1][i];
        onLine.x3[i] <== out[0][i];
        onLine.y3[i] <== out[1][i];
    }

    component xRange = CheckInRangeP256();
    component yRange = CheckInRangeP256();
    for (var i = 0; i < 8; i++) {
        xRange.in[i] <== out[0][i];
        yRange.in[i] <== out[1][i];
    }
}

// 2 * in. P-256 has prime order, so no finite point has y == 0.
template P256Double() {
    signal input in[2][8];
    signal output out[2][8];

    var x1[8];
    var y1[8];
    for (var i = 0; i < 8; i++) {
        x1[i] = in[0][i];
        y1[i] = in[1][i];
    }

    var tmp[2][100] = p256_double_func(32, 8, x1, y1);
    for (var i = 0; i < 8; i++) {
        out[0][i] <-- tmp[0][i];
        out[1][i] <-- tmp[1][i];
    }

    component onTangent = P256PointOnTangent();
    component onCurve = P256PointOnCurve();
    for (var i = 0; i < 8; i++) {
        onTangent.x1[i] <== in[0][i];
        onTangent.y1[i] <== in[1][i];
        onTangent.x3[i] <== out[0][i];
        onTangent.y3[i] <== out[1][i];
        onCurve.x[i] <== out[0][i];
        onCurve.y[i] <== out[1][i];
    }

    component xRange = CheckInRangeP256();
    component yRange = CheckInRangeP256();
    for (var i = 0; i < 8; i++) {
        xRange.in[i] <== out[0][i];
        yRange.in[i] <== out[1][i];
    }

    // The tangent meets the curve at in (twice) and at -out; x3 != x1 picks
    // the latter.
    component sameX = BigIsEqual(8);
    for (var i = 0; i < 8; i++) {
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
    signal input a[2][8];
    signal input b[2][8];
    signal output out[2][8];

    component same = BigIsEqual(8);
    for (var j = 0; j < 8; j++) {
        same.in[0][j] <== a[0][j];
        same.in[1][j] <== b[0][j];
    }
    same.out === 0;

    component add = P256AddUnequal();
    for (var c = 0; c < 2; c++) {
        for (var j = 0; j < 8; j++) {
            add.a[c][j] <== a[c][j];
            add.b[c][j] <== b[c][j];
        }
    }
    for (var c = 0; c < 2; c++) {
        for (var j = 0; j < 8; j++) {
            out[c][j] <== add.out[c][j];
        }
    }
}
