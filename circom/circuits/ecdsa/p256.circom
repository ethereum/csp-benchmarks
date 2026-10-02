pragma circom 2.0.2;

/*
    Point operations on secp256r1 (P-256), y^2 = x^3 - 3x + b, on points of
    eight 32-bit limbs per coordinate. P256AddUnequal and P256PointOnCurve keep
    the constraint shapes of the circom-ecdsa secp256k1 templates; P256Double
    witnesses its tangent slope and uses quadratic checks only. Complete
    flagged group operations are defined in p256_complete.circom.
    The curve enters through the reduction modulo p and through the a = -3
    terms, which are linear and cost no constraints.

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

// a + b for finite points with distinct x. The caller must enforce that
// precondition; equal points leave the chord and line equations unconstrained.
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

/*
    2 * in, with the tangent slope witnessed. Three quadratic checks hold mod p:

        (1) 2 * y1 * lambda == 3 * x1^2 - 3
        (2) x3 == lambda^2 - 2 * x1
        (3) y3 == lambda * (x1 - x3) - y1

    in must be on the curve. P-256 has prime order, so no finite point has
    y1 == 0: (1) fixes lambda, and (2) and (3) fix the output. Eliminating
    lambda instead gives a cubic check that the tangent's second intersection
    also satisfies, which needs an on-curve check and x3 != x1 on the output;
    the witnessed slope needs neither.

    In (1), 2 * lambda * y1 stays below 2^68 and 3 * x1^2 below 3 * 2^67, so
    every register stays below 2^69.
*/
template P256Double() {
    signal input in[2][8];
    signal output out[2][8];

    var x1[8];
    var y1[8];
    for (var i = 0; i < 8; i++) {
        x1[i] = in[0][i];
        y1[i] = in[1][i];
    }

    var tmp[3][100] = p256_double_slope_func(32, 8, x1, y1);
    signal lambda[8];
    for (var i = 0; i < 8; i++) {
        lambda[i] <-- tmp[0][i];
        out[0][i] <-- tmp[1][i];
        out[1][i] <-- tmp[2][i];
    }

    component lambdaRange[8];
    for (var i = 0; i < 8; i++) {
        lambdaRange[i] = Num2Bits(32);
        lambdaRange[i].in <== lambda[i];
    }
    component xRange = CheckInRangeP256();
    component yRange = CheckInRangeP256();
    for (var i = 0; i < 8; i++) {
        xRange.in[i] <== out[0][i];
        yRange.in[i] <== out[1][i];
    }

    component ly1 = P256Mul();
    component x1sq = P256Mul();
    component lsq = P256Mul();
    component lx1 = P256Mul();
    component lx3 = P256Mul();
    for (var i = 0; i < 8; i++) {
        ly1.a[i] <== lambda[i]; ly1.b[i] <== in[1][i];
        x1sq.a[i] <== in[0][i]; x1sq.b[i] <== in[0][i];
        lsq.a[i] <== lambda[i]; lsq.b[i] <== lambda[i];
        lx1.a[i] <== lambda[i]; lx1.b[i] <== in[0][i];
        lx3.a[i] <== lambda[i]; lx3.b[i] <== out[0][i];
    }

    component tangent = P256CheckQuadraticModPIsZero69();
    component chord = P256CheckQuadraticModPIsZero69();
    component line = P256CheckQuadraticModPIsZero69();
    for (var i = 0; i < 15; i++) {
        if (i == 0) {
            tangent.in[i] <== 2 * ly1.out[i] - 3 * x1sq.out[i] + 3;
        } else {
            tangent.in[i] <== 2 * ly1.out[i] - 3 * x1sq.out[i];
        }
        if (i < 8) {
            chord.in[i] <== lsq.out[i] - 2 * in[0][i] - out[0][i];
            line.in[i] <== lx3.out[i] - lx1.out[i] + out[1][i] + in[1][i];
        } else {
            chord.in[i] <== lsq.out[i];
            line.in[i] <== lx3.out[i] - lx1.out[i];
        }
    }
}
