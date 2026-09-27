pragma circom 2.0.2;

/*
    Point operations on secp256r1 (P-256), y^2 = x^3 - 3x + b, on points of
    eight 32-bit limbs per coordinate. P256AddUnequal and P256PointOnCurve keep
    the constraint shapes of the circom-ecdsa secp256k1 templates; P256Double
    and P256QuadAddStrict witness their slopes and use quadratic checks only.
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

/*
    4*r + b in one step. It replaces two doublings and an addition.

    The doubling d = 2*r is given by its tangent slope lambda0 and its x
    coordinate xD. The y of d enters the rest only linearly, so it is never
    witnessed or range-checked; wherever it appears it is replaced by its
    expression through the tangent,

        yD = lambda0 * (xR - xD) - yR.

    2*d + b is then computed as (d + b) + d, without the y of d + b
    (Eisentraeger, Lauter and Montgomery). Following the public descriptions
    of rot256's (Mathias Hall-Andersen) zk.golf secp256k1 submissions
    ("ELM fused 2R+T", "intermediate y never materialised") and
    patchgravity's, which recover the y coordinate from adjacent slopes; no
    code was copied.

    With (xR, yR) = r, (x2, y2) = b and (x4, y4) = out, the slopes lambda0,
    lambda1, lambda2 and the x coordinates xD = x(d) and x3 = x(d + b) are
    witnessed, and seven quadratic checks hold mod p:

        (D1) 2 * yR * lambda0 == 3 * xR^2 - 3
        (D2) xD == lambda0^2 - 2 * xR
        (1)  lambda1 * (x2 - xD) == y2 - yD
        (2)  x3 == lambda1^2 - xD - x2
        (3)  (lambda1 + lambda2) * (x3 - xD) == -2 * yD
        (4)  x4 == lambda2^2 - xD - x3
        (5)  y4 == lambda2 * (xD - x4) - yD

    r must be on the curve. P-256 has prime order, so no finite point has
    y == 0. yR != 0, so (D1) fixes lambda0 and (D2) fixes xD, which makes yD
    the y of d. xD != x2 is checked, as in P256AddStrict, so (1) fixes
    lambda1 and (2) fixes x3. If x3 == xD, (3) demands yD == 0, so there is
    no witness; otherwise (3) fixes lambda2, and (4) and (5) fix the output.
    xD is kept canonical for that guard; b must be canonical.

    The output is fixed mod p but only range-checked to 32-bit limbs, not
    kept canonical: r enters only the checks mod p, never a guard, so a next
    step reads either representative the same way. A caller that compares the
    output limb by limb against a canonical constant pins the value anyway.

    A product register sums at most eight products of 32-bit limbs, so it is
    at most 8 * (2^32 - 1)^2 = 2^67 - 2^36 + 8. The widest side, in (3), sums
    four products and two 32-bit limbs, at most 2^69 - 2^38 + 2^33 + 30; every
    other side sums less, so every register stays below 2^69.
*/
template P256QuadAddStrict() {
    signal input a[2][8];
    signal input b[2][8];
    signal output out[2][8];

    var xR[8];
    var yR[8];
    var x2[8];
    var y2[8];
    for (var i = 0; i < 8; i++) {
        xR[i] = a[0][i];
        yR[i] = a[1][i];
        x2[i] = b[0][i];
        y2[i] = b[1][i];
    }

    var dbl[3][100] = p256_double_slope_func(32, 8, xR, yR);
    var xDv[8];
    var yDv[8];
    for (var i = 0; i < 8; i++) {
        xDv[i] = dbl[1][i];
        yDv[i] = dbl[2][i];
    }
    var tmp[5][100] = p256_double_add_func(32, 8, xDv, yDv, x2, y2);

    signal l0[8];
    signal xD[8];
    signal l1[8];
    signal x3[8];
    signal l2[8];
    for (var i = 0; i < 8; i++) {
        l0[i] <-- dbl[0][i];
        xD[i] <-- dbl[1][i];
        l1[i] <-- tmp[0][i];
        x3[i] <-- tmp[1][i];
        l2[i] <-- tmp[2][i];
        out[0][i] <-- tmp[3][i];
        out[1][i] <-- tmp[4][i];
    }

    // xD is canonical for the distinct-x guard; the other values, the output
    // included, only need 32-bit limbs for the register bounds.
    component xDRange = CheckInRangeP256();
    for (var i = 0; i < 8; i++) { xDRange.in[i] <== xD[i]; }
    component same = BigIsEqual(8);
    for (var j = 0; j < 8; j++) {
        same.in[0][j] <== xD[j];
        same.in[1][j] <== b[0][j];
    }
    same.out === 0;

    component l0Range[8];
    component l1Range[8];
    component x3Range[8];
    component l2Range[8];
    component x4Range[8];
    component y4Range[8];
    for (var i = 0; i < 8; i++) {
        l0Range[i] = Num2Bits(32);
        l0Range[i].in <== l0[i];
        l1Range[i] = Num2Bits(32);
        l1Range[i].in <== l1[i];
        x3Range[i] = Num2Bits(32);
        x3Range[i].in <== x3[i];
        l2Range[i] = Num2Bits(32);
        l2Range[i].in <== l2[i];
        x4Range[i] = Num2Bits(32);
        x4Range[i].in <== out[0][i];
        y4Range[i] = Num2Bits(32);
        y4Range[i].in <== out[1][i];
    }

    component l0yR = P256Mul();
    component xRsq = P256Mul();
    component l0sq = P256Mul();
    component l0xR = P256Mul();
    component l0xD = P256Mul();
    component l1x2 = P256Mul();
    component l1xD = P256Mul();
    component l1sq = P256Mul();
    component l1x3 = P256Mul();
    component l2x3 = P256Mul();
    component l2xD = P256Mul();
    component l2sq = P256Mul();
    component l2x4 = P256Mul();
    for (var i = 0; i < 8; i++) {
        l0yR.a[i] <== l0[i]; l0yR.b[i] <== a[1][i];
        xRsq.a[i] <== a[0][i]; xRsq.b[i] <== a[0][i];
        l0sq.a[i] <== l0[i]; l0sq.b[i] <== l0[i];
        l0xR.a[i] <== l0[i]; l0xR.b[i] <== a[0][i];
        l0xD.a[i] <== l0[i]; l0xD.b[i] <== xD[i];
        l1x2.a[i] <== l1[i]; l1x2.b[i] <== b[0][i];
        l1xD.a[i] <== l1[i]; l1xD.b[i] <== xD[i];
        l1sq.a[i] <== l1[i]; l1sq.b[i] <== l1[i];
        l1x3.a[i] <== l1[i]; l1x3.b[i] <== x3[i];
        l2x3.a[i] <== l2[i]; l2x3.b[i] <== x3[i];
        l2xD.a[i] <== l2[i]; l2xD.b[i] <== xD[i];
        l2sq.a[i] <== l2[i]; l2sq.b[i] <== l2[i];
        l2x4.a[i] <== l2[i]; l2x4.b[i] <== out[0][i];
    }

    // yD = l0xR - l0xD - yR, registerwise; yR only reaches the first 8 registers.
    component tangent = P256CheckQuadraticModPIsZero69();
    component chordD = P256CheckQuadraticModPIsZero69();
    component slope1 = P256CheckQuadraticModPIsZero69();
    component chord1 = P256CheckQuadraticModPIsZero69();
    component slope2 = P256CheckQuadraticModPIsZero69();
    component chord2 = P256CheckQuadraticModPIsZero69();
    component line2 = P256CheckQuadraticModPIsZero69();
    for (var i = 0; i < 15; i++) {
        if (i == 0) {
            tangent.in[i] <== 2 * l0yR.out[i] - 3 * xRsq.out[i] + 3;
        } else {
            tangent.in[i] <== 2 * l0yR.out[i] - 3 * xRsq.out[i];
        }
        if (i < 8) {
            chordD.in[i] <== l0sq.out[i] - 2 * a[0][i] - xD[i];
            // (1): lambda1 * (x2 - xD) - y2 + yD
            slope1.in[i] <== l1x2.out[i] - l1xD.out[i] - b[1][i] + l0xR.out[i] - l0xD.out[i] - a[1][i];
            chord1.in[i] <== l1sq.out[i] - xD[i] - b[0][i] - x3[i];
            // (3): (lambda1 + lambda2) * (x3 - xD) + 2 * yD
            slope2.in[i] <== l1x3.out[i] - l1xD.out[i] + l2x3.out[i] - l2xD.out[i]
                + 2 * l0xR.out[i] - 2 * l0xD.out[i] - 2 * a[1][i];
            chord2.in[i] <== l2sq.out[i] - xD[i] - x3[i] - out[0][i];
            // (5): lambda2 * (x4 - xD) + y4 + yD
            line2.in[i] <== l2x4.out[i] - l2xD.out[i] + out[1][i] + l0xR.out[i] - l0xD.out[i] - a[1][i];
        } else {
            chordD.in[i] <== l0sq.out[i];
            slope1.in[i] <== l1x2.out[i] - l1xD.out[i] + l0xR.out[i] - l0xD.out[i];
            chord1.in[i] <== l1sq.out[i];
            slope2.in[i] <== l1x3.out[i] - l1xD.out[i] + l2x3.out[i] - l2xD.out[i]
                + 2 * l0xR.out[i] - 2 * l0xD.out[i];
            chord2.in[i] <== l2sq.out[i];
            line2.in[i] <== l2x4.out[i] - l2xD.out[i] + l0xR.out[i] - l0xD.out[i];
        }
    }
}
