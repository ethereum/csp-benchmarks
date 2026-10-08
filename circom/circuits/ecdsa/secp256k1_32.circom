pragma circom 2.0.2;

/*
    Point operations on secp256k1, y^2 = x^3 + 7, on points of eight 32-bit
    limbs per coordinate. The constraint shapes are those of the circom-ecdsa
    templates in secp256k1.circom (chord cubic, line, curve equation); only the
    limb size and the modular checks change. Secp256k1Double32 witnesses its
    tangent slope and uses quadratic checks only.

    Products go through P256Mul and P256Mul3, which do not depend on the curve:
    8 x 8 limbs give 15 registers below 2^67, and a further factor gives 22.
    Witness values are computed with the 64-bit circom-ecdsa functions and
    split into 32-bit limbs.
*/

include "./p256.circom";
include "./secp256k1_func.circom";
include "./secp256k1_utils32.circom";

// Eight 32-bit limbs to four 64-bit limbs, for the witness functions.
function secp256k1_join32(x) {
    var out[100];
    for (var i = 0; i < 100; i++) { out[i] = 0; }
    for (var i = 0; i < 4; i++) {
        out[i] = x[2 * i] + x[2 * i + 1] * (1 << 32);
    }
    return out;
}

// Returns [slope, x, y] of a+b, for distinct x (tangent = 0) or a = b
// (tangent = 1). Witness generation only.
function secp256k1_slope_add_func(n, k, x1, y1, x2, y2, tangent) {
    var p[100] = get_secp256k1_prime(n, k);
    var a[2][100];
    var b[2][100];
    for (var i = 0; i < 100; i++) {
        a[0][i] = 0; a[1][i] = 0; b[0][i] = 0; b[1][i] = 0;
    }
    for (var i = 0; i < k; i++) {
        a[0][i] = x1[i]; a[1][i] = y1[i]; b[0][i] = x2[i]; b[1][i] = y2[i];
    }
    var num[100];
    var den[100];
    if (tangent == 1) {
        var three[100];
        var two[100];
        for (var i = 0; i < 100; i++) {
            three[i] = i == 0 ? 3 : 0;
            two[i] = i == 0 ? 2 : 0;
        }
        var xsq[100] = prod_mod_p(n, k, a[0], a[0], p);
        num = prod_mod_p(n, k, xsq, three, p);
        den = prod_mod_p(n, k, a[1], two, p);
    } else {
        num = long_sub_mod_p(n, k, b[1], a[1], p);
        den = long_sub_mod_p(n, k, b[0], a[0], p);
    }
    var denInv[100] = mod_inv(n, k, den, p);
    var lambda[100] = prod_mod_p(n, k, num, denInv, p);
    var lsq[100] = prod_mod_p(n, k, lambda, lambda, p);
    var xPre[100] = long_sub_mod_p(n, k, lsq, a[0], p);
    var x3[100] = long_sub_mod_p(n, k, xPre, b[0], p);
    var dx[100] = long_sub_mod_p(n, k, a[0], x3, p);
    var ldx[100] = prod_mod_p(n, k, lambda, dx, p);
    var y3[100] = long_sub_mod_p(n, k, ldx, a[1], p);
    var out[3][100];
    for (var i = 0; i < 100; i++) {
        out[0][i] = lambda[i]; out[1][i] = x3[i]; out[2][i] = y3[i];
    }
    return out;
}

// x1 + x2 + x3 - lambda^2 == 0 mod p for the chord through (x1, y1), (x2, y2),
// multiplied out:
// x1^3 + x2^3 - x1^2x2 - x1x2^2 + x2^2x3 + x1^2x3 - 2x1x2x3 - y2^2 + 2y1y2 - y1^2 == 0
// Each side of the sign stays below 4 * 48 * 2^96 < 2^104.
template Secp256k1AddUnequalCubicConstraint32() {
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

    component zeroCheck = Secp256k1CheckCubicModPIsZero104();
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
template Secp256k1PointOnLine32() {
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

    component zeroCheck = Secp256k1CheckQuadraticModPIsZero69();
    for (var i = 0; i < 15; i++) {
        zeroCheck.in[i] <== x3y2.out[i] + x2y3.out[i] + x2y1.out[i]
            - x3y1.out[i] - x1y2.out[i] - x1y3.out[i];
    }
}

// x^3 + 7 - y^2 == 0 mod p. Each side below 48 * 2^96 + 2^67 < 2^102.
template Secp256k1PointOnCurve32() {
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

    component zeroCheck = Secp256k1CheckCubicModPIsZero102();
    for (var i = 0; i < 22; i++) {
        if (i == 0) {
            zeroCheck.in[i] <== x3.out[i] - ysq.out[i] + 7;
        } else if (i < 15) {
            zeroCheck.in[i] <== x3.out[i] - ysq.out[i];
        } else {
            zeroCheck.in[i] <== x3.out[i];
        }
    }
}

// a + b for finite points with distinct x. The caller must enforce that
// precondition; equal points leave the chord and line equations unconstrained.
template Secp256k1AddUnequal32() {
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
    var tmp[2][100] = secp256k1_addunequal_func(64, 4, secp256k1_join32(x1), secp256k1_join32(y1),
        secp256k1_join32(x2), secp256k1_join32(y2));
    var outx[100] = p256_split64to32(tmp[0]);
    var outy[100] = p256_split64to32(tmp[1]);
    for (var i = 0; i < 8; i++) {
        out[0][i] <-- outx[i];
        out[1][i] <-- outy[i];
    }

    component cubic = Secp256k1AddUnequalCubicConstraint32();
    component onLine = Secp256k1PointOnLine32();
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

    component xRange = CheckInRangeSecp256k1Limbs32();
    component yRange = CheckInRangeSecp256k1Limbs32();
    for (var i = 0; i < 8; i++) {
        xRange.in[i] <== out[0][i];
        yRange.in[i] <== out[1][i];
    }
}

/*
    2 * in for a finite point on the curve, with the tangent slope witnessed.
    Three quadratic checks hold mod p:

        (1) 2 * y1 * lambda == 3 * x1^2
        (2) x3 == lambda^2 - 2 * x1
        (3) y3 == lambda * (x1 - x3) - y1

    secp256k1 has prime order, so no finite point has y1 == 0: (1) fixes
    lambda, and (2) and (3) fix the output. As in P256Double, no on-curve
    check and no x3 != x1 check on the output are needed.

    In (1), 2 * lambda * y1 stays below 2^68 and 3 * x1^2 below 3 * 2^67, so
    every register stays below 2^69.
*/
template Secp256k1Double32() {
    signal input in[2][8];
    signal output out[2][8];

    var x1[8];
    var y1[8];
    for (var i = 0; i < 8; i++) {
        x1[i] = in[0][i];
        y1[i] = in[1][i];
    }
    var tmp[3][100] = secp256k1_slope_add_func(64, 4, secp256k1_join32(x1), secp256k1_join32(y1),
        secp256k1_join32(x1), secp256k1_join32(y1), 1);
    var lv[100] = p256_split64to32(tmp[0]);
    var xv[100] = p256_split64to32(tmp[1]);
    var yv[100] = p256_split64to32(tmp[2]);
    signal lambda[8];
    for (var i = 0; i < 8; i++) {
        lambda[i] <-- lv[i];
        out[0][i] <-- xv[i];
        out[1][i] <-- yv[i];
    }

    component lambdaRange[8];
    for (var i = 0; i < 8; i++) {
        lambdaRange[i] = Num2Bits(32);
        lambdaRange[i].in <== lambda[i];
    }
    component xRange = CheckInRangeSecp256k1Limbs32();
    component yRange = CheckInRangeSecp256k1Limbs32();
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

    component tangent = Secp256k1CheckQuadraticModPIsZero69();
    component chord = Secp256k1CheckQuadraticModPIsZero69();
    component line = Secp256k1CheckQuadraticModPIsZero69();
    for (var i = 0; i < 15; i++) {
        tangent.in[i] <== 2 * ly1.out[i] - 3 * x1sq.out[i];
        if (i < 8) {
            chord.in[i] <== lsq.out[i] - 2 * in[0][i] - out[0][i];
            line.in[i] <== lx3.out[i] - lx1.out[i] + out[1][i] + in[1][i];
        } else {
            chord.in[i] <== lsq.out[i];
            line.in[i] <== lx3.out[i] - lx1.out[i];
        }
    }
}

// a * b mod p, canonical, for canonical a and b. a * b - out is below
// 8 * 2^64 + 2^32 < 2^69 per register.
template Secp256k1MulModP32() {
    signal input a[8];
    signal input b[8];
    signal output out[8];

    var av[8];
    var bv[8];
    for (var i = 0; i < 8; i++) {
        av[i] = a[i];
        bv[i] = b[i];
    }
    var prime64[100] = get_secp256k1_prime(64, 4);
    var prod[100] = prod_mod_p(64, 4, secp256k1_join32(av), secp256k1_join32(bv), prime64);
    var outv[100] = p256_split64to32(prod);
    for (var i = 0; i < 8; i++) { out[i] <-- outv[i]; }

    component range = CheckInRangeSecp256k1Limbs32();
    for (var i = 0; i < 8; i++) { range.in[i] <== out[i]; }

    component ab = P256Mul();
    for (var i = 0; i < 8; i++) { ab.a[i] <== a[i]; ab.b[i] <== b[i]; }
    component zeroCheck = Secp256k1CheckQuadraticModPIsZero69();
    for (var i = 0; i < 15; i++) {
        if (i < 8) {
            zeroCheck.in[i] <== ab.out[i] - out[i];
        } else {
            zeroCheck.in[i] <== ab.out[i];
        }
    }
}
