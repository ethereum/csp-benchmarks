pragma circom 2.0.2;

/*
    Point operations on secp256k1, y^2 = x^3 + 7, on points of eight 32-bit
    limbs per coordinate. The constraint shapes are those of the circom-ecdsa
    templates in secp256k1.circom (chord cubic, line, tangent cubic, curve
    equation); only the limb size and the modular checks change.

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

// 2y1^2 + 2y1y3 - 3x1^3 + 3x1^2x3 == 0 mod p: (x3, -y3) lies on the tangent
// at (x1, y1). Each side below 3 * 48 * 2^96 + 4 * 8 * 2^64 < 2^104.
template Secp256k1PointOnTangent32() {
    signal input x1[8];
    signal input y1[8];
    signal input x3[8];
    signal input y3[8];

    component y1sq = P256Mul();
    component y1y3 = P256Mul();
    component x1sq = P256Mul();
    for (var i = 0; i < 8; i++) {
        y1sq.a[i] <== y1[i]; y1sq.b[i] <== y1[i];
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

    component zeroCheck = Secp256k1CheckCubicModPIsZero104();
    for (var i = 0; i < 22; i++) {
        if (i < 15) {
            zeroCheck.in[i] <== 2 * y1sq.out[i] + 2 * y1y3.out[i]
                - 3 * x13.out[i] + 3 * x12x3.out[i];
        } else {
            zeroCheck.in[i] <== -3 * x13.out[i] + 3 * x12x3.out[i];
        }
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

// 2 * in for a finite point on the curve: the output lies on the tangent and
// on the curve, and its x differs from the input's, which excludes the input
// point itself as the other tangent intersection.
template Secp256k1Double32() {
    signal input in[2][8];
    signal output out[2][8];

    var x1[8];
    var y1[8];
    for (var i = 0; i < 8; i++) {
        x1[i] = in[0][i];
        y1[i] = in[1][i];
    }
    var tmp[2][100] = secp256k1_double_func(64, 4, secp256k1_join32(x1), secp256k1_join32(y1));
    var outx[100] = p256_split64to32(tmp[0]);
    var outy[100] = p256_split64to32(tmp[1]);
    for (var i = 0; i < 8; i++) {
        out[0][i] <-- outx[i];
        out[1][i] <-- outy[i];
    }

    component onTangent = Secp256k1PointOnTangent32();
    for (var i = 0; i < 8; i++) {
        onTangent.x1[i] <== in[0][i];
        onTangent.y1[i] <== in[1][i];
        onTangent.x3[i] <== out[0][i];
        onTangent.y3[i] <== out[1][i];
    }

    component onCurve = Secp256k1PointOnCurve32();
    for (var i = 0; i < 8; i++) {
        onCurve.x[i] <== out[0][i];
        onCurve.y[i] <== out[1][i];
    }

    component xRange = CheckInRangeSecp256k1Limbs32();
    component yRange = CheckInRangeSecp256k1Limbs32();
    for (var i = 0; i < 8; i++) {
        xRange.in[i] <== out[0][i];
        yRange.in[i] <== out[1][i];
    }

    component x3EqX1 = BigIsEqual(8);
    for (var i = 0; i < 8; i++) {
        x3EqX1.in[0][i] <== out[0][i];
        x3EqX1.in[1][i] <== in[0][i];
    }
    x3EqX1.out === 0;
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
