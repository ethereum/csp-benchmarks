pragma circom 2.0.2;

include "../../circomlib/circuits/bitify.circom";
include "../../circomlib/circuits/comparators.circom";
include "./bigint.circom";
include "./bigint_func.circom";
include "./p256_func.circom";

// Row i is 2^(64 i) mod p as four signed coefficients: input register i adds
// T[i][j] * in[i] to output register j. Chosen to minimise the coefficient
// magnitudes, which is what bounds the register growth below.
function p256_reduce_table() {
    var T[10][4] = [
        [1, 0, 0, 0],
        [0, 1, 0, 0],
        [0, 0, 1, 0],
        [0, 0, 0, 1],
        [1, -(1 << 32), 0, (1 << 32) - 1],
        [1 << 32, 1, -((1 << 32) + 1), -(1 << 32)],
        [-((1 << 32) + 1), 1 << 33, 2, -(1 << 32)],
        [-((1 << 32) + 1), -1, (1 << 33) + 1, 3],
        [3, -((1 << 34) + 1), -1, 5 * (1 << 32) - 2],
        [5 * (1 << 32) + 3, -(3 * (1 << 32) - 3), -((1 << 34) + 6), -((1 << 33) + 4)]
    ];
    return T;
}

// Signed registers of 64-bit scale to eight proper 64-bit limbs of the same
// value, for a value known to be non-negative and below 2^512. Witness
// generation only.
//
// getProperRepresentation cannot be used for the checks below: its sign test
// compares against half the field, but circom compares field elements by their
// signed value, so the test never fires and a negative register is split as
// its field representative. Here registers 1 and 2 of the value being divided
// can be negative, because p's limbs there (2^32 - 1 and 0) are too small for
// the added multiple of p to cover them.
function p256_carry_signed(k, in) {
    var out[100];
    for (var i = 0; i < 100; i++) { out[i] = 0; }
    var carry = 0;
    for (var i = 0; i < 8; i++) {
        var v = carry;
        if (i < k) { v += in[i]; }
        if (v < 0) {
            var a = -v;
            var lo = a % (1 << 64);
            if (lo == 0) {
                out[i] = 0;
                carry = -(a >> 64);
            } else {
                out[i] = (1 << 64) - lo;
                carry = -(a >> 64) - 1;
            }
        } else {
            out[i] = v % (1 << 64);
            carry = v >> 64;
        }
    }
    return out;
}

// 10 registers of 64-bit scale, possibly overfull and possibly negative, to 4
// registers congruent mod p. Adds at most 36 bits: the coefficient sums per
// output register are below 2^36, 2^36, 2^35, 2^36.
template P256PrimeReduce10Registers() {
    signal input in[10];
    signal output out[4];

    var T[10][4] = p256_reduce_table();
    for (var j = 0; j < 4; j++) {
        var acc = 0;
        for (var i = 0; i < 10; i++) { acc += T[i][j] * in[i]; }
        out[j] <== acc;
    }
}

// 7 registers. Adds at most 34 bits: coefficient sums below 2^34, 2^34, 2^33,
// 2^34 -- one bit more than the secp256k1 equivalent.
template P256PrimeReduce7Registers() {
    signal input in[7];
    signal output out[4];

    var T[10][4] = p256_reduce_table();
    for (var j = 0; j < 4; j++) {
        var acc = 0;
        for (var i = 0; i < 7; i++) { acc += T[i][j] * in[i]; }
        out[j] <== acc;
    }
}

// in < p, every limb below 2^64. p = [2^64 - 1, 2^32 - 1, 0, 2^64 - 2^32 + 1]:
// in < p  <=>  in3 < p3, or in3 == p3 and in2 == 0 and
//              (in1 < 2^32 - 1, or in1 == 2^32 - 1 and in0 != 2^64 - 1).
// The comparisons of in0 and in1 against their constants reuse the limb bits.
template CheckInRangeP256() {
    signal input in[4];

    component range64[4];
    for (var i = 0; i < 4; i++) {
        range64[i] = Num2Bits(64);
        range64[i].in <== in[i];
    }

    component lt3 = LessThan(64);
    lt3.in[0] <== in[3];
    lt3.in[1] <== 18446744069414584321;
    component eq3 = IsEqual();
    eq3.in[0] <== in[3];
    eq3.in[1] <== 18446744069414584321;

    component z2 = IsZero();
    z2.in <== in[2];

    // in1 < 2^32 - 1  <=>  its top 32 bits are zero and in1 != 2^32 - 1
    var hi1 = 0;
    for (var t = 32; t < 64; t++) { hi1 += range64[1].out[t] * (1 << (t - 32)); }
    component hiZero1 = IsZero();
    hiZero1.in <== hi1;
    component eq1 = IsEqual();
    eq1.in[0] <== in[1];
    eq1.in[1] <== 4294967295;
    signal lt1;
    lt1 <== hiZero1.out * (1 - eq1.out);

    // in0 < 2^64 - 1  <=>  in0 != 2^64 - 1, given in0 < 2^64
    component eq0 = IsEqual();
    eq0.in[0] <== in[0];
    eq0.in[1] <== 18446744073709551615;

    signal tail;
    tail <== eq1.out * (1 - eq0.out);
    signal top;
    top <== eq3.out * z2.out;
    signal equalTop;
    equalTop <== top * (lt1 + tail);
    lt3.out + equalTop === 1;
}

// 64-bit registers with m-bit overflow, possibly negative. Constrains the
// 10-register value to be 0 mod p.
template P256CheckCubicModPIsZero(m) {
    assert(m < 206);

    signal input in[10];

    var prime[100] = get_p256_prime(64, 4);
    signal p[4];
    for (var i = 0; i < 4; i++) { p[i] <== prime[i]; }

    // z = reduce(in) keeps the residue, with registers of at most m + 36 bits,
    // so |z| < 2^(m + 229). p * 2^(m - 20) is just under 2^(m + 236): adding
    // it makes the value positive, and every register stays below 2^(m + 45).
    signal reduced[4];
    component reducer = P256PrimeReduce10Registers();
    for (var i = 0; i < 10; i++) { reducer.in[i] <== in[i]; }
    signal multipleOfP[4];
    for (var i = 0; i < 4; i++) { multipleOfP[i] <== p[i] * (1 << (m - 20)); }
    for (var i = 0; i < 4; i++) { reduced[i] <== reducer.out[i] + multipleOfP[i]; }

    // The quotient is below 2^192, so three registers hold it.
    signal q[3];
    var temp[100] = p256_carry_signed(4, reduced);
    var proper[8];
    for (var i = 0; i < 8; i++) { proper[i] = temp[i]; }
    var qVarTemp[2][100] = long_div(64, 4, 4, proper, p);
    for (var i = 0; i < 3; i++) { q[i] <-- qVarTemp[0][i]; }

    component qRangeChecks[3];
    for (var i = 0; i < 3; i++) {
        qRangeChecks[i] = Num2Bits(64);
        qRangeChecks[i].in <== q[i];
    }

    signal qpProd[6];
    component qpProdComp = BigMultNoCarry(64, 64, 64, 3, 4);
    for (var i = 0; i < 3; i++) { qpProdComp.a[i] <== q[i]; }
    for (var i = 0; i < 4; i++) { qpProdComp.b[i] <== p[i]; }
    for (var i = 0; i < 6; i++) { qpProd[i] <== qpProdComp.out[i]; }

    component zeroCheck = CheckCarryToZero(64, m + 46, 6);
    for (var i = 0; i < 6; i++) {
        if (i < 4) {
            zeroCheck.in[i] <== qpProd[i] - reduced[i];
        } else {
            zeroCheck.in[i] <== qpProd[i];
        }
    }
}

// 64-bit registers with m-bit overflow, possibly negative. Constrains the
// 7-register value to be 0 mod p.
template P256CheckQuadraticModPIsZero(m) {
    assert(m < 147);

    signal input in[7];

    var prime[100] = get_p256_prime(64, 4);
    signal p[4];
    for (var i = 0; i < 4; i++) { p[i] <== prime[i]; }

    // Registers of z are at most m + 34 bits and the top coefficient sum is
    // 3 * 2^32, so |z| < 3 * 2^(m + 224) + 2^(m + 161). p * 2^(m - 30) is
    // about 4 * 2^(m + 224) and still dominates; registers stay below 2^(m + 35).
    signal reduced[4];
    component reducer = P256PrimeReduce7Registers();
    for (var i = 0; i < 7; i++) { reducer.in[i] <== in[i]; }
    signal multipleOfP[4];
    for (var i = 0; i < 4; i++) { multipleOfP[i] <== p[i] * (1 << (m - 30)); }
    for (var i = 0; i < 4; i++) { reduced[i] <== reducer.out[i] + multipleOfP[i]; }

    // The quotient is below 2^128, so two registers hold it.
    signal q[2];
    var temp[100] = p256_carry_signed(4, reduced);
    var proper[8];
    for (var i = 0; i < 8; i++) { proper[i] = temp[i]; }
    var qVarTemp[2][100] = long_div(64, 4, 4, proper, p);
    for (var i = 0; i < 2; i++) { q[i] <-- qVarTemp[0][i]; }

    component qRangeChecks[2];
    for (var i = 0; i < 2; i++) {
        qRangeChecks[i] = Num2Bits(64);
        qRangeChecks[i].in <== q[i];
    }

    signal qpProd[5];
    component qpProdComp = BigMultNoCarry(64, 64, 64, 2, 4);
    for (var i = 0; i < 2; i++) { qpProdComp.a[i] <== q[i]; }
    for (var i = 0; i < 4; i++) { qpProdComp.b[i] <== p[i]; }
    for (var i = 0; i < 5; i++) { qpProd[i] <== qpProdComp.out[i]; }

    component zeroCheck = CheckCarryToZero(64, m + 36, 5);
    for (var i = 0; i < 5; i++) {
        if (i < 4) {
            zeroCheck.in[i] <== qpProd[i] - reduced[i];
        } else {
            zeroCheck.in[i] <== qpProd[i];
        }
    }
}
