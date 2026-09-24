pragma circom 2.0.2;

/*
    Arithmetic modulo the P-256 prime in (32, 8): eight 32-bit limbs, least
    significant first.

    p = 2^256 - 2^224 + 2^192 + 2^96 - 1 is aligned to 32 bits. With x = 2^32,
    2^256 == 2^224 - 2^192 - 2^96 + 1 (mod p) reads x^8 == x^7 - x^6 - x^3 + 1,
    so every power of x folds back into eight registers with coefficients of at
    most four bits: the NIST fast reduction, written as a table.
*/

include "../../circomlib/circuits/bitify.circom";
include "../../circomlib/circuits/comparators.circom";
include "./bigint.circom";
include "./bigint_func.circom";
include "./p256_func.circom";

// Row i is 2^(32 i) mod p as eight signed coefficients: input register i adds
// T[i][j] * in[i] to output register j. Rows 0..21 cover the products of three
// field elements; the first 15 cover the products of two.
function p256_reduce_table32() {
    var T[22][8] = [
        [1, 0, 0, 0, 0, 0, 0, 0],
        [0, 1, 0, 0, 0, 0, 0, 0],
        [0, 0, 1, 0, 0, 0, 0, 0],
        [0, 0, 0, 1, 0, 0, 0, 0],
        [0, 0, 0, 0, 1, 0, 0, 0],
        [0, 0, 0, 0, 0, 1, 0, 0],
        [0, 0, 0, 0, 0, 0, 1, 0],
        [0, 0, 0, 0, 0, 0, 0, 1],
        [1, 0, 0, -1, 0, 0, -1, 1],
        [1, 1, 0, -1, -1, 0, -1, 0],
        [0, 1, 1, 0, -1, -1, 0, -1],
        [-1, 0, 1, 2, 0, -1, 0, -1],
        [-1, -1, 0, 2, 2, 0, 0, -1],
        [-1, -1, -1, 1, 2, 2, 1, -1],
        [-1, -1, -1, 0, 1, 2, 3, 0],
        [0, -1, -1, -1, 0, 1, 2, 3],
        [3, 0, -1, -4, -1, 0, -2, 5],
        [5, 3, 0, -6, -4, -1, -5, 3],
        [3, 5, 3, -3, -6, -4, -4, -2],
        [-2, 3, 5, 5, -3, -6, -2, -6],
        [-6, -2, 3, 11, 5, -3, 0, -8],
        [-8, -6, -2, 11, 11, 5, 5, -8]
    ];
    return T;
}

// Signed registers of 32-bit scale to len proper 32-bit limbs of the same
// value, for a value known to be non-negative. Witness generation only.
//
// getProperRepresentation cannot be used for the checks below: its sign test
// compares against half the field, but circom compares field elements by their
// signed value, so the test never fires and a negative register is split as
// its field representative. Here registers 3, 4 and 5 of the value being
// divided can be negative, because p's limbs there are zero and the added
// multiple of p does not cover them.
function p256_carry_signed(k, len, in) {
    var out[100];
    for (var i = 0; i < 100; i++) { out[i] = 0; }
    var carry = 0;
    for (var i = 0; i < len; i++) {
        var v = carry;
        if (i < k) { v += in[i]; }
        if (v < 0) {
            var a = -v;
            var lo = a % (1 << 32);
            if (lo == 0) {
                out[i] = 0;
                carry = -(a >> 32);
            } else {
                out[i] = (1 << 32) - lo;
                carry = -(a >> 32) - 1;
            }
        } else {
            out[i] = v % (1 << 32);
            carry = v >> 32;
        }
    }
    return out;
}

/*
    a * b as a polynomial product without carries: out has ka + kb - 1
    registers. The constraints are those of BigMultNoCarry: the identity
    out(x) == a(x) * b(x) at the points x = 0 .. ka + kb - 2, which pins the
    ka + kb - 1 coefficients of out as long as every register stays below the
    field size (ma + mb <= 253).

    Only witness generation differs. BigMultNoCarry evaluates each point as
    i ** j, which the witness generator computes as a full field
    exponentiation per term; with eight-limb operands that dominated witness
    time. Here the powers of i are accumulated by multiplication. The
    constraint system is the same.
*/
template P256MultNoCarry(ma, mb, ka, kb) {
    assert(ma + mb <= 253);
    signal input a[ka];
    signal input b[kb];
    signal output out[ka + kb - 1];

    var prod_val[ka + kb - 1];
    for (var i = 0; i < ka + kb - 1; i++) { prod_val[i] = 0; }
    for (var i = 0; i < ka; i++) {
        for (var j = 0; j < kb; j++) {
            prod_val[i + j] += a[i] * b[j];
        }
    }
    for (var i = 0; i < ka + kb - 1; i++) {
        out[i] <-- prod_val[i];
    }

    var a_poly[ka + kb - 1];
    var b_poly[ka + kb - 1];
    var out_poly[ka + kb - 1];
    for (var i = 0; i < ka + kb - 1; i++) {
        out_poly[i] = 0;
        a_poly[i] = 0;
        b_poly[i] = 0;
        var pw = 1;
        for (var j = 0; j < ka + kb - 1; j++) {
            out_poly[i] = out_poly[i] + out[j] * pw;
            if (j < ka) { a_poly[i] = a_poly[i] + a[j] * pw; }
            if (j < kb) { b_poly[i] = b_poly[i] + b[j] * pw; }
            pw = pw * i;
        }
    }
    for (var i = 0; i < ka + kb - 1; i++) {
        out_poly[i] === a_poly[i] * b_poly[i];
    }
}

/*
    Constrains a value of `regs` 32-bit-scale registers, each possibly negative
    and below 2^m in absolute value, to be 0 mod p.

    The registers are folded to eight with the table above, and p * 2^shift is
    added so the value is positive. The prover supplies the quotient q in kq
    limbs; q * p - reduced must then carry to zero, with every register below
    2^(M - 1). shift, kq, M and len (the limbs the witness-time division needs)
    are derived per caller from the exact coefficient sums, not bit ceilings.
*/
template P256CheckModPIsZero(regs, m, shift, kq, M, len) {
    assert(regs <= 22);
    assert(M + 3 <= 253);

    signal input in[regs];

    var T[22][8] = p256_reduce_table32();
    var prime[100] = get_p256_prime(32, 8);
    signal p[8];
    for (var i = 0; i < 8; i++) { p[i] <== prime[i]; }

    signal reduced[8];
    for (var j = 0; j < 8; j++) {
        var acc = 0;
        for (var i = 0; i < regs; i++) { acc += T[i][j] * in[i]; }
        reduced[j] <== acc + p[j] * (1 << shift);
    }

    signal q[kq];
    var temp[100] = p256_carry_signed(8, len, reduced);
    var proper[100];
    for (var i = 0; i < 100; i++) { proper[i] = 0; }
    for (var i = 0; i < len; i++) { proper[i] = temp[i]; }
    var qv[2][100] = long_div(32, 8, len - 8, proper, prime);
    for (var i = 0; i < kq; i++) { q[i] <-- qv[0][i]; }

    component qRange[kq];
    for (var i = 0; i < kq; i++) {
        qRange[i] = Num2Bits(32);
        qRange[i].in <== q[i];
    }

    component qp = P256MultNoCarry(32, 32, kq, 8);
    for (var i = 0; i < kq; i++) { qp.a[i] <== q[i]; }
    for (var i = 0; i < 8; i++) { qp.b[i] <== p[i]; }

    component zero = CheckCarryToZero(32, M, kq + 7);
    for (var i = 0; i < kq + 7; i++) {
        if (i < 8) {
            zero.in[i] <== qp.out[i] - reduced[i];
        } else {
            zero.in[i] <== qp.out[i];
        }
    }
}

// Products of three field elements, |in| < 2^104: the chord of an addition and
// the tangent of a doubling. Register growth 6 bits.
template P256CheckCubicModPIsZero104() {
    signal input in[22];
    component c = P256CheckModPIsZero(22, 104, 78, 3, 112, 12);
    for (var i = 0; i < 22; i++) { c.in[i] <== in[i]; }
}

// Products of three field elements, |in| < 2^102: the curve equation.
template P256CheckCubicModPIsZero102() {
    signal input in[22];
    component c = P256CheckModPIsZero(22, 102, 76, 3, 110, 12);
    for (var i = 0; i < 22; i++) { c.in[i] <== in[i]; }
}

// Products of two field elements, |in| < 2^69: the line of an addition.
// Register growth 4 bits.
template P256CheckQuadraticModPIsZero69() {
    signal input in[15];
    component c = P256CheckModPIsZero(15, 69, 40, 2, 74, 11);
    for (var i = 0; i < 15; i++) { c.in[i] <== in[i]; }
}

// in < p, every limb below 2^32. p = [2^32-1, 2^32-1, 2^32-1, 0, 0, 0, 1, 2^32-1]:
// in < p  <=>  in7 != p7, or in7 == p7 and (in6 == 0, or in6 == 1 and
//              in5 = in4 = in3 = 0 and not in2 = in1 = in0 = 2^32 - 1).
template CheckInRangeP256() {
    signal input in[8];

    component range32[8];
    for (var i = 0; i < 8; i++) {
        range32[i] = Num2Bits(32);
        range32[i].in <== in[i];
    }

    component eq7 = IsEqual();
    eq7.in[0] <== in[7];
    eq7.in[1] <== 4294967295;
    component z6 = IsZero();
    z6.in <== in[6];
    component one6 = IsEqual();
    one6.in[0] <== in[6];
    one6.in[1] <== 1;

    component zMid[3];
    component eqLow[3];
    for (var i = 0; i < 3; i++) {
        zMid[i] = IsZero();
        zMid[i].in <== in[3 + i];
        eqLow[i] = IsEqual();
        eqLow[i].in[0] <== in[i];
        eqLow[i].in[1] <== 4294967295;
    }
    signal z45;
    z45 <== zMid[1].out * zMid[2].out;
    signal z345;
    z345 <== z45 * zMid[0].out;
    signal e01;
    e01 <== eqLow[0].out * eqLow[1].out;
    signal e012;
    e012 <== e01 * eqLow[2].out;
    signal mid;
    mid <== one6.out * z345;
    signal lowOk;
    lowOk <== mid * (1 - e012);

    // in7 < p7 needs nothing more; in7 == p7 needs one of the two lower cases
    signal topEq;
    topEq <== eq7.out * (z6.out + lowOk);
    topEq === eq7.out;
}

// in: four 64-bit limbs. out: the same value in eight 32-bit limbs. Unique only
// once the caller range-checks out (CheckInRangeP256 does): lo + hi * 2^32 then
// stays below 2^64, far under the field size.
template P256Limbs64To32() {
    signal input in[4];
    signal output out[8];
    for (var i = 0; i < 4; i++) {
        out[2 * i] <-- in[i] % (1 << 32);
        out[2 * i + 1] <-- in[i] \ (1 << 32);
        out[2 * i] + out[2 * i + 1] * (1 << 32) === in[i];
    }
}

// Linear: eight 32-bit limbs to four 64-bit limbs.
template P256Limbs32To64() {
    signal input in[8];
    signal output out[4];
    for (var i = 0; i < 4; i++) {
        out[i] <== in[2 * i] + in[2 * i + 1] * (1 << 32);
    }
}
