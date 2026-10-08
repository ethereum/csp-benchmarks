pragma circom 2.0.2;

/*
    Arithmetic modulo the secp256k1 prime in (32, 8): eight 32-bit limbs, least
    significant first.

    p = 2^256 - 2^32 - 977. With x = 2^32, 2^256 == 2^32 + 977 (mod p) reads
    x^8 == x + 977. Unlike P-256, the coefficient is not small: registers 8..15
    fold once (coefficient 977), registers 16..21 fold twice (977^2 = 954,529),
    so the reduced registers grow by up to 20 bits more than the inputs. The
    parameters below are derived from the exact coefficient sums, as for P-256.

    P256MultNoCarry and p256_carry_signed do not depend on the curve and are
    reused from p256_utils.circom.
*/

include "../../circomlib/circuits/bitify.circom";
include "../../circomlib/circuits/comparators.circom";
include "./bigint.circom";
include "./bigint_func.circom";
include "./p256_utils.circom";

// Row i is 2^(32 i) mod p as eight coefficients: input register i adds
// T[i][j] * in[i] to output register j. Rows 0..21 cover the products of three
// field elements; the first 15 cover the products of two.
function secp256k1_reduce_table32() {
    var T[22][8] = [
        [1, 0, 0, 0, 0, 0, 0, 0],
        [0, 1, 0, 0, 0, 0, 0, 0],
        [0, 0, 1, 0, 0, 0, 0, 0],
        [0, 0, 0, 1, 0, 0, 0, 0],
        [0, 0, 0, 0, 1, 0, 0, 0],
        [0, 0, 0, 0, 0, 1, 0, 0],
        [0, 0, 0, 0, 0, 0, 1, 0],
        [0, 0, 0, 0, 0, 0, 0, 1],
        [977, 1, 0, 0, 0, 0, 0, 0],
        [0, 977, 1, 0, 0, 0, 0, 0],
        [0, 0, 977, 1, 0, 0, 0, 0],
        [0, 0, 0, 977, 1, 0, 0, 0],
        [0, 0, 0, 0, 977, 1, 0, 0],
        [0, 0, 0, 0, 0, 977, 1, 0],
        [0, 0, 0, 0, 0, 0, 977, 1],
        [977, 1, 0, 0, 0, 0, 0, 977],
        [954529, 1954, 1, 0, 0, 0, 0, 0],
        [0, 954529, 1954, 1, 0, 0, 0, 0],
        [0, 0, 954529, 1954, 1, 0, 0, 0],
        [0, 0, 0, 954529, 1954, 1, 0, 0],
        [0, 0, 0, 0, 954529, 1954, 1, 0],
        [0, 0, 0, 0, 0, 954529, 1954, 1]
    ];
    return T;
}

function get_secp256k1_prime32() {
    var ret[100];
    for (var i = 0; i < 100; i++) { ret[i] = 0; }
    ret[0] = 4294966319;
    ret[1] = 4294967294;
    for (var i = 2; i < 8; i++) { ret[i] = 4294967295; }
    return ret;
}

/*
    Constrains a value of `regs` 32-bit-scale registers, each possibly negative
    and below 2^m in absolute value, to be 0 mod p. The same construction as
    P256CheckModPIsZero, with the secp256k1 table and prime: fold to eight
    registers, add p * 2^shift, witness the quotient on qbits bits and check
    that q * p - reduced carries to zero over groups of g registers.
*/
template Secp256k1CheckModPIsZero32(regs, m, shift, kq, M, len, g, qbits) {
    assert(regs <= 22);
    assert(qbits > 32 * (kq - 1) && qbits <= 32 * kq);
    var MG = M + 32 * (g - 1) + 1;
    assert(MG + 3 <= 253);

    signal input in[regs];

    var T[22][8] = secp256k1_reduce_table32();
    var prime[100] = get_secp256k1_prime32();
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
        qRange[i] = Num2Bits(i < kq - 1 ? 32 : qbits - 32 * (kq - 1));
        qRange[i].in <== q[i];
    }

    component qp = P256MultNoCarry(32, 32, kq, 8);
    for (var i = 0; i < kq; i++) { qp.a[i] <== q[i]; }
    for (var i = 0; i < 8; i++) { qp.b[i] <== p[i]; }

    var K = kq + 7;
    signal diff[K];
    for (var i = 0; i < K; i++) {
        if (i < 8) {
            diff[i] <== qp.out[i] - reduced[i];
        } else {
            diff[i] <== qp.out[i];
        }
    }

    var KG = (K + g - 1) \ g;
    component zero = CheckCarryToZero(32 * g, MG, KG);
    for (var j = 0; j < KG; j++) {
        var joined = 0;
        for (var t = 0; t < g; t++) {
            if (j * g + t < K) { joined += diff[j * g + t] * (1 << (32 * t)); }
        }
        zero.in[j] <== joined;
    }
}

// Products of three field elements, |in| < 2^104: the chord of an addition and
// the tangent of a doubling. Carries over groups of four registers; five would
// need M <= 121 for MG + 3 <= 253.
template Secp256k1CheckCubicModPIsZero104() {
    signal input in[22];
    component c = Secp256k1CheckModPIsZero32(22, 104, 82, 3, 125, 12, 4, 96);
    for (var i = 0; i < 22; i++) { c.in[i] <== in[i]; }
}

// Products of three field elements, |in| < 2^102: the curve equation.
// Carries over groups of four registers.
template Secp256k1CheckCubicModPIsZero102() {
    signal input in[22];
    component c = Secp256k1CheckModPIsZero32(22, 102, 80, 3, 123, 12, 4, 96);
    for (var i = 0; i < 22; i++) { c.in[i] <== in[i]; }
}

// Products of two field elements, |in| < 2^69: the line of an addition.
// Carries over groups of six registers.
template Secp256k1CheckQuadraticModPIsZero69() {
    signal input in[15];
    component c = Secp256k1CheckModPIsZero32(15, 69, 39, 2, 80, 11, 6, 64);
    for (var i = 0; i < 15; i++) { c.in[i] <== in[i]; }
}

// in < p, every limb below 2^32. p = 2^256 - 2^32 - 977: in >= p exactly when
// limbs 2..7 are all 2^32 - 1 and the low 64 bits are at least 2^64 - 2^32 - 977.
// CheckInRangeSecp256k1 on eight limbs.
template CheckInRangeSecp256k1Limbs32() {
    signal input in[8];

    component range32[8];
    for (var i = 0; i < 8; i++) {
        range32[i] = Num2Bits(32);
        range32[i].in <== in[i];
    }

    component isEqual[6];
    signal allEqual[7];
    allEqual[0] <== 1;
    for (var i = 2; i < 8; i++) {
        isEqual[i - 2] = IsEqual();
        isEqual[i - 2].in[0] <== in[i];
        isEqual[i - 2].in[1] <== 4294967295;
        allEqual[i - 1] <== allEqual[i - 2] * isEqual[i - 2].out;
    }

    component lessThan = LessThan(64);
    lessThan.in[0] <== in[0] + in[1] * (1 << 32);
    lessThan.in[1] <== (1 << 64) - (1 << 32) - 977;
    (1 - lessThan.out) * allEqual[6] === 0;
}
