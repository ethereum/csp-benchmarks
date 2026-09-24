pragma circom 2.0.2;

/*
    [k]G on P-256 with the width-12 signed-digit comb: 22 windows of 2048
    precomputed odd multiples, one lookup per window, 21 additions.

    The scalar is taken in four 64-bit limbs; points are handled in eight
    32-bit limbs per coordinate.

    The technique follows the public description of rot256's (Mathias
    Hall-Andersen) submission to the zk.golf secp256k1 fixed-base scalar
    multiplication challenge, applied here to P-256. No code was copied.
*/

include "./p256.circom";
include "./comb_table_p256.circom";
include "./bigint.circom";
include "../../circomlib/circuits/comparators.circom";

template CombFixedBaseP256() {
    signal input k[4];                 // k in [1, n), 64-bit limbs
    signal output out[2][8];           // [k]G, 32-bit limbs

    var ordN[100] = get_p256_order(64, 4);
    var prime[100] = get_p256_prime(32, 8);

    // ---------- 1. the limbs are in range ----------
    component kRange[4];
    for (var j = 0; j < 4; j++) {
        kRange[j] = Num2Bits(64);
        kRange[j].in <== k[j];
    }
    signal isOdd;
    isOdd <== kRange[0].out[0];

    // ---------- 2. parity, folded ----------
    // The all-odd recoding requires k odd. n is odd and [n]G = O, so k + n has
    // the opposite parity and the same multiple.
    component fold = BigAdd(64, 4);
    for (var j = 0; j < 4; j++) {
        fold.a[j] <== k[j];
        fold.b[j] <== (1 - isOdd) * ordN[j];
    }

    // ---------- 3. the bits of kOdd ----------
    // kOdd < 2n < 2^257, so the carry limb is 0 or 1. Positions 257..263 are
    // zero: the recoding holds for any L >= bitlength(k), and the tables use
    // L = 264.
    signal kb[264];
    component lb[4];
    for (var j = 0; j < 4; j++) {
        lb[j] = Num2Bits(64);
        lb[j].in <== fold.out[j];
        for (var t = 0; t < 64; t++) { kb[64 * j + t] <== lb[j].out[t]; }
    }
    fold.out[4] * (fold.out[4] - 1) === 0;
    kb[256] <== fold.out[4];
    for (var t = 257; t < 264; t++) { kb[t] <== 0; }

    kb[0] === 1;

    // ---------- 3a. the scalar that makes the final addition a doubling ----------
    // An accumulator addition degenerates exactly when
    // partial_i == d_i * 2^(12 i) mod n, which leaves its output free. Windows
    // 1..20 rule it out by magnitude; at window 21 an exhaustive search over the
    // top digit finds exactly one such scalar for P-256's n. Step 7 routes it
    // through a doubling. It is reachable, since u1 = h * s^-1 and an adversary
    // picks h and s. It must be recomputed if the window width or count changes.
    // k_bad = 0xe0000000ffffffff00000000000000004319055258e8617b0c46353d039cdaaf
    component badEq[5];
    signal badAcc[5];
    badEq[0] = IsZero();
    badEq[0].in <== fold.out[0] - 884452912994769583;
    badAcc[0] <== badEq[0].out;
    badEq[1] = IsZero();
    badEq[1].in <== fold.out[1] - 4834901526196019579;
    badAcc[1] <== badAcc[0] * badEq[1].out;
    badEq[2] = IsZero();
    badEq[2].in <== fold.out[2] - 0;
    badAcc[2] <== badAcc[1] * badEq[2].out;
    badEq[3] = IsZero();
    badEq[3].in <== fold.out[3] - 16140901068790824959;
    badAcc[3] <== badAcc[2] * badEq[3].out;
    badEq[4] = IsZero();
    badEq[4].in <== fold.out[4] - 0;
    badAcc[4] <== badAcc[3] * badEq[4].out;
    signal useFinalDouble;
    useFinalDouble <== badAcc[4];

    // ---------- 4. the recoding: wires and XNOR only ----------
    // B[i] is the top sign bit of window i. For i = 21 the digit at position
    // 263 is always +1, so it is not read from any bit.
    signal B[22];
    for (var i = 0; i < 21; i++) { B[i] <== kb[12 * i + 12]; }
    B[21] <== 1;

    // Index bit t is 1 exactly when the lower sign matches the upper one:
    // idxbit = XNOR(kb[12i + t + 1], B[i]). One multiplication per bit.
    signal xn[22][11];
    signal idxbit[22][11];
    for (var i = 0; i < 22; i++) {
        for (var t = 0; t < 11; t++) {
            xn[i][t] <== kb[12 * i + t + 1] * B[i];
            idxbit[i][t] <== 1 - kb[12 * i + t + 1] - B[i] + 2 * xn[i][t];
        }
    }

    // ---------- 5. table lookup ----------
    // Each window has its own table, hence its own template; an array of
    // components would require the same template throughout. A window outputs
    // x in out[0..7] and y in out[8..15].
    signal Tx[22][8];
    signal Ty[22][8];
    component win0 = P256CombWindow0();
    for (var t = 0; t < 11; t++) { win0.sel[t] <== idxbit[0][t]; }
    for (var j = 0; j < 8; j++) { Tx[0][j] <== win0.out[j]; Ty[0][j] <== win0.out[8 + j]; }
    component win1 = P256CombWindow1();
    for (var t = 0; t < 11; t++) { win1.sel[t] <== idxbit[1][t]; }
    for (var j = 0; j < 8; j++) { Tx[1][j] <== win1.out[j]; Ty[1][j] <== win1.out[8 + j]; }
    component win2 = P256CombWindow2();
    for (var t = 0; t < 11; t++) { win2.sel[t] <== idxbit[2][t]; }
    for (var j = 0; j < 8; j++) { Tx[2][j] <== win2.out[j]; Ty[2][j] <== win2.out[8 + j]; }
    component win3 = P256CombWindow3();
    for (var t = 0; t < 11; t++) { win3.sel[t] <== idxbit[3][t]; }
    for (var j = 0; j < 8; j++) { Tx[3][j] <== win3.out[j]; Ty[3][j] <== win3.out[8 + j]; }
    component win4 = P256CombWindow4();
    for (var t = 0; t < 11; t++) { win4.sel[t] <== idxbit[4][t]; }
    for (var j = 0; j < 8; j++) { Tx[4][j] <== win4.out[j]; Ty[4][j] <== win4.out[8 + j]; }
    component win5 = P256CombWindow5();
    for (var t = 0; t < 11; t++) { win5.sel[t] <== idxbit[5][t]; }
    for (var j = 0; j < 8; j++) { Tx[5][j] <== win5.out[j]; Ty[5][j] <== win5.out[8 + j]; }
    component win6 = P256CombWindow6();
    for (var t = 0; t < 11; t++) { win6.sel[t] <== idxbit[6][t]; }
    for (var j = 0; j < 8; j++) { Tx[6][j] <== win6.out[j]; Ty[6][j] <== win6.out[8 + j]; }
    component win7 = P256CombWindow7();
    for (var t = 0; t < 11; t++) { win7.sel[t] <== idxbit[7][t]; }
    for (var j = 0; j < 8; j++) { Tx[7][j] <== win7.out[j]; Ty[7][j] <== win7.out[8 + j]; }
    component win8 = P256CombWindow8();
    for (var t = 0; t < 11; t++) { win8.sel[t] <== idxbit[8][t]; }
    for (var j = 0; j < 8; j++) { Tx[8][j] <== win8.out[j]; Ty[8][j] <== win8.out[8 + j]; }
    component win9 = P256CombWindow9();
    for (var t = 0; t < 11; t++) { win9.sel[t] <== idxbit[9][t]; }
    for (var j = 0; j < 8; j++) { Tx[9][j] <== win9.out[j]; Ty[9][j] <== win9.out[8 + j]; }
    component win10 = P256CombWindow10();
    for (var t = 0; t < 11; t++) { win10.sel[t] <== idxbit[10][t]; }
    for (var j = 0; j < 8; j++) { Tx[10][j] <== win10.out[j]; Ty[10][j] <== win10.out[8 + j]; }
    component win11 = P256CombWindow11();
    for (var t = 0; t < 11; t++) { win11.sel[t] <== idxbit[11][t]; }
    for (var j = 0; j < 8; j++) { Tx[11][j] <== win11.out[j]; Ty[11][j] <== win11.out[8 + j]; }
    component win12 = P256CombWindow12();
    for (var t = 0; t < 11; t++) { win12.sel[t] <== idxbit[12][t]; }
    for (var j = 0; j < 8; j++) { Tx[12][j] <== win12.out[j]; Ty[12][j] <== win12.out[8 + j]; }
    component win13 = P256CombWindow13();
    for (var t = 0; t < 11; t++) { win13.sel[t] <== idxbit[13][t]; }
    for (var j = 0; j < 8; j++) { Tx[13][j] <== win13.out[j]; Ty[13][j] <== win13.out[8 + j]; }
    component win14 = P256CombWindow14();
    for (var t = 0; t < 11; t++) { win14.sel[t] <== idxbit[14][t]; }
    for (var j = 0; j < 8; j++) { Tx[14][j] <== win14.out[j]; Ty[14][j] <== win14.out[8 + j]; }
    component win15 = P256CombWindow15();
    for (var t = 0; t < 11; t++) { win15.sel[t] <== idxbit[15][t]; }
    for (var j = 0; j < 8; j++) { Tx[15][j] <== win15.out[j]; Ty[15][j] <== win15.out[8 + j]; }
    component win16 = P256CombWindow16();
    for (var t = 0; t < 11; t++) { win16.sel[t] <== idxbit[16][t]; }
    for (var j = 0; j < 8; j++) { Tx[16][j] <== win16.out[j]; Ty[16][j] <== win16.out[8 + j]; }
    component win17 = P256CombWindow17();
    for (var t = 0; t < 11; t++) { win17.sel[t] <== idxbit[17][t]; }
    for (var j = 0; j < 8; j++) { Tx[17][j] <== win17.out[j]; Ty[17][j] <== win17.out[8 + j]; }
    component win18 = P256CombWindow18();
    for (var t = 0; t < 11; t++) { win18.sel[t] <== idxbit[18][t]; }
    for (var j = 0; j < 8; j++) { Tx[18][j] <== win18.out[j]; Ty[18][j] <== win18.out[8 + j]; }
    component win19 = P256CombWindow19();
    for (var t = 0; t < 11; t++) { win19.sel[t] <== idxbit[19][t]; }
    for (var j = 0; j < 8; j++) { Tx[19][j] <== win19.out[j]; Ty[19][j] <== win19.out[8 + j]; }
    component win20 = P256CombWindow20();
    for (var t = 0; t < 11; t++) { win20.sel[t] <== idxbit[20][t]; }
    for (var j = 0; j < 8; j++) { Tx[20][j] <== win20.out[j]; Ty[20][j] <== win20.out[8 + j]; }
    component win21 = P256CombWindow21();
    for (var t = 0; t < 11; t++) { win21.sel[t] <== idxbit[21][t]; }
    for (var j = 0; j < 8; j++) { Tx[21][j] <== win21.out[j]; Ty[21][j] <== win21.out[8 + j]; }

    // ---------- 6. conditional negation ----------
    // An upper sign of -1 selects the opposite point (x, p - y). P-256 has
    // prime order, so y != 0 for every table entry and p - y stays in [1, p-1].
    component negy[22];
    signal pick[22][8];
    signal Py[22][8];
    for (var i = 0; i < 22; i++) {
        negy[i] = BigSub(32, 8);
        for (var j = 0; j < 8; j++) {
            negy[i].a[j] <== prime[j];
            negy[i].b[j] <== Ty[i][j];
        }
        for (var j = 0; j < 8; j++) {
            pick[i][j] <== B[i] * (Ty[i][j] - negy[i].out[j]);
            Py[i][j] <== negy[i].out[j] + pick[i][j];
        }
    }

    // ---------- 7. accumulation ----------
    // Sequential, window 0 initialises the accumulator. The one equal-point
    // case occurs in the final addition: both operands are replaced by fixed
    // distinct-x points there, and the output is taken from a doubling of the
    // accumulator instead.
    var safe[2][100] = get_p256_dummy_point(32, 8);
    var safeGx[100] = get_p256_gx(32, 8);
    var safeGy[100] = get_p256_gy(32, 8);
    component acc[21];
    for (var i = 0; i < 21; i++) {
        acc[i] = P256AddUnequal();
        for (var j = 0; j < 8; j++) {
            if (i == 0) {
                acc[i].a[0][j] <== Tx[0][j];
                acc[i].a[1][j] <== Py[0][j];
            } else if (i == 20) {
                acc[i].a[0][j] <== acc[i - 1].out[0][j]
                    + useFinalDouble * (safe[0][j] - acc[i - 1].out[0][j]);
                acc[i].a[1][j] <== acc[i - 1].out[1][j]
                    + useFinalDouble * (safe[1][j] - acc[i - 1].out[1][j]);
            } else {
                acc[i].a[0][j] <== acc[i - 1].out[0][j];
                acc[i].a[1][j] <== acc[i - 1].out[1][j];
            }
            if (i == 20) {
                acc[i].b[0][j] <== Tx[i + 1][j]
                    + useFinalDouble * (safeGx[j] - Tx[i + 1][j]);
                acc[i].b[1][j] <== Py[i + 1][j]
                    + useFinalDouble * (safeGy[j] - Py[i + 1][j]);
            } else {
                acc[i].b[0][j] <== Tx[i + 1][j];
                acc[i].b[1][j] <== Py[i + 1][j];
            }
        }
    }

    component finalDouble = P256Double();
    for (var j = 0; j < 8; j++) {
        finalDouble.in[0][j] <== acc[19].out[0][j];
        finalDouble.in[1][j] <== acc[19].out[1][j];
    }

    for (var j = 0; j < 8; j++) {
        out[0][j] <== acc[20].out[0][j]
            + useFinalDouble * (finalDouble.out[0][j] - acc[20].out[0][j]);
        out[1][j] <== acc[20].out[1][j]
            + useFinalDouble * (finalDouble.out[1][j] - acc[20].out[1][j]);
    }
}
