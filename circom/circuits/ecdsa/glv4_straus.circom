/*
    4-dimensional Straus loop for fake-GLV on secp256k1.

    The technique is taken from the public description of rot256's (Mathias
    Hall-Andersen) submission to the zk.golf secp256k1 scalar multiplication
    challenge. No code was copied.

    Instead of computing [s]P, a relation is proved: Q is witnessed, the prover
    supplies four small scalars with

        u1 + u2*lambda  ==  s * (v1 + v2*lambda)   (mod n)

    and the circuit checks the point identity

        [u1]P + [u2]phi(P) - [v1]Q - [v2]phi(Q)  ==  O

    (u1, u2, v1, v2) live in the lattice

        L = { x in Z^4 : x1 + x2*L - s*x3 - s*L*x4 == 0 (mod n) },  det L = n

    whose shortest vector in dimension 4 is of order n^(1/4) ~ 2^64: four
    64-bit scalars instead of two 128-bit ones, so half the loop, at the price
    of a 16-entry table instead of 4.

    The table is offset by a sentinel D:

        T[d] = D + d0*A0 + d1*A1 + d2*A2 + d3*A3,   d = sum d_i * 2^i

    After nbits steps the accumulator holds (2^nbits - 1)*D + sum_i [e_i] A_i.
    Since that sum must be O, the accumulator has to equal the constant point
    C = (2^nbits - 1)*D, so the terminal assertion is a plain equality against
    a constant. (rot256: "closed by an =O assertion".)

    D is public with a known discrete logarithm, so inputs can be chosen to
    make a table entry or an intermediate accumulator equal to O, or to make
    an addition a doubling. The table and the accumulator therefore use
    complete group operations with an explicit infinity flag; an entry or an
    accumulator may be O and later become finite again. Only the final
    accumulator is required to be finite.

    The bases must be valid canonical finite points: the equality selectors
    of the complete addition compare limbs.

    Points are eight 32-bit limbs per coordinate. The constants below are
    kept in 64-bit limbs and split at compile time.
*/
pragma circom 2.0.2;

include "./secp256k1_complete.circom";
include "../../circomlib/circuits/mux4.circom";

// D = [12345678901234567890]G, the table sentinel.
// 0x99c126da20397558f23658764c3a7c583db7ff706e93981cc170e27ca8336201
function get_glv4_sentinel_x() {
    var ret[4];
    ret[0] = 13938889871737446913;
    ret[1] = 4447304015408240668;
    ret[2] = 17453234671029222488;
    ret[3] = 11079179276593493336;
    return ret;
}

// 0x3751007f028f021b4a1ff42ac6d29166c6bce10f5ccb2ea5370f7f5ba5b7296c
function get_glv4_sentinel_y() {
    var ret[4];
    ret[0] = 3967529828335692140;
    ret[1] = 14320568371228913317;
    ret[2] = 5341256147646189926;
    ret[3] = 3985967690703372827;
    return ret;
}

// C = (2^64 - 1)*D, the target of the terminal assertion.
// Depends on nbits: a different nbits requires regenerating this constant,
// which is why GLV4StrausLoop asserts nbits == 64 at compile time.
// 0xd45b2884575abd9c6ad810fb2d9c7f8cd575e1c8521870ea9e7635525f4b2355
function get_glv4_target_x() {
    var ret[4];
    ret[0] = 11418372533146821461;
    ret[1] = 15381448352840839402;
    ret[2] = 7698922233977929612;
    ret[3] = 15301868707787750812;
    return ret;
}

// 0xdb2d19b1b590cfe34f811e88b8f2db719e443f9a3687964ee8131c2dd0d534be
function get_glv4_target_y() {
    var ret[4];
    ret[0] = 16722740824459523262;
    ret[1] = 11404310087981307470;
    ret[2] = 5728893773559290737;
    ret[3] = 15793307719304269795;
    return ret;
}

// bits[i][j] = bit j of scalar i (little-endian). A[i] = base i, with the sign
// already folded into the point. No output: closes on the assertion acc == C.
template GLV4StrausLoop(nbits) {
    // The constant C above is computed for 64. Any other nbits requires
    // regenerating it, so the failure has to happen at compile time.
    assert(nbits == 64);

    signal input bits[4][nbits];
    signal input A[4][2][8];

    var Dx[100] = p256_split64to32(get_glv4_sentinel_x());
    var Dy[100] = p256_split64to32(get_glv4_sentinel_y());

    // ---------- the bases have to be canonical ----------
    // The equality selectors compare limbs, so representations must be
    // unique. The ECDSA caller supplies canonical coordinates, but this
    // template should not depend on what the caller does.
    component baseRange[4][2];
    for (var b = 0; b < 4; b++) {
        for (var c = 0; c < 2; c++) {
            baseRange[b][c] = CheckInRangeSecp256k1Limbs32();
            for (var j = 0; j < 8; j++) baseRange[b][c].in[j] <== A[b][c][j];
        }
    }

    // ---------- the table: 16 entries, 15 additions ----------
    // T[d] = T[d without its lowest set bit] + A[index of that bit], so every
    // new entry costs exactly one addition.
    signal T[16][2][8];
    signal TInf[16];
    for (var j = 0; j < 8; j++) {
        T[0][0][j] <== Dx[j];
        T[0][1][j] <== Dy[j];
    }
    TInf[0] <== 0;

    component tab[16];
    for (var d = 1; d < 16; d++) {
        // index of the lowest set bit of d, and d without that bit
        var lowidx = 0;
        var pow = 1;
        while ((d \ pow) % 2 == 0) {
            pow = pow * 2;
            lowidx = lowidx + 1;
        }
        var prev = d - pow;

        tab[d] = Secp256k1AddComplete();
        tab[d].aInf <== TInf[prev];
        tab[d].bInf <== 0;
        for (var c = 0; c < 2; c++) {
            for (var j = 0; j < 8; j++) {
                tab[d].a[c][j] <== T[prev][c][j];
                tab[d].b[c][j] <== A[lowidx][c][j];
            }
        }
        for (var c = 0; c < 2; c++) {
            for (var j = 0; j < 8; j++) {
                T[d][c][j] <== tab[d].out[c][j];
            }
        }
        TInf[d] <== tab[d].outInf;
    }

    // ---------- the loop: nbits steps, one double + one add each ----------
    // The selector also carries the infinity flag of the entry. The bits are
    // Boolean, so the selected entry is exactly one table row.
    component sel[nbits];
    component dbl[nbits - 1];
    component adder[nbits - 1];
    signal acc[nbits][2][8];
    signal accInf[nbits];

    for (var i = nbits - 1; i >= 0; i--) {
        sel[i] = MultiMux4(17);
        for (var d = 0; d < 16; d++) {
            for (var c = 0; c < 2; c++) {
                for (var j = 0; j < 8; j++) {
                    sel[i].c[c * 8 + j][d] <== T[d][c][j];
                }
            }
            sel[i].c[16][d] <== TInf[d];
        }
        for (var b = 0; b < 4; b++) {
            sel[i].s[b] <== bits[b][i];
        }

        if (i == nbits - 1) {
            for (var c = 0; c < 2; c++) {
                for (var j = 0; j < 8; j++) {
                    acc[i][c][j] <== sel[i].out[c * 8 + j];
                }
            }
            accInf[i] <== sel[i].out[16];
        } else {
            dbl[i] = Secp256k1DoubleComplete();
            adder[i] = Secp256k1AddComplete();

            dbl[i].inInf <== accInf[i + 1];
            for (var c = 0; c < 2; c++) {
                for (var j = 0; j < 8; j++) {
                    dbl[i].in[c][j] <== acc[i + 1][c][j];
                }
            }
            adder[i].aInf <== dbl[i].outInf;
            adder[i].bInf <== sel[i].out[16];
            for (var c = 0; c < 2; c++) {
                for (var j = 0; j < 8; j++) {
                    adder[i].a[c][j] <== dbl[i].out[c][j];
                    adder[i].b[c][j] <== sel[i].out[c * 8 + j];
                }
            }
            for (var c = 0; c < 2; c++) {
                for (var j = 0; j < 8; j++) {
                    acc[i][c][j] <== adder[i].out[c][j];
                }
            }
            accInf[i] <== adder[i].outInf;
        }
    }

    // ---------- terminal assertion: acc == (2^nbits - 1)*D ----------
    // C is finite, so the final accumulator must be finite as well.
    var Cx[100] = p256_split64to32(get_glv4_target_x());
    var Cy[100] = p256_split64to32(get_glv4_target_y());
    accInf[0] === 0;
    for (var j = 0; j < 8; j++) {
        acc[0][0][j] === Cx[j];
        acc[0][1][j] === Cy[j];
    }
}
