pragma circom 2.0.2;

/*
    2-dimensional Straus loop closing a fake-GLV check on P-256.

    Proves [e0]A0 + [e1]A1 == O for the bits e0, e1 of two 128-bit
    magnitudes, with the signs already folded into the bases. The table is
    offset by a sentinel D, so no entry and no intermediate accumulator is the
    point at infinity:

        T[d] = D + d0*A0 + d1*A1,   d = d0 + 2*d1

    After nbits steps the accumulator holds (2^nbits - 1)*D + [e0]A0 + [e1]A1.
    That sum must be O, so the terminal check is a plain equality against the
    constant C = (2^nbits - 1)*D.

    Points are eight 32-bit limbs per coordinate.

    The technique follows the public description of rot256's (Mathias
    Hall-Andersen) submission to the zk.golf secp256k1 scalar multiplication
    challenge, reduced to two dimensions. No code was copied.
*/

include "./p256.circom";
include "../../circomlib/circuits/mux2.circom";

// D = [12345678901234567890]G, the table sentinel.
// 0x3ed7a28ec648edce5d5b7e252f6b2aafbb44835114a24b3caa8f710f64993bc2
function get_glv2_sentinel_x() {
    var ret[8];
    ret[0] = 1687763906;
    ret[1] = 2861527311;
    ret[2] = 346180412;
    ret[3] = 3141829457;
    ret[4] = 795552431;
    ret[5] = 1566277157;
    ret[6] = 3326668238;
    ret[7] = 1054319246;
    return ret;
}

// 0x5711a34cdc9229080b639f09977feb7ca91ecce1649bfea8ad85c72b206ade7e
function get_glv2_sentinel_y() {
    var ret[8];
    ret[0] = 543874686;
    ret[1] = 2911225643;
    ret[2] = 1687944872;
    ret[3] = 2837368033;
    ret[4] = 2541742972;
    ret[5] = 191078153;
    ret[6] = 3700566280;
    ret[7] = 1460773708;
    return ret;
}

// C = (2^128 - 1)*D, the target of the terminal assertion. It depends on
// nbits, which is why FakeGLV2StrausLoop asserts nbits == 128.
// 0x7e8ac0843a1090bd43a548fb232218b8f204af2a426ac8e2731b8e83f771d9fc
function get_glv2_target_x() {
    var ret[8];
    ret[0] = 4151433724;
    ret[1] = 1931185795;
    ret[2] = 1114294498;
    ret[3] = 4060393258;
    ret[4] = 589437112;
    ret[5] = 1134905595;
    ret[6] = 974164157;
    ret[7] = 2123022468;
    return ret;
}

// 0x12a981a361dc7854864b4b063efa6c6d126f67413f5ae0b241bc21c498693665
function get_glv2_target_y() {
    var ret[8];
    ret[0] = 2557032037;
    ret[1] = 1102848452;
    ret[2] = 1062920370;
    ret[3] = 309290817;
    ret[4] = 1056599149;
    ret[5] = 2253081350;
    ret[6] = 1641838676;
    ret[7] = 313098659;
    return ret;
}

// bits[i][j] = bit j of magnitude i, little-endian. A[i] = base i with its
// sign folded in. No output: closes on the assertion acc == C.
template FakeGLV2StrausLoop(nbits) {
    assert(nbits == 128);

    signal input bits[2][nbits];
    signal input A[2][2][8];

    var Dx[8] = get_glv2_sentinel_x();
    var Dy[8] = get_glv2_sentinel_y();

    // The distinct-x guards compare limbs, so the bases must be canonical.
    component baseRange[2];
    for (var b = 0; b < 2; b++) {
        baseRange[b] = CheckInRangeP256();
        for (var j = 0; j < 8; j++) { baseRange[b].in[j] <== A[b][0][j]; }
    }

    // ---------- the table: 4 entries, 3 additions ----------
    // T[1] = D + A0, T[2] = D + A1, T[3] = T[2] + A0
    signal T[4][2][8];
    for (var j = 0; j < 8; j++) {
        T[0][0][j] <== Dx[j];
        T[0][1][j] <== Dy[j];
    }
    component tab[4];
    for (var d = 1; d < 4; d++) {
        var prev = 0;
        var base = 0;
        if (d == 2) { base = 1; }
        if (d == 3) { prev = 2; }
        tab[d] = P256AddStrict();
        for (var c = 0; c < 2; c++) {
            for (var j = 0; j < 8; j++) {
                tab[d].a[c][j] <== T[prev][c][j];
                tab[d].b[c][j] <== A[base][c][j];
            }
        }
        for (var c = 0; c < 2; c++) {
            for (var j = 0; j < 8; j++) {
                T[d][c][j] <== tab[d].out[c][j];
            }
        }
    }

    // ---------- the loop: nbits steps, one double + one add each ----------
    component sel[nbits];
    component dbl[nbits - 1];
    component adder[nbits - 1];
    signal acc[nbits][2][8];

    for (var i = nbits - 1; i >= 0; i--) {
        sel[i] = MultiMux2(16);
        for (var d = 0; d < 4; d++) {
            for (var c = 0; c < 2; c++) {
                for (var j = 0; j < 8; j++) {
                    sel[i].c[c * 8 + j][d] <== T[d][c][j];
                }
            }
        }
        sel[i].s[0] <== bits[0][i];
        sel[i].s[1] <== bits[1][i];

        if (i == nbits - 1) {
            for (var c = 0; c < 2; c++) {
                for (var j = 0; j < 8; j++) {
                    acc[i][c][j] <== sel[i].out[c * 8 + j];
                }
            }
        } else {
            dbl[i] = P256Double();
            adder[i] = P256AddStrict();
            for (var c = 0; c < 2; c++) {
                for (var j = 0; j < 8; j++) {
                    dbl[i].in[c][j] <== acc[i + 1][c][j];
                }
            }
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
        }
    }

    // ---------- terminal assertion: acc == (2^nbits - 1)*D ----------
    var Cx[8] = get_glv2_target_x();
    var Cy[8] = get_glv2_target_y();
    for (var j = 0; j < 8; j++) {
        acc[0][0][j] === Cx[j];
        acc[0][1][j] === Cy[j];
    }
}
