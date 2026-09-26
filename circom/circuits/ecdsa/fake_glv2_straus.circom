pragma circom 2.0.2;

/*
    2-dimensional Straus loop closing a fake-GLV check on P-256.

    Proves [e0]A0 + [e1]A1 == O for the bits e0, e1 of two 128-bit
    magnitudes, with the signs already folded into the bases. Both scalars are
    read two bits at a time, which gives the loop the same shape as the
    4-dimensional one on secp256k1: a 16-entry table and 64 steps. The table
    is offset by a sentinel D, so no entry and no intermediate accumulator is
    the point at infinity:

        T[d0 + 4*d1] = D + d0*A0 + d1*A1,   d0, d1 in {0, 1, 2, 3}

    Each step computes acc = 2*(2*acc) + T[d]: one doubling, then the second
    doubling and the addition fused into one P256DoubleAddStrict.
    After nbits/2 steps the accumulator holds
    ((4^(nbits/2) - 1)/3)*D + [e0]A0 + [e1]A1. That sum must be O, so the
    terminal check is a plain equality against the constant
    C = ((2^nbits - 1)/3)*D.

    Points are eight 32-bit limbs per coordinate.

    The technique follows the public description of rot256's (Mathias
    Hall-Andersen) submission to the zk.golf secp256k1 scalar multiplication
    challenge, reduced to two dimensions. No code was copied.
*/

include "./p256.circom";
include "../../circomlib/circuits/mux4.circom";

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

// C = ((2^128 - 1)/3)*D, the target of the terminal assertion. It depends on
// nbits, which is why FakeGLV2StrausLoop asserts nbits == 128.
// 0xc03069531ba69674085e8cb527d1133d96987a53fdb5a86dbd4d257d24faedf2
function get_glv2_target_x() {
    var ret[8];
    ret[0] = 620424690;
    ret[1] = 3175949693;
    ret[2] = 4256540781;
    ret[3] = 2526575187;
    ret[4] = 668013373;
    ret[5] = 140414133;
    ret[6] = 463902324;
    ret[7] = 3224398163;
    return ret;
}

// 0x5bca673dab486c1b275ce6867a828d75663eb5d78c3fd23bbd15ed565af092c8
function get_glv2_target_y() {
    var ret[8];
    ret[0] = 1525715656;
    ret[1] = 3172330838;
    ret[2] = 2352992827;
    ret[3] = 1715385815;
    ret[4] = 2055376245;
    ret[5] = 660399750;
    ret[6] = 2873650203;
    ret[7] = 1539991357;
    return ret;
}

// bits[i][j] = bit j of magnitude i, little-endian. A[i] = base i with its
// sign folded in. No output: closes on the assertion acc == C.
template FakeGLV2StrausLoop(nbits) {
    assert(nbits == 128);
    var nsteps = nbits \ 2;

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

    // ---------- the table: 16 entries, 15 additions ----------
    // T[4*d1] = T[4*(d1 - 1)] + A1; otherwise T[d] = T[d - 1] + A0
    signal T[16][2][8];
    for (var j = 0; j < 8; j++) {
        T[0][0][j] <== Dx[j];
        T[0][1][j] <== Dy[j];
    }
    component tab[16];
    for (var d = 1; d < 16; d++) {
        var prev = d - 1;
        var base = 0;
        if (d % 4 == 0) { prev = d - 4; base = 1; }
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

    // ---------- the loop: nsteps steps, one double + one double-add each ----------
    component sel[nsteps];
    component dbl[nsteps - 1];
    component dadd[nsteps - 1];
    signal acc[nsteps][2][8];

    for (var i = nsteps - 1; i >= 0; i--) {
        sel[i] = MultiMux4(16);
        for (var d = 0; d < 16; d++) {
            for (var c = 0; c < 2; c++) {
                for (var j = 0; j < 8; j++) {
                    sel[i].c[c * 8 + j][d] <== T[d][c][j];
                }
            }
        }
        // Selector index d0 + 4*d1, with d0 and d1 the two-bit digits of
        // e0 and e1 at this step.
        sel[i].s[0] <== bits[0][2 * i];
        sel[i].s[1] <== bits[0][2 * i + 1];
        sel[i].s[2] <== bits[1][2 * i];
        sel[i].s[3] <== bits[1][2 * i + 1];

        if (i == nsteps - 1) {
            for (var c = 0; c < 2; c++) {
                for (var j = 0; j < 8; j++) {
                    acc[i][c][j] <== sel[i].out[c * 8 + j];
                }
            }
        } else {
            dbl[i] = P256Double();
            dadd[i] = P256DoubleAddStrict();
            for (var c = 0; c < 2; c++) {
                for (var j = 0; j < 8; j++) {
                    dbl[i].in[c][j] <== acc[i + 1][c][j];
                }
            }
            for (var c = 0; c < 2; c++) {
                for (var j = 0; j < 8; j++) {
                    dadd[i].a[c][j] <== dbl[i].out[c][j];
                    dadd[i].b[c][j] <== sel[i].out[c * 8 + j];
                }
            }
            for (var c = 0; c < 2; c++) {
                for (var j = 0; j < 8; j++) {
                    acc[i][c][j] <== dadd[i].out[c][j];
                }
            }
        }
    }

    // ---------- terminal assertion: acc == ((2^nbits - 1)/3)*D ----------
    var Cx[8] = get_glv2_target_x();
    var Cy[8] = get_glv2_target_y();
    for (var j = 0; j < 8; j++) {
        acc[0][0][j] === Cx[j];
        acc[0][1][j] === Cy[j];
    }
}
