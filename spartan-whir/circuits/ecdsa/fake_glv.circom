pragma circom 2.2.0;

include "fused.circom";
include "fake_glv_constants.circom";
include "../../../circom/circomlib/circuits/mux4.circom";

template KbFakeGlvAdvance(p256) {
    signal input a[2][22];
    signal input b[2][22];
    signal input aInf;
    signal input bInf;
    signal output out[2][22];
    signal output outInf;
    if (p256 == 1) {
        component quad = KbPointQuadAdd(p256);
        quad.aInf <== aInf; quad.bInf <== bInf;
        for (var c = 0; c < 2; c++) {
            for (var j = 0; j < 22; j++) {
                quad.a[c][j] <== a[c][j]; quad.b[c][j] <== b[c][j];
            }
        }
        outInf <== quad.outInf;
        for (var c = 0; c < 2; c++) {
            for (var j = 0; j < 22; j++) out[c][j] <== quad.out[c][j];
        }
    } else {
        component fused = KbPointDoubleAdd(p256);
        fused.aInf <== aInf; fused.bInf <== bInf;
        for (var c = 0; c < 2; c++) {
            for (var j = 0; j < 22; j++) {
                fused.a[c][j] <== a[c][j]; fused.b[c][j] <== b[c][j];
            }
        }
        outInf <== fused.outInf;
        for (var c = 0; c < 2; c++) {
            for (var j = 0; j < 22; j++) out[c][j] <== fused.out[c][j];
        }
    }
}

// The signed residues and endomorphisms reduce the relation Q = [s]P to a
// 64-step Straus loop. P and Q must be canonical finite curve points, checked
// by the caller. The denominator residue is explicitly nonzero, so soundness
// does not depend on a lower bound for a shortest endomorphism lattice vector.
template KbFakeGlvVerify(p256) {
    var p[22] = ecdsa_prime(p256);
    var n[22] = ecdsa_order(p256);
    var dimensions = 4;
    var limbCount = 6;
    var topBits = 4;
    var nbits = 64;
    if (p256 == 1) {
        dimensions = 2;
        limbCount = 11;
        topBits = 8;
        nbits = 128;
    }
    signal input scalar[22];
    signal input P[2][22];
    signal input Q[2][22];
    // Uniform hint ABI: four magnitudes, eleven little-endian 12-bit limbs.
    // The unused k1 limbs and P-256 magnitudes/signs must be zero.
    signal input mag[4][11];
    signal input sgn[4];

    component scalarRange = KbCanonical(n);
    for (var j = 0; j < 22; j++) scalarRange.in[j] <== scalar[j];
    component range[dimensions][limbCount];
    component zero[dimensions];
    component negate[dimensions];
    signal bits[dimensions][nbits];
    signal residue[dimensions][22];
    for (var d = 0; d < 4; d++) {
        if (d < dimensions) {
            sgn[d] * (sgn[d] - 1) === 0;
            var total = 0;
            for (var j = 0; j < 11; j++) {
                if (j < limbCount) {
                    if (j == limbCount-1) range[d][j] = Num2Bits(topBits);
                    else range[d][j] = Num2Bits(12);
                    range[d][j].in <== mag[d][j];
                    var width = 12;
                    if (j == limbCount-1) width = topBits;
                    for (var b = 0; b < width; b++) bits[d][12*j+b] <== range[d][j].out[b];
                    total += mag[d][j];
                } else mag[d][j] === 0;
            }
            zero[d] = IsZero();
            zero[d].in <== total;
            sgn[d] * zero[d].out === 0;
            negate[d] = KbSub(n);
            for (var j = 0; j < 22; j++) {
                negate[d].a[j] <== 0;
                if (j < limbCount) negate[d].b[j] <== mag[d][j];
                else negate[d].b[j] <== 0;
            }
            for (var j = 0; j < 22; j++) {
                if (j < limbCount) residue[d][j] <== mag[d][j] + sgn[d] * (negate[d].out[j] - mag[d][j]);
                else residue[d][j] <== sgn[d] * negate[d].out[j];
            }
        } else {
            sgn[d] === 0;
            for (var j = 0; j < 11; j++) mag[d][j] === 0;
        }
    }

    signal numerator[22];
    signal denominator[22];
    signal base[dimensions][2][22];
    component negPy = KbSub(p);
    component negQy = KbSub(p);
    for (var j = 0; j < 22; j++) {
        negPy.a[j] <== 0; negPy.b[j] <== P[1][j];
        negQy.a[j] <== 0; negQy.b[j] <== Q[1][j];
    }
    if (p256 == 1) {
        for (var j = 0; j < 22; j++) {
            numerator[j] <== residue[0][j];
            denominator[j] <== residue[1][j];
            base[0][0][j] <== P[0][j];
            base[1][0][j] <== Q[0][j];
            base[0][1][j] <== P[1][j] + sgn[0] * (negPy.out[j] - P[1][j]);
            base[1][1][j] <== negQy.out[j] + sgn[1] * (Q[1][j] - negQy.out[j]);
        }
    } else {
        var lambda[22] = kb_glv_lambda();
        var beta[22] = kb_glv_beta();
        component bLambda = KbMul(n);
        component dLambda = KbMul(n);
        component numeratorAdd = KbAdd(n);
        component denominatorAdd = KbAdd(n);
        component phiPx = KbMul(p);
        component phiQx = KbMul(p);
        for (var j = 0; j < 22; j++) {
            bLambda.a[j] <== residue[1][j]; bLambda.b[j] <== lambda[j];
            dLambda.a[j] <== residue[3][j]; dLambda.b[j] <== lambda[j];
            phiPx.a[j] <== P[0][j]; phiPx.b[j] <== beta[j];
            phiQx.a[j] <== Q[0][j]; phiQx.b[j] <== beta[j];
        }
        for (var j = 0; j < 22; j++) {
            numeratorAdd.a[j] <== residue[0][j]; numeratorAdd.b[j] <== bLambda.out[j];
            denominatorAdd.a[j] <== residue[2][j]; denominatorAdd.b[j] <== dLambda.out[j];
        }
        for (var j = 0; j < 22; j++) {
            numerator[j] <== numeratorAdd.out[j];
            denominator[j] <== denominatorAdd.out[j];
            base[0][0][j] <== P[0][j];
            base[1][0][j] <== phiPx.out[j];
            base[2][0][j] <== Q[0][j];
            base[3][0][j] <== phiQx.out[j];
            base[0][1][j] <== P[1][j] + sgn[0] * (negPy.out[j] - P[1][j]);
            base[1][1][j] <== P[1][j] + sgn[1] * (negPy.out[j] - P[1][j]);
            base[2][1][j] <== negQy.out[j] + sgn[2] * (Q[1][j] - negQy.out[j]);
            base[3][1][j] <== negQy.out[j] + sgn[3] * (Q[1][j] - negQy.out[j]);
        }
    }
    component denominatorZero = IsZero();
    var denominatorSum = 0;
    for (var j = 0; j < 22; j++) denominatorSum += denominator[j];
    denominatorZero.in <== denominatorSum;
    denominatorZero.out === 0;
    component relation = KbMul(n);
    for (var j = 0; j < 22; j++) {
        relation.a[j] <== scalar[j]; relation.b[j] <== denominator[j];
    }
    for (var j = 0; j < 22; j++) relation.out[j] === numerator[j];

    // A sentinel keeps the terminal assertion finite. Table entries and all
    // intermediate accumulators may be infinity and use complete operations.
    // K1: T[d] = D + sum bit_d[i]*base[i], acc <- 2*acc+T[d].
    // P256: T[d0+4*d1] = D+d0*base[0]+d1*base[1], acc <- 4*acc+T[d].
    var sentinel[2][22] = kb_glv_sentinel(p256);
    var target[2][22] = kb_glv_target(p256);
    signal table[16][2][22];
    signal tableInf[16];
    tableInf[0] <== 0;
    for (var c = 0; c < 2; c++) {
        for (var j = 0; j < 22; j++) table[0][c][j] <== sentinel[c][j];
    }
    component tab[16];
    for (var d = 1; d < 16; d++) {
        var previous = d-1;
        var baseIndex = 0;
        if (p256 == 1) {
            if (d % 4 == 0) { previous = d-4; baseIndex = 1; }
        } else {
            var power = 1;
            while ((d \ power) % 2 == 0) { power *= 2; baseIndex++; }
            previous = d-power;
        }
        tab[d] = KbPointAdd(p256);
        tab[d].aInf <== tableInf[previous]; tab[d].bInf <== 0;
        for (var c = 0; c < 2; c++) {
            for (var j = 0; j < 22; j++) {
                tab[d].a[c][j] <== table[previous][c][j];
                tab[d].b[c][j] <== base[baseIndex][c][j];
            }
        }
        tableInf[d] <== tab[d].outInf;
        for (var c = 0; c < 2; c++) {
            for (var j = 0; j < 22; j++) table[d][c][j] <== tab[d].out[c][j];
        }
    }
    component select[64];
    component advance[63];
    signal accumulator[64][2][22];
    signal accumulatorInf[64];
    for (var step = 63; step >= 0; step--) {
        select[step] = MultiMux4(45);
        for (var d = 0; d < 16; d++) {
            for (var c = 0; c < 2; c++) {
                for (var j = 0; j < 22; j++) select[step].c[22*c+j][d] <== table[d][c][j];
            }
            select[step].c[44][d] <== tableInf[d];
        }
        for (var b = 0; b < 4; b++) {
            if (p256 == 1) select[step].s[b] <== bits[b \ 2][2*step+b % 2];
            else select[step].s[b] <== bits[b][step];
        }
        if (step == 63) {
            accumulatorInf[step] <== select[step].out[44];
            for (var c = 0; c < 2; c++) {
                for (var j = 0; j < 22; j++) accumulator[step][c][j] <== select[step].out[22*c+j];
            }
        } else {
            advance[step] = KbFakeGlvAdvance(p256);
            advance[step].aInf <== accumulatorInf[step+1];
            advance[step].bInf <== select[step].out[44];
            for (var c = 0; c < 2; c++) {
                for (var j = 0; j < 22; j++) {
                    advance[step].a[c][j] <== accumulator[step+1][c][j];
                    advance[step].b[c][j] <== select[step].out[22*c+j];
                }
            }
            accumulatorInf[step] <== advance[step].outInf;
            for (var c = 0; c < 2; c++) {
                for (var j = 0; j < 22; j++) accumulator[step][c][j] <== advance[step].out[c][j];
            }
        }
    }
    accumulatorInf[0] === 0;
    for (var c = 0; c < 2; c++) {
        for (var j = 0; j < 22; j++) accumulator[0][c][j] === target[c][j];
    }
}
