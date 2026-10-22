pragma circom 2.2.3;

// Adapted from circom/circuits/sha256/sha256_compression.circom.
// Word additions and constants use segments that fit in KoalaBear.

include "../bitwise.circom";
include "add_words.circom";
include "constants.circom";

// Little-endian bits within each word. Inputs must already be boolean.
template Sha256Sigma(R0, R1, R2, SHIFT) {
    signal input in[32];
    signal output out[32];
    component parity = Xor3Bits(32);
    for (var i = 0; i < 32; i++) {
        parity.a[i] <== in[(i + R0) % 32];
        parity.b[i] <== in[(i + R1) % 32];
        if (SHIFT && i + R2 >= 32) {
            parity.c[i] <== 0;
        } else {
            parity.c[i] <== in[(i + R2) % 32];
        }
    }
    out <== parity.out;
}

template Sha256Compression() {
    signal input block[16][32];
    signal input state[8][32];
    signal output out[8][32];
    signal w[64][32];
    signal s[65][8][32];
    component scheduleSigma0[48];
    component scheduleSigma1[48];
    component scheduleSum[48];
    for (var t = 0; t < 64; t++) {
        if (t < 16) {
            w[t] <== block[t];
        } else {
            scheduleSigma0[t-16] = Sha256Sigma(7, 18, 3, 1);
            scheduleSigma1[t-16] = Sha256Sigma(17, 19, 10, 1);
            scheduleSigma0[t-16].in <== w[t-15];
            scheduleSigma1[t-16].in <== w[t-2];
            scheduleSum[t-16] = AddWords32(4);
            scheduleSum[t-16].in[0] <== scheduleSigma0[t-16].out;
            scheduleSum[t-16].in[1] <== scheduleSigma1[t-16].out;
            scheduleSum[t-16].in[2] <== w[t-7];
            scheduleSum[t-16].in[3] <== w[t-16];
            w[t] <== scheduleSum[t-16].out;
        }
    }

    s[0] <== state;
    component sigma0[64];
    component sigma1[64];
    component majority[64];
    component sumE[64];
    component sumA[64];
    signal choice[64][32];
    for (var t = 0; t < 64; t++) {
        sigma0[t] = Sha256Sigma(2, 13, 22, 0);
        sigma1[t] = Sha256Sigma(6, 11, 25, 0);
        majority[t] = MajorityBits(32);
        sigma0[t].in <== s[t][0];
        sigma1[t].in <== s[t][4];
        majority[t].a <== s[t][0];
        majority[t].b <== s[t][1];
        majority[t].c <== s[t][2];
        sumE[t] = AddWords32(6);
        sumA[t] = AddWords32(5);
        for (var j = 0; j < 32; j++) {
            choice[t][j] <== s[t][4][j] * (s[t][5][j] - s[t][6][j]) + s[t][6][j];
            sumE[t].in[0][j] <== Sha256RoundBit(t, j);
            sumE[t].in[1][j] <== s[t][3][j];
            sumE[t].in[2][j] <== s[t][7][j];
            sumE[t].in[3][j] <== sigma1[t].out[j];
            sumE[t].in[4][j] <== choice[t][j];
            sumE[t].in[5][j] <== w[t][j];
        }
        // new_a = new_e - d + Sigma0(a) + Maj modulo 2^32.
        for (var j = 0; j < 32; j++) {
            sumA[t].in[0][j] <== sumE[t].out[j];
            sumA[t].in[1][j] <== 1 - s[t][3][j];
            sumA[t].in[2][j] <== sigma0[t].out[j];
            sumA[t].in[3][j] <== majority[t].out[j];
            sumA[t].in[4][j] <== j == 0;
        }
        for (var j = 0; j < 32; j++) {
            s[t+1][0][j] <== sumA[t].out[j];
            s[t+1][4][j] <== sumE[t].out[j];
        }
        for (var lane = 1; lane < 8; lane++) {
            if (lane != 4) s[t+1][lane] <== s[t][lane-1];
        }
    }

    component feedForward[8];
    for (var lane = 0; lane < 8; lane++) {
        feedForward[lane] = AddWords32(2);
        feedForward[lane].in[0] <== state[lane];
        feedForward[lane].in[1] <== s[64][lane];
        out[lane] <== feedForward[lane].out;
    }
}
