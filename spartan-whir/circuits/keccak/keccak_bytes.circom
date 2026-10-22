pragma circom 2.2.3;

include "keccak_f1600.circom";
include "../bits.circom";

// Keccak-256: 1088-bit rate, 512-bit capacity, pad10*1 (suffix 0x01).
template Keccak_256_bytes(N) {
    signal input inp_bytes[N];
    signal output out_bytes[32];
    var blocks = (N \ 136) + 1;
    component bytes[N];
    signal padded[blocks*1088];
    for (var i = 0; i < N; i++) {
        bytes[i] = SmallNum2Bits(8);
        bytes[i].in <== inp_bytes[i];
        for (var j = 0; j < 8; j++) padded[8*i+j] <== bytes[i].out[j];
    }
    for (var i = N*8; i < blocks*1088; i++) {
        if (i == N*8 || i == blocks*1088-1) {
            padded[i] <== 1;
        } else {
            padded[i] <== 0;
        }
    }
    component permutation[blocks];
    for (var b = 0; b < blocks; b++) {
        permutation[b] = KeccakF1600();
        for (var i = 0; i < 1600; i++) {
            if (b == 0) {
                if (i < 1088) {
                    permutation[b].in[i] <== padded[i];
                } else {
                    permutation[b].in[i] <== 0;
                }
            } else {
                if (i < 1088) {
                    permutation[b].in[i] <== permutation[b-1].out[i] + padded[b*1088+i]
                        - 2*permutation[b-1].out[i]*padded[b*1088+i];
                } else {
                    permutation[b].in[i] <== permutation[b-1].out[i];
                }
            }
        }
    }
    for (var i = 0; i < 32; i++) {
        var byte = 0;
        for (var j = 0; j < 8; j++) byte += permutation[blocks-1].out[8*i+j] * 2**j;
        out_bytes[i] <== byte;
    }
}
