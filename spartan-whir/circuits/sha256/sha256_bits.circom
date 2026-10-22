pragma circom 2.2.3;

include "sha256_compression.circom";
include "constants.circom";

// Fixed-length SHA-256, with message and digest bits in big-endian order.
// The byte wrapper constrains the input bits.
template Sha256(NBITS) {
    signal input in[NBITS];
    signal output out[256];
    var blocks = ((NBITS + 64) \ 512) + 1;
    signal padded[blocks * 512];
    for (var i = 0; i < NBITS; i++) padded[i] <== in[i];
    padded[NBITS] <== 1;
    for (var i = NBITS + 1; i < blocks * 512 - 64; i++) padded[i] <== 0;
    for (var i = 0; i < 64; i++) padded[blocks * 512 - 1 - i] <== (NBITS >> i) & 1;

    component compression[blocks];
    for (var b = 0; b < blocks; b++) {
        compression[b] = Sha256Compression();
        for (var lane = 0; lane < 8; lane++) {
            if (b == 0) {
                for (var j = 0; j < 32; j++) {
                    compression[b].state[lane][j] <== Sha256InitialBit(lane, j);
                }
            } else {
                compression[b].state[lane] <== compression[b-1].out[lane];
            }
        }
        for (var word = 0; word < 16; word++) {
            for (var j = 0; j < 32; j++) {
                compression[b].block[word][j] <== padded[b*512 + word*32 + 31-j];
            }
        }
    }
    for (var lane = 0; lane < 8; lane++) {
        for (var j = 0; j < 32; j++) out[lane*32 + 31-j] <== compression[blocks-1].out[lane][j];
    }
}
