pragma circom 2.2.3;

include "../bits.circom";

// Addition modulo 2^32 of already constrained bit arrays. Two 16-bit
// segments keep both sides of every carry equation below 2^19 < KoalaBear.
// The bounded carry and output bits make each integer equation unique.
template AddWords32(OPS) {
    assert(OPS >= 2 && OPS <= 6);
    signal input in[OPS][32];
    signal output out[32];
    signal carry[3];
    component sum[2];
    carry[0] <== 0;
    for (var chunk = 0; chunk < 2; chunk++) {
        var packed = carry[chunk];
        for (var bit = 0; bit < 16; bit++) {
            for (var operand = 0; operand < OPS; operand++) {
                packed += in[operand][chunk*16+bit] * 2**bit;
            }
        }
        sum[chunk] = SmallNum2Bits(19);
        sum[chunk].in <== packed;
        for (var bit = 0; bit < 16; bit++) out[chunk*16+bit] <== sum[chunk].out[bit];
        carry[chunk+1] <== sum[chunk].out[16]
            + 2*sum[chunk].out[17] + 4*sum[chunk].out[18];
    }
}
