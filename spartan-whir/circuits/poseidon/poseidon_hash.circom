pragma circom 2.2.3;

include "constants.circom";

// Native KoalaBear Poseidon1. The S-box and round structure follow the
// existing Circom Poseidon circuit; parameters match Plonky3's width 16
// Poseidon1 permutation. MDS is the circulant matrix in koala-bear/src/mds.rs.
template Poseidon1Permutation() {
    signal input in[16];
    signal output out[16];
    signal state[29][16];
    signal added[28][16];
    signal squared[28][16];
    signal nonlinear[28][16];
    var firstRow[16] = [1, 1, 51, 1, 11, 17, 2, 1, 101, 63, 15, 2, 67, 22, 13, 3];
    state[0] <== in;
    for (var round = 0; round < 28; round++) {
        for (var lane = 0; lane < 16; lane++) {
            added[round][lane] <== state[round][lane] + Poseidon1RoundConstant(round, lane);
            if (round < 4 || round >= 24 || lane == 0) {
                squared[round][lane] <== added[round][lane] * added[round][lane];
                nonlinear[round][lane] <== squared[round][lane] * added[round][lane];
            } else {
                squared[round][lane] <== 0;
                nonlinear[round][lane] <== added[round][lane];
            }
        }
        for (var lane = 0; lane < 16; lane++) {
            var mixed = 0;
            for (var column = 0; column < 16; column++) {
                mixed += firstRow[(column + 16 - lane) % 16] * nonlinear[round][column];
            }
            state[round+1][lane] <== mixed;
        }
    }
    out <== state[28];
}

// Plonky3 Pad10Sponge: width 16, rate 8, capacity 8, output 8, Increment(1).
// Partial final blocks place 1 after the message and zero the remaining rate.
// Full final blocks increment the first capacity element before permutation.
template PoseidonHash(N) {
    assert(N > 0);
    signal input inputs[N];
    signal input hash[8];
    var blocks = (N + 7) \ 8;
    component permutation[blocks];
    for (var block = 0; block < blocks; block++) {
        permutation[block] = Poseidon1Permutation();
        for (var lane = 0; lane < 16; lane++) {
            if (lane < 8) {
                if (block*8 + lane < N) {
                    permutation[block].in[lane] <== inputs[block*8 + lane];
                } else {
                    permutation[block].in[lane] <== block*8 + lane == N;
                }
            } else {
                var padding = block == blocks - 1 && N % 8 == 0 && lane == 8;
                if (block == 0) {
                    permutation[block].in[lane] <== padding;
                } else {
                    permutation[block].in[lane] <== permutation[block-1].out[lane] + padding;
                }
            }
        }
    }
    for (var lane = 0; lane < 8; lane++) {
        permutation[blocks-1].out[lane] === hash[lane];
    }
}
