pragma circom 2.0.2;
include "./check_point.circom";
include "../../circuits/ecdsa/glv4_straus.circom";

template Straus() {
    signal input mag[4];
    signal input A[4][2][4];
    component range[4];
    component valid[4];
    component loop = GLV4StrausLoop(64);
    for (var b = 0; b < 4; b++) {
        range[b] = Num2Bits(64);
        range[b].in <== mag[b];
        valid[b] = Secp256k1CheckPoint();
        valid[b].isInf <== 0;
        for (var c = 0; c < 2; c++) {
            for (var j = 0; j < 4; j++) {
                valid[b].p[c][j] <== A[b][c][j]; loop.A[b][c][j] <== A[b][c][j];
            }
        }
        for (var j = 0; j < 64; j++) { loop.bits[b][j] <== range[b].out[j]; }
    }
}
component main {public [mag, A]} = Straus();
