pragma circom 2.0.2;
include "./check_point.circom";
include "../../circuits/ecdsa/fake_glv2_straus.circom";

template Straus() {
    signal input mag[2];
    signal input A[2][2][8];
    component range[2];
    component valid[2];
    component loop = FakeGLV2StrausLoop(128);
    for (var b = 0; b < 2; b++) {
        range[b] = Num2Bits(128);
        range[b].in <== mag[b];
        valid[b] = P256CheckPoint();
        valid[b].isInf <== 0;
        for (var c = 0; c < 2; c++) {
            for (var j = 0; j < 8; j++) {
                valid[b].p[c][j] <== A[b][c][j]; loop.A[b][c][j] <== A[b][c][j];
            }
        }
        for (var j = 0; j < 128; j++) { loop.bits[b][j] <== range[b].out[j]; }
    }
}
component main {public [mag, A]} = Straus();
