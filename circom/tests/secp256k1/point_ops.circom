pragma circom 2.0.2;
include "./check_point.circom";

// out[0] = a + b, out[1] = 2a + b (the Straus step).
template PointOps() {
    signal input a[2][8];
    signal input b[2][8];
    signal input aInf;
    signal input bInf;
    signal output out[2][2][8];
    signal output outInf[2];
    component aCheck = Secp256k1CheckPoint();
    component bCheck = Secp256k1CheckPoint();
    aCheck.isInf <== aInf; bCheck.isInf <== bInf;
    for (var c = 0; c < 2; c++) {
        for (var j = 0; j < 8; j++) {
            aCheck.p[c][j] <== a[c][j]; bCheck.p[c][j] <== b[c][j];
        }
    }
    component add = Secp256k1AddComplete();
    component step = Secp256k1DoubleAddComplete();
    add.aInf <== aInf; add.bInf <== bInf;
    step.aInf <== aInf; step.bInf <== bInf;
    for (var c = 0; c < 2; c++) {
        for (var j = 0; j < 8; j++) {
            add.a[c][j] <== a[c][j]; add.b[c][j] <== b[c][j];
            step.a[c][j] <== a[c][j]; step.b[c][j] <== b[c][j];
        }
    }
    outInf[0] <== add.outInf; outInf[1] <== step.outInf;
    for (var c = 0; c < 2; c++) {
        for (var j = 0; j < 8; j++) {
            out[0][c][j] <== add.out[c][j];
            out[1][c][j] <== step.out[c][j];
        }
    }
}
component main {public [a, b, aInf, bInf]} = PointOps();
