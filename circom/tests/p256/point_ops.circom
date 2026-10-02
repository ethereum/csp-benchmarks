pragma circom 2.0.2;
include "./check_point.circom";
include "./double_add.circom";

template PointOps() {
    signal input a[2][8];
    signal input b[2][8];
    signal input aInf;
    signal input bInf;
    signal output out[3][2][8];
    signal output outInf[3];
    component aCheck = P256CheckPoint();
    component bCheck = P256CheckPoint();
    aCheck.isInf <== aInf; bCheck.isInf <== bInf;
    for (var c = 0; c < 2; c++) {
        for (var j = 0; j < 8; j++) {
            aCheck.p[c][j] <== a[c][j]; bCheck.p[c][j] <== b[c][j];
        }
    }
    component add = P256AddComplete();
    component fused = P256DoubleAddComplete();
    component quad = P256QuadAddComplete();
    add.aInf <== aInf; add.bInf <== bInf;
    fused.aInf <== aInf; fused.bInf <== bInf;
    quad.aInf <== aInf; quad.bInf <== bInf;
    for (var c = 0; c < 2; c++) {
        for (var j = 0; j < 8; j++) {
            add.a[c][j] <== a[c][j]; add.b[c][j] <== b[c][j];
            fused.a[c][j] <== a[c][j]; fused.b[c][j] <== b[c][j];
            quad.a[c][j] <== a[c][j]; quad.b[c][j] <== b[c][j];
        }
    }
    outInf[0] <== add.outInf; outInf[1] <== fused.outInf; outInf[2] <== quad.outInf;
    for (var c = 0; c < 2; c++) {
        for (var j = 0; j < 8; j++) {
            out[0][c][j] <== add.out[c][j];
            out[1][c][j] <== fused.out[c][j];
            out[2][c][j] <== quad.out[c][j];
        }
    }
}
component main {public [a, b, aInf, bInf]} = PointOps();
