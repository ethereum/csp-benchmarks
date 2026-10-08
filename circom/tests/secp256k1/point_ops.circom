pragma circom 2.0.2;
include "./check_point.circom";

template PointOps() {
    signal input a[2][4];
    signal input b[2][4];
    signal input aInf;
    signal input bInf;
    signal output out[2][2][4];
    signal output outInf[2];
    component aCheck = Secp256k1CheckPoint();
    component bCheck = Secp256k1CheckPoint();
    aCheck.isInf <== aInf; bCheck.isInf <== bInf;
    for (var c = 0; c < 2; c++) {
        for (var j = 0; j < 4; j++) {
            aCheck.p[c][j] <== a[c][j]; bCheck.p[c][j] <== b[c][j];
        }
    }
    component add = Secp256k1AddComplete();
    component dbl = Secp256k1DoubleComplete();
    add.aInf <== aInf; add.bInf <== bInf;
    dbl.inInf <== aInf;
    for (var c = 0; c < 2; c++) {
        for (var j = 0; j < 4; j++) {
            add.a[c][j] <== a[c][j]; add.b[c][j] <== b[c][j];
            dbl.in[c][j] <== a[c][j];
        }
    }
    outInf[0] <== add.outInf; outInf[1] <== dbl.outInf;
    for (var c = 0; c < 2; c++) {
        for (var j = 0; j < 4; j++) {
            out[0][c][j] <== add.out[c][j];
            out[1][c][j] <== dbl.out[c][j];
        }
    }
}
component main {public [a, b, aInf, bInf]} = PointOps();
