pragma circom 2.0.2;
include "./check_point.circom";
include "../../circuits/ecdsa/p256_complete.circom";

template QuadModulo() {
    signal input a[2][8];
    signal input b[2][8];
    signal input aInf;
    signal input bInf;
    signal output out[2][8];
    signal output outInf;
    aInf * (aInf - 1) === 0;
    var gx[100] = get_p256_gx(32, 8);
    var gy[100] = get_p256_gy(32, 8);
    component aRange[2][8];
    component on = P256PointOnCurve();
    for (var c = 0; c < 2; c++) {
        for (var j = 0; j < 8; j++) {
            aRange[c][j] = Num2Bits(32); aRange[c][j].in <== a[c][j];
            aInf * a[c][j] === 0;
        }
    }
    for (var j = 0; j < 8; j++) {
        on.x[j] <== a[0][j] + aInf * (gx[j] - a[0][j]);
        on.y[j] <== a[1][j] + aInf * (gy[j] - a[1][j]);
    }
    component bCheck = P256CheckPoint();
    bCheck.isInf <== bInf;
    for (var c = 0; c < 2; c++) {
        for (var j = 0; j < 8; j++) { bCheck.p[c][j] <== b[c][j]; }
    }
    component quad = P256QuadAddComplete();
    quad.aInf <== aInf; quad.bInf <== bInf;
    for (var c = 0; c < 2; c++) {
        for (var j = 0; j < 8; j++) {
            quad.a[c][j] <== a[c][j]; quad.b[c][j] <== b[c][j];
        }
    }
    outInf <== quad.outInf;
    for (var c = 0; c < 2; c++) {
        for (var j = 0; j < 8; j++) { out[c][j] <== quad.out[c][j]; }
    }
}
component main {public [a, b, aInf, bInf]} = QuadModulo();
