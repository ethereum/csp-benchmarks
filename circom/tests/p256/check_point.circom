pragma circom 2.0.2;
include "../../circuits/ecdsa/p256_complete.circom";

// Validate canonical finite points or the zero-coordinate infinity encoding.
template P256CheckPoint() {
    signal input p[2][8];
    signal input isInf;
    isInf * (isInf - 1) === 0;
    var gx[100] = get_p256_gx(32, 8);
    var gy[100] = get_p256_gy(32, 8);
    component range[2];
    component on = P256PointOnCurve();
    for (var c = 0; c < 2; c++) {
        range[c] = CheckInRangeP256();
        for (var j = 0; j < 8; j++) {
            range[c].in[j] <== p[c][j];
            isInf * p[c][j] === 0;
        }
    }
    for (var j = 0; j < 8; j++) {
        on.x[j] <== p[0][j] + isInf * (gx[j] - p[0][j]);
        on.y[j] <== p[1][j] + isInf * (gy[j] - p[1][j]);
    }
}
