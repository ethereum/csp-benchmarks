pragma circom 2.0.2;
include "../../circuits/ecdsa/secp256k1_complete.circom";

// Validate canonical finite points or the zero-coordinate infinity encoding.
template Secp256k1CheckPoint() {
    signal input p[2][8];
    signal input isInf;
    isInf * (isInf - 1) === 0;
    var gx[100] = p256_split64to32(get_gx64());
    var gy[100] = p256_split64to32(get_gy64());
    component range[2];
    component on = Secp256k1PointOnCurve32();
    for (var c = 0; c < 2; c++) {
        range[c] = CheckInRangeSecp256k1Limbs32();
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
