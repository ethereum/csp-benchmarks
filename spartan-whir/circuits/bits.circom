pragma circom 2.2.3;

// Every use has n <= 19, so the packed integer is below KoalaBear.
template SmallNum2Bits(n) {
    assert(n <= 19);
    signal input in;
    signal output out[n];
    var packed = 0;
    for (var i = 0; i < n; i++) {
        out[i] <-- (in >> i) & 1;
        out[i] * (out[i] - 1) === 0;
        packed += out[i] * 2**i;
    }
    in === packed;
}
