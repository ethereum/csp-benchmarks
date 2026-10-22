pragma circom 2.0.0;

include "keccak_bytes.circom";

template Keccak256Hash(N) {
    signal input in[N];
    signal input hash[32];

    component keccak = Keccak_256_bytes(N);
    keccak.inp_bytes <== in;

    for (var i = 0; i < 32; i++) {
        keccak.out_bytes[i] === hash[i];
    }
}
