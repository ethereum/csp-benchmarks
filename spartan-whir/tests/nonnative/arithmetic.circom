pragma circom 2.2.3;

include "../../circuits/nonnative/modular.circom";
include "../../circuits/ecdsa/constants.circom";

template ArithmeticProbe(p256, order) {
    var modulus[22];
    if (order) modulus = ecdsa_order(p256);
    else modulus = ecdsa_prime(p256);
    signal input a[22];
    signal input b[22];
    signal output sum[22];
    signal output difference[22];
    component aCanonical = KbCanonical(modulus);
    component bCanonical = KbCanonical(modulus);
    component add = KbAdd(modulus);
    component sub = KbSub(modulus);
    for (var i = 0; i < 22; i++) {
        aCanonical.in[i] <== a[i];
        bCanonical.in[i] <== b[i];
        add.a[i] <== a[i];
        add.b[i] <== b[i];
        sub.a[i] <== a[i];
        sub.b[i] <== b[i];
    }
    sum <== add.out;
    difference <== sub.out;
}
