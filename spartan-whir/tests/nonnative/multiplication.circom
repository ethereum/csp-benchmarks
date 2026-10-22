pragma circom 2.2.3;

include "../../circuits/nonnative/modular.circom";
include "../../circuits/ecdsa/constants.circom";

// ECDSA's prehash may exceed the scalar modulus. Both inputs admit the full
// 256-bit range; the multiplication constrains its output below the modulus.
template MultiplicationProbe(p256, order) {
    var modulus[22];
    if (order) modulus = ecdsa_order(p256);
    else modulus = ecdsa_prime(p256);
    signal input a[22];
    signal input b[22];
    signal output product[22];
    component aRange[22];
    component bRange[22];
    component mul = KbMul(modulus);
    for (var i = 0; i < 22; i++) {
        if (i == 21) {
            aRange[i] = Num2Bits(4);
            bRange[i] = Num2Bits(4);
        } else {
            aRange[i] = Num2Bits(12);
            bRange[i] = Num2Bits(12);
        }
        aRange[i].in <== a[i];
        bRange[i].in <== b[i];
        mul.a[i] <== a[i];
        mul.b[i] <== b[i];
    }
    product <== mul.out;
}
