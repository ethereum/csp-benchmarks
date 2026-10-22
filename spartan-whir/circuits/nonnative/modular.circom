pragma circom 2.2.0;

include "bigint.circom";

template KbPackBytes() {
    signal input in[32];
    signal output out[22];
    component bytes[32];
    for (var i = 0; i < 32; i++) {
        bytes[i] = Num2Bits(8);
        bytes[i].in <== in[i];
    }
    component limbs[22];
    for (var i = 0; i < 22; i++) {
        limbs[i] = Bits2Num(12);
        for (var b = 0; b < 12; b++) {
            var bit = 12 * i + b;
            if (bit < 256) limbs[i].in[b] <== bytes[bit \ 8].out[bit % 8];
            else limbs[i].in[b] <== 0;
        }
        out[i] <== limbs[i].out;
    }
}

// The generic Circom ECDSA bigint routines operate on 22 little-endian 12-bit limbs.
// A multiplication diagonal is at most 23 * 4095^2 < 2^29. Its carry
// equations and range checks therefore hold as integer equations in KoalaBear.
function kb_constant_bit(p, bit) {
    return (p[bit \ 12] >> (bit % 12)) & 1;
}

template KbCanonical(p) {
    assert(p[21] < 16);
    signal input in[22];
    component limbs[22];
    for (var i = 0; i < 22; i++) {
        if (i == 21) limbs[i] = Num2Bits(4);
        else limbs[i] = Num2Bits(12);
        limbs[i].in <== in[i];
    }

    // Compare one maximal run of equal modulus bits at a time. The sum is
    // zero exactly when every input bit matches that run, since it is at
    // most 256 and every summand is a constrained bit.
    var runs = 1;
    for (var bit = 1; bit < 256; bit++) {
        if (kb_constant_bit(p, bit) != kb_constant_bit(p, bit-1)) runs++;
    }
    component equal[runs];
    signal less[runs+1];
    less[0] <== 0;
    var run = 0;
    var difference = 0;
    for (var bit = 0; bit < 256; bit++) {
        var modulusBit = kb_constant_bit(p, bit);
        if (modulusBit == 0) difference += limbs[bit \ 12].out[bit % 12];
        else difference += 1 - limbs[bit \ 12].out[bit % 12];
        var finalBit = bit == 255;
        if (bit < 255) finalBit = modulusBit != kb_constant_bit(p, bit+1);
        if (finalBit) {
            equal[run] = IsZero();
            equal[run].in <== difference;
            if (modulusBit == 0) less[run+1] <== equal[run].out * less[run];
            else less[run+1] <== 1 - equal[run].out * (1 - less[run]);
            run++;
            difference = 0;
        }
    }
    less[runs] === 1;
}

template KbMul(p) {
    signal input a[22];
    signal input b[22];
    signal output out[22];
    var product[100] = prod(12, 22, a, b);
    var qr[2][100] = long_div(12, 22, 22, product, p);
    signal quotient[22];
    component quotientRange[22];
    component remainderRange = KbCanonical(p);
    for (var i = 0; i < 22; i++) {
        quotient[i] <-- qr[0][i];
        out[i] <-- qr[1][i];
        quotientRange[i] = Num2Bits(12);
        quotientRange[i].in <== quotient[i];
        remainderRange.in[i] <== out[i];
    }
    // A(X) and B(X) have degree at most 21. Their product's 43
    // coefficients are uniquely fixed by equality at 43 distinct field
    // points: A(X)*B(X)-C(X) has degree at most 42, below 43.
    signal convolution[43];
    for (var i = 0; i < 43; i++) {
        var coefficient = 0;
        for (var j = 0; j < 22; j++) {
            if (i >= j && i-j < 22) coefficient += a[j] * b[i-j];
        }
        convolution[i] <-- coefficient;
    }
    for (var point = 0; point < 43; point++) {
        var aValue = 0;
        var bValue = 0;
        var cValue = 0;
        var power = 1;
        for (var i = 0; i < 43; i++) {
            if (i < 22) {
                aValue += power*a[i];
                bValue += power*b[i];
            }
            cValue += power*convolution[i];
            power *= point;
        }
        aValue * bValue === cValue;
    }
    signal difference[43];
    signal carry[42];
    component carryRange[42];
    for (var i = 0; i < 43; i++) {
        var qp = 0;
        for (var j = 0; j < 22; j++) {
            if (i >= j && i - j < 22) {
                qp += quotient[j] * p[i - j];
            }
        }
        // For 12-bit input limbs, convolution[i] is the unique embedding of
        // an integer in [0,22*4095^2], strictly below KoalaBear's modulus.
        // Quotient-product coefficients obey the same bound. Thus the
        // signed carry equations below retain their integer interpretation.
        if (i < 22) difference[i] <== convolution[i] - qp - out[i];
        else difference[i] <== convolution[i] - qp;
        if (i < 42) {
            if (i == 0) {
                carry[i] <-- difference[i] / 4096;
                difference[i] === carry[i] * 4096;
            } else {
                carry[i] <-- (difference[i] + carry[i - 1]) / 4096;
                difference[i] + carry[i - 1] === carry[i] * 4096;
            }
            // |carry| < 2^17; the entire carry equation has magnitude <2^30.
            carryRange[i] = Num2Bits(18);
            carryRange[i].in <== carry[i] + 131072;
        } else {
            difference[i] + carry[i - 1] === 0;
        }
    }
}

// Witness arithmetic uses 12-bit limbs throughout. The caller supplies
// canonical 256-bit residues, so addition needs at most one subtraction.
function kb_add_sub_hint(a, b, p, subtract) {
    var result[2][100];
    for (var row = 0; row < 2; row++) {
        for (var i = 0; i < 100; i++) result[row][i] = 0;
    }
    if (subtract) {
        result[1][0] = long_gt(12, 22, b, a);
        if (result[1][0]) {
            var difference[100] = long_sub(12, 22, b, a);
            result[0] = long_sub(12, 22, p, difference);
        } else {
            result[0] = long_sub(12, 22, a, b);
        }
    } else {
        var sum[100];
        for (var i = 0; i < 100; i++) sum[i] = 0;
        var carry = 0;
        for (var i = 0; i < 22; i++) {
            var value = a[i] + b[i] + carry;
            sum[i] = value % 4096;
            carry = value \ 4096;
        }
        result[1][0] = 1 - long_gt(12, 22, p, sum);
        if (result[1][0]) result[0] = long_sub(12, 22, sum, p);
        else result[0] = sum;
    }
    return result;
}

// Each carry equation has magnitude below 2^15, so equality in KoalaBear
// gives integer equality. Canonical outputs and a boolean quotient establish
// the unique modular sum or difference for canonical input residues.
template KbAdd(p) {
    signal input a[22];
    signal input b[22];
    signal output out[22];
    var hint[2][100] = kb_add_sub_hint(a, b, p, 0);
    signal quotient;
    signal carry[23];
    component carryRange[21];
    component canonical = KbCanonical(p);
    quotient <-- hint[1][0];
    quotient * (quotient - 1) === 0;
    carry[0] <== 0;
    for (var i = 0; i < 22; i++) {
        out[i] <-- hint[0][i];
        canonical.in[i] <== out[i];
        carry[i+1] <-- (a[i] + b[i] - out[i] - quotient*p[i] + carry[i]) / 4096;
        a[i] + b[i] - out[i] - quotient*p[i] + carry[i] === 4096*carry[i+1];
        if (i < 21) {
            carryRange[i] = Num2Bits(2);
            carryRange[i].in <== carry[i+1] + 1;
        }
    }
    carry[22] === 0;
}

template KbSub(p) {
    signal input a[22];
    signal input b[22];
    signal output out[22];
    var hint[2][100] = kb_add_sub_hint(a, b, p, 1);
    signal quotient;
    signal carry[23];
    component carryRange[21];
    component canonical = KbCanonical(p);
    quotient <-- hint[1][0];
    quotient * (quotient - 1) === 0;
    carry[0] <== 0;
    for (var i = 0; i < 22; i++) {
        out[i] <-- hint[0][i];
        canonical.in[i] <== out[i];
        carry[i+1] <-- (a[i] - b[i] - out[i] + quotient*p[i] + carry[i]) / 4096;
        a[i] - b[i] - out[i] + quotient*p[i] + carry[i] === 4096*carry[i+1];
        if (i < 21) {
            carryRange[i] = Num2Bits(2);
            carryRange[i].in <== carry[i+1] + 1;
        }
    }
    carry[22] === 0;
}

function kb_divide(a, b, p) {
    var inverse[100] = mod_inv(12, 22, b, p);
    var product[100] = prod(12, 22, a, inverse);
    var qr[2][100] = long_div(12, 22, 22, product, p);
    var out[100];
    for (var i = 0; i < 100; i++) out[i] = qr[1][i];
    return out;
}
