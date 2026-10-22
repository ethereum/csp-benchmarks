pragma circom 2.2.0;

include "../nonnative/modular.circom";
include "constants.circom";

function kb_fused_prime11_for(p256) {
    var p12[22] = ecdsa_prime(p256);
    var p11[24];
    for (var i = 0; i < 24; i++) {
        p11[i] = 0;
        for (var b = 0; b < 11; b++) {
            var bit = 11*i+b;
            if (bit < 256) p11[i] += ((p12[bit \ 12] >> (bit % 12)) & 1)*(1 << b);
        }
    }
    return p11;
}

function kb_fused_prime11() {
    return kb_fused_prime11_for(1);
}

function kb_fused_12to11(in) {
    var out[100];
    for (var i = 0; i < 100; i++) out[i] = 0;
    for (var i = 0; i < 24; i++) {
        for (var b = 0; b < 11; b++) {
            var bit = 11*i+b;
            if (bit < 256) out[i] += ((in[bit \ 12] >> (bit % 12)) & 1)*(1 << b);
        }
    }
    return out;
}

template KbFusedTo11() {
    signal input in[22];
    signal output out[24];
    component bits[22];
    for (var j = 0; j < 22; j++) {
        if (j == 21) bits[j] = Num2Bits(4);
        else bits[j] = Num2Bits(12);
        bits[j].in <== in[j];
    }
    for (var j = 0; j < 24; j++) {
        var sum = 0;
        for (var b = 0; b < 11; b++) {
            var bit = 11*j+b;
            if (bit < 256) sum += bits[bit \ 12].out[bit % 12]*(1 << b);
        }
        out[j] <== sum;
    }
}

template KbFusedCanonical11For(p256) {
    var p[24] = kb_fused_prime11_for(p256);
    signal input in[24];
    signal output out12[22];
    component range[24];
    for (var j = 0; j < 24; j++) {
        if (j == 23) range[j] = Num2Bits(3);
        else range[j] = Num2Bits(11);
        range[j].in <== in[j];
    }
    var runs = 1;
    for (var bit = 1; bit < 256; bit++) {
        if (((p[bit \ 11] >> (bit % 11)) & 1) != ((p[(bit-1) \ 11] >> ((bit-1) % 11)) & 1)) runs++;
    }
    component equal[runs];
    signal less[runs+1];
    less[0] <== 0;
    var run = 0;
    var difference = 0;
    for (var bit = 0; bit < 256; bit++) {
        var modulusBit = (p[bit \ 11] >> (bit % 11)) & 1;
        if (modulusBit == 0) difference += range[bit \ 11].out[bit % 11];
        else difference += 1-range[bit \ 11].out[bit % 11];
        var finalBit = bit == 255;
        if (bit < 255) finalBit = modulusBit != ((p[(bit+1) \ 11] >> ((bit+1) % 11)) & 1);
        if (finalBit) {
            equal[run] = IsZero();
            equal[run].in <== difference;
            if (modulusBit == 0) less[run+1] <== equal[run].out*less[run];
            else less[run+1] <== 1-equal[run].out*(1-less[run]);
            difference = 0;
            run++;
        }
    }
    less[runs] === 1;
    for (var j = 0; j < 22; j++) {
        var sum = 0;
        for (var b = 0; b < 12; b++) {
            var bit = 12*j+b;
            if (bit < 256) sum += range[bit \ 11].out[bit % 11]*(1 << b);
        }
        out12[j] <== sum;
    }
}

template KbFusedCanonical11() {
    signal input in[24];
    signal output out12[22];
    component check = KbFusedCanonical11For(1);
    for (var j = 0; j < 24; j++) check.in[j] <== in[j];
    for (var j = 0; j < 22; j++) out12[j] <== check.out12[j];
}

// The caller supplies bounded 11-bit digits. For the 24x24 and 24x48
// products used here each coefficient is at most 24*2047^2=100565016.
// Equality at n+m-1 distinct points determines every product coefficient
// over KoalaBear; the integer bound makes their field encodings unique.
template KbFusedConvolution11(n, m) {
    signal input a[n];
    signal input b[m];
    signal output out[n+m-1];
    for (var i = 0; i < n+m-1; i++) {
        var coefficient = 0;
        for (var j = 0; j < n; j++) {
            if (i >= j && i-j < m) coefficient += a[j]*b[i-j];
        }
        out[i] <-- coefficient;
    }
    for (var t = 0; t < n+m-1; t++) {
        var av = 0;
        var bv = 0;
        var cv = 0;
        var power = 1;
        for (var j = 0; j < n+m-1; j++) {
            if (j < n) av += power*a[j];
            if (j < m) bv += power*b[j];
            cv += power*out[j];
            power *= t;
        }
        av*bv === cv;
    }
}

// Normalize an explicitly positive integer polynomial into base 2048.
// This does not reduce modulo the curve field. The fixed p*2048^24 offset
// in the caller makes l0*(xR-xD)-yR positive and smaller than 2048^48.
function kb_fused_normalize_hint(in, count) {
    var out[100];
    for (var i = 0; i < 100; i++) out[i] = 0;
    var carry = 0;
    for (var i = 0; i < count; i++) {
        var value = in[i]+carry;
        if (value < 0) {
            var magnitude = -value;
            out[i] = (2048-magnitude % 2048) % 2048;
            carry = -(magnitude \ 2048);
            if (out[i] != 0) carry--;
        } else {
            out[i] = value % 2048;
            carry = value \ 2048;
        }
    }
    return out;
}

template KbFusedNormalize11(count) {
    signal input in[count];
    signal output out[count];
    var digits[100] = kb_fused_normalize_hint(in, count);
    signal carry[count+1];
    component digitRange[count];
    component carryRange[count-1];
    carry[0] <== 0;
    carry[count] <== 0;
    for (var i = 0; i < count; i++) {
        out[i] <-- digits[i];
        digitRange[i] = Num2Bits(11);
        digitRange[i].in <== out[i];
        if (i < count-1) {
            carry[i+1] <-- (in[i]+carry[i]-out[i])/2048;
            carryRange[i] = Num2Bits(20);
            carryRange[i].in <== carry[i+1]+524288;
        }
        in[i]+carry[i]-out[i] === 2048*carry[i+1];
    }
}

// Return the sign and magnitude of the quotient of a signed coefficient
// polynomial by the selected curve prime. Positive/negative coefficient sums are
// normalized separately, keeping witness arithmetic below KoalaBear/2.
function kb_fused_quotient_hint_for(in, count, p256) {
    var p[24] = kb_fused_prime11_for(p256);
    var positive[100];
    var negative[100];
    for (var i = 0; i < 100; i++) { positive[i] = 0; negative[i] = 0; }
    for (var i = 0; i < count; i++) {
        if (in[i] < 0) negative[i] = -in[i];
        else positive[i] = in[i];
    }
    for (var i = 0; i < count+1; i++) {
        positive[i+1] += positive[i] \ 2048;
        negative[i+1] += negative[i] \ 2048;
        positive[i] = positive[i] % 2048;
        negative[i] = negative[i] % 2048;
    }
    var sign = long_gt(11, count+2, negative, positive);
    var magnitude[100];
    if (sign == 1) magnitude = long_sub(11, count+2, negative, positive);
    else magnitude = long_sub(11, count+2, positive, negative);
    var division[2][100] = long_div(11, 24, count-22, magnitude, p);
    var out[2][100];
    for (var i = 0; i < 100; i++) { out[0][i] = 0; out[1][i] = 0; }
    for (var i = 0; i < count-21; i++) out[0][i] = division[0][i];
    out[1][0] = sign;
    return out;
}

function kb_fused_quotient_hint(in, count) {
    return kb_fused_quotient_hint_for(in, count, 1);
}

// Each input coefficient has magnitude <=502825083. The signed quotient
// convolution has magnitude <=24*2047^2=100565016; each signed carry is
// in [-524288,524287]. Thus the complete integer carry equality has
// magnitude <=502825083+100565016+524288+2048*524288=1677656211,
// strictly below KoalaBear's 2130706433. Equality in KoalaBear therefore
// establishes integer equality, including negative quotients and carries.
template KbFusedModZero11For(count, p256) {
    assert(count >= 24 && count <= 71);
    var p[24] = kb_fused_prime11_for(p256);
    var qCount = count-21;
    var total = count+2;
    signal input in[count];
    var hint[2][100] = kb_fused_quotient_hint_for(in, count, p256);
    signal qMagnitude[qCount];
    signal qSign;
    signal signedQuotient[qCount];
    signal carry[total+1];
    component qRange[qCount];
    component carryRange[total-1];
    qSign <-- hint[1][0];
    qSign*(qSign-1) === 0;
    var quotientSum = 0;
    for (var j = 0; j < qCount; j++) {
        qMagnitude[j] <-- hint[0][j];
        qRange[j] = Num2Bits(11);
        qRange[j].in <== qMagnitude[j];
        signedQuotient[j] <== (1-2*qSign)*qMagnitude[j];
        quotientSum += qMagnitude[j];
    }
    component qZero = IsZero();
    qZero.in <== quotientSum;
    qSign*qZero.out === 0;
    carry[0] <== 0;
    carry[total] <== 0;
    for (var i = 0; i < total; i++) {
        var coefficient = 0;
        for (var j = 0; j < qCount; j++) {
            if (i >= j && i-j < 24) coefficient += signedQuotient[j]*p[i-j];
        }
        var residual = -coefficient;
        if (i < count) residual += in[i];
        if (i < total-1) {
            carry[i+1] <-- (residual+carry[i])/2048;
            carryRange[i] = Num2Bits(20);
            carryRange[i].in <== carry[i+1]+524288;
        }
        residual+carry[i] === 2048*carry[i+1];
    }
}

template KbFusedModZero11(count) {
    signal input in[count];
    component check = KbFusedModZero11For(count, 1);
    for (var i = 0; i < count; i++) check.in[i] <== in[i];
}
