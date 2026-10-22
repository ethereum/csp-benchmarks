pragma circom 2.2.0;

include "curve.circom";
include "comb_constants.circom";

// Decode constrained bits into a one-hot vector. The high half of each
// level takes the newly decoded bit as the next most significant bit.
template KbCombOneHot(bits) {
    signal input in[bits];
    signal output out[1 << bits];
    signal levels[bits+1][1 << bits];
    levels[0][0] <== 1;
    for (var j = 1; j < (1 << bits); j++) levels[0][j] <== 0;
    for (var bit = 0; bit < bits; bit++) {
        in[bit] * (in[bit] - 1) === 0;
        for (var j = 0; j < (1 << bit); j++) {
            levels[bit+1][j+(1 << bit)] <== levels[bit][j] * in[bit];
            levels[bit+1][j] <== levels[bit][j] - levels[bit+1][j+(1 << bit)];
        }
        for (var j = (1 << (bit+1)); j < (1 << bits); j++) levels[bit+1][j] <== 0;
    }
    for (var j = 0; j < (1 << bits); j++) out[j] <== levels[bits][j];
}

// The runtime loop keeps native witness code compact. Its symbolic result
// is the same constant linear combination used by the R1CS lookup.
function kb_comb_linear(rows, selectors) {
    var out[44];
    for (var limb = 0; limb < 44; limb++) {
        var sum = 0;
        for (var lower = 0; lower < 256; lower++) sum += rows[lower][limb] * selectors[lower];
        out[limb] = sum;
    }
    return out;
}

template KbCombWindow(p256, window) {
    signal input bits[11];
    signal output out[2][22];
    var table[2048][44] = kb_comb_table(p256, window);
    component low = KbCombOneHot(8);
    component high = KbCombOneHot(3);
    for (var bit = 0; bit < 8; bit++) low.in[bit] <== bits[bit];
    for (var bit = 0; bit < 3; bit++) high.in[bit] <== bits[8+bit];
    signal partial[8][44];
    signal product[8][44];
    for (var upper = 0; upper < 8; upper++) {
        var rows[256][44];
        for (var lower = 0; lower < 256; lower++) {
            for (var limb = 0; limb < 44; limb++) rows[lower][limb] = table[256*upper+lower][limb];
        }
        var linear[44] = kb_comb_linear(rows, low.out);
        for (var limb = 0; limb < 44; limb++) {
            partial[upper][limb] <== linear[limb];
            product[upper][limb] <== high.out[upper] * partial[upper][limb];
        }
    }
    for (var limb = 0; limb < 44; limb++) {
        var sum = 0;
        for (var upper = 0; upper < 8; upper++) sum += product[upper][limb];
        out[limb \ 22][limb % 22] <== sum;
    }
}

// Width-12 signed-digit comb for [k]G on either curve, using the recoding
// and lookup structure of the Circom benchmarks based on rot256's zk.golf
// fixed-base multiplication submission. The parity fold is
// the integer k+(1-odd(k))*n: its bit 256 is retained before padding to 264
// bits. The recoded odd digits sum to that integer, and [n]G is infinity.
// The first 20 additions have unequal x coordinates by the prefix bound
// below. The final addition is complete, including zero and doubling cases.
template KbCombFixedBase(p256) {
    signal input k[22];
    signal output out[2][22];
    signal output outInf;
    var n[22] = ecdsa_order(p256);
    var p[22] = ecdsa_prime(p256);
    assert(n[21] > 1); // Both curve orders exceed 2^252.
    component canonical = KbCanonical(n);
    // Canonical checks already bound every limb. Only the low limb's
    // parity is needed for the signed-digit recoding.
    component lowBits = Num2Bits(12);
    lowBits.in <== k[0];
    component zero = BigIsEqual(22);
    for (var limb = 0; limb < 22; limb++) {
        canonical.in[limb] <== k[limb];
        zero.in[0][limb] <== k[limb];
        zero.in[1][limb] <== 0;
    }
    signal odd;
    odd <== lowBits.out[0];
    signal folded[22];
    signal carry[23];
    carry[0] <== 0;
    component foldedBits[22];
    for (var limb = 0; limb < 22; limb++) {
        // A local sum is at most 8191. Boolean carries and 12-bit outputs
        // establish the integer addition in the KoalaBear field.
        folded[limb] <-- (k[limb] + (1-odd)*n[limb] + carry[limb]) % 4096;
        carry[limb+1] <-- (k[limb] + (1-odd)*n[limb] + carry[limb]) \ 4096;
        k[limb] + (1-odd)*n[limb] + carry[limb] === folded[limb] + 4096*carry[limb+1];
        carry[limb+1] * (carry[limb+1]-1) === 0;
        foldedBits[limb] = Num2Bits(12);
        foldedBits[limb].in <== folded[limb];
    }
    carry[22] === 0;
    signal bits[264];
    for (var bit = 0; bit < 264; bit++) bits[bit] <== foldedBits[bit \ 12].out[bit % 12];
    bits[0] === 1;
    for (var bit = 257; bit < 264; bit++) bits[bit] === 0;

    signal sign[22];
    signal indexBits[22][11];
    component selected[22];
    component negate[22];
    signal point[22][2][22];
    for (var window = 0; window < 22; window++) {
        if (window == 21) sign[window] <== 1;
        else sign[window] <== bits[12*window+12];
        selected[window] = KbCombWindow(p256, window);
        for (var bit = 0; bit < 11; bit++) {
            indexBits[window][bit] <== 1-bits[12*window+bit+1]-sign[window]
                +2*bits[12*window+bit+1]*sign[window];
            selected[window].bits[bit] <== indexBits[window][bit];
        }
        negate[window] = KbSub(p);
        for (var limb = 0; limb < 22; limb++) {
            negate[window].a[limb] <== 0;
            negate[window].b[limb] <== selected[window].out[1][limb];
        }
        for (var limb = 0; limb < 22; limb++) {
            point[window][0][limb] <== selected[window].out[0][limb];
            point[window][1][limb] <== negate[window].out[limb]
                +sign[window]*(selected[window].out[1][limb]-negate[window].out[limb]);
        }
    }

    // Let B=4096, b_j be the folded bits, and b_264=1 be the final sign.
    // The lookup gives d_i=1-B+sum_(t=1..12) b_(12i+t)*2^t. Therefore
    // sum_(i=0..21) d_i*B^i = 1-B^22+sum_(j=1..264) b_j*2^j = kOdd,
    // using b_0=1. This holds for either integer parity fold k or k+n.
    // Each d_j is the signed odd digit selected at window j:
    // 1<=|d_j|<=B-1. Before window i, S=sum_(j<i) d_j*B^j is odd,
    // so S!=0, and |S|<=B^i-1. The next digit D=d_i*B^i is even,
    // nonzero, and |D|<=B^(i+1)-B^i. Hence S+D and S-D are odd and
    // 0<|S+/-D|<=B^(i+1)-1. For i=1..20 this is <2^252<n. Neither
    // S nor D nor S+/-D vanishes modulo n: both inputs and their sum
    // are finite, and the inputs cannot be equal or inverses. On either
    // curve equal x coordinates mean equal or inverse group elements.
    // This bound holds for every possible digit sequence, including the
    // parity fold k=0 -> n. At i=21 the bound crosses n, so that step
    // uses the complete group law.
    signal accumulator[22][2][22];
    for (var coordinate = 0; coordinate < 2; coordinate++) {
        for (var limb = 0; limb < 22; limb++) accumulator[0][coordinate][limb] <== point[0][coordinate][limb];
    }
    component add[20];
    for (var window = 1; window < 21; window++) {
        add[window-1] = KbPointAddUnequal(p256);
        for (var coordinate = 0; coordinate < 2; coordinate++) {
            for (var limb = 0; limb < 22; limb++) {
                add[window-1].a[coordinate][limb] <== accumulator[window-1][coordinate][limb];
                add[window-1].b[coordinate][limb] <== point[window][coordinate][limb];
            }
        }
        for (var coordinate = 0; coordinate < 2; coordinate++) {
            for (var limb = 0; limb < 22; limb++) accumulator[window][coordinate][limb] <== add[window-1].out[coordinate][limb];
        }
    }
    component finalAdd = KbPointAdd(p256);
    finalAdd.aInf <== 0;
    finalAdd.bInf <== 0;
    for (var coordinate = 0; coordinate < 2; coordinate++) {
        for (var limb = 0; limb < 22; limb++) {
            finalAdd.a[coordinate][limb] <== accumulator[20][coordinate][limb];
            finalAdd.b[coordinate][limb] <== point[21][coordinate][limb];
        }
    }
    for (var coordinate = 0; coordinate < 2; coordinate++) {
        for (var limb = 0; limb < 22; limb++) accumulator[21][coordinate][limb] <== finalAdd.out[coordinate][limb];
    }
    finalAdd.outInf === zero.out;
    outInf <== zero.out;
    for (var coordinate = 0; coordinate < 2; coordinate++) {
        for (var limb = 0; limb < 22; limb++) out[coordinate][limb] <== accumulator[21][coordinate][limb];
    }
}
