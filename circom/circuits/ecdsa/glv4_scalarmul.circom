/*
    Verifying Q == [s]P on secp256k1 with 4-dimensional fake-GLV.

    The technique is taken from the public description of rot256's (Mathias
    Hall-Andersen) submission to the zk.golf secp256k1 scalar multiplication
    challenge. No code was copied; the circom below is an independent
    implementation.

    Interface note, read before comparing constraint counts:
    Secp256k1ScalarMult(64, 4) computes [s]P, this circuit verifies a given Q.
    The prover supplies the result and four small scalars, and the circuit
    convinces itself they are correct -- the same shape as the zkGolf record
    ("result witnessed, closed by an =O assertion"). For ECDSA it costs
    nothing, since the verification equation is itself a check.

    The hint (u1, u2, v1, v2) is an input of this template, not of the
    circuit: whoever instantiates it computes the hint at witness generation
    time. It does not weaken soundness: the hint is constrained by the
    relation mod n, by the ranges, and by (v1,v2) != 0.

    Soundness. Let t be such that Q = [t]P (it exists: Q is checked to be on
    the curve and the group is cyclic of prime order n). The constraints give

        (1)  u1 + u2*L == s*(v1 + v2*L)  (mod n)        -- the relation
        (2)  [u1]P + [u2]phi(P) == [v1]Q + [v2]phi(Q)   -- loop + =O assertion
        (3)  |u_i|, |v_i| < 2^64                        -- Num2Bits(64)
        (4)  (v1, v2) != (0, 0)

    From (2), u1 + u2*L == t*(v1 + v2*L) mod n, so with (1)
    (t - s)*(v1 + v2*L) == 0 mod n. By (3) and (4), v1 + v2*L != 0 mod n: the
    shortest vector of {(a,b) : a + b*L == 0 mod n} has norm ~2^128, so no
    non-zero (v1,v2) has both components below 2^64. n is prime, hence t == s.

    Not handled: P at infinity, or s = 0.

    Scalars are 64-bit limbs and each hint magnitude is a single value below
    2^64; points are eight 32-bit limbs per coordinate.
*/
pragma circom 2.0.2;

include "./secp256k1.circom";
include "./glv4_straus.circom";
include "../../circomlib/circuits/comparators.circom";

// lambda = 0x5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72
// Checked out of circuit: lambda^3 == 1 mod n, lambda != 1.
function get_glv_lambda_limbs() {
    var ret[4];
    ret[0] = 16069571880186789234;
    ret[1] = 1310022930574435960;
    ret[2] = 11900229862571533402;
    ret[3] = 6008836872998760672;
    return ret;
}

// beta = 0x7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee
// phi(x, y) = (beta*x mod p, y). Checked: beta^3 == 1 mod p, phi(G) == [lambda]G.
function get_glv_beta_limbs() {
    var ret[4];
    ret[0] = 13923278643952681454;
    ret[1] = 11308619431505398165;
    ret[2] = 7954561588662645993;
    ret[3] = 8856726876819556112;
    return ret;
}

// x + y (mod n), built out of BigSubModP because circom-ecdsa has no
// BigAddModP: x + y == x - (0 - y). Requires x, y < n.
template AddModN() {
    signal input x[4];
    signal input y[4];
    signal input m[4];
    signal output out[4];

    signal zero[4];
    for (var j = 0; j < 4; j++) zero[j] <== 0;

    component neg = BigSubModP(64, 4);   // -y mod n
    component add = BigSubModP(64, 4);   // x - (-y) mod n
    for (var j = 0; j < 4; j++) {
        neg.a[j] <== zero[j];
        neg.b[j] <== y[j];
        neg.p[j] <== m[j];
    }
    for (var j = 0; j < 4; j++) {
        add.a[j] <== x[j];
        add.b[j] <== neg.out[j];
        add.p[j] <== m[j];
    }
    // Separate loop: circom rejects access to `out` while any input of the
    // component is still uninitialized.
    for (var j = 0; j < 4; j++) {
        out[j] <== add.out[j];
    }
}

template GLV4ScalarMulVerify() {
    signal input scalar[4];   // s, in 64-bit limbs
    signal input P[2][8];     // the base, canonical
    signal input Q[2][8];     // the claimed result, supplied by the prover, canonical

    // The hint: magnitudes (each < 2^64, so one signal each) and signs.
    // Order: 0 = u1, 1 = u2, 2 = v1, 3 = v2.
    signal input mag[4];
    signal input sgn[4];

    var ordN[100] = get_secp256k1_order(64, 4);
    var prime[100] = get_secp256k1_prime32();
    var lam[4] = get_glv_lambda_limbs();
    var bet[100] = p256_split64to32(get_glv_beta_limbs());

    signal ordSig[4];
    signal primeSig[8];
    signal lamSig[4];
    signal betSig[8];
    for (var j = 0; j < 4; j++) {
        ordSig[j] <== ordN[j];
        lamSig[j] <== lam[j];
    }
    for (var j = 0; j < 8; j++) {
        primeSig[j] <== prime[j];
        betSig[j] <== bet[j];
    }

    // ---------- 1. the hint: bits, range, canonicalization ----------
    component n2b[4];
    component isz[4];
    for (var i = 0; i < 4; i++) {
        sgn[i] * (sgn[i] - 1) === 0;

        // Num2Bits(64) does two things at once: it checks mag[i] < 2^64 AND
        // produces the bits the loop consumes ("canonicality bits reused").
        n2b[i] = Num2Bits(64);
        n2b[i].in <== mag[i];

        // The sign of zero has to be pinned down: otherwise n - 0 == n falls
        // outside the range BigSubModP expects.
        isz[i] = IsZero();
        isz[i].in <== mag[i];
        sgn[i] * isz[i].out === 0;
    }

    // (v1, v2) != (0, 0) -- without it the relation says nothing about Q.
    isz[2].out * isz[3].out === 0;

    // ---------- 2. signed residues, in [0, n) ----------
    signal magLimb[4][4];
    for (var i = 0; i < 4; i++) {
        magLimb[i][0] <== mag[i];
        for (var j = 1; j < 4; j++) magLimb[i][j] <== 0;
    }

    component negm[4];
    signal r[4][4];
    for (var i = 0; i < 4; i++) {
        negm[i] = BigSub(64, 4);      // n - mag, no underflow: mag < 2^64 < n
        for (var j = 0; j < 4; j++) {
            negm[i].a[j] <== ordSig[j];
            negm[i].b[j] <== magLimb[i][j];
        }
        for (var j = 0; j < 4; j++) {
            r[i][j] <== magLimb[i][j] + sgn[i] * (negm[i].out[j] - magLimb[i][j]);
        }
    }

    // ---------- 3. s < n ----------
    // Not needed for soundness, but it makes the interface unambiguous.
    component sLtN = BigLessThan(64, 4);
    for (var j = 0; j < 4; j++) {
        sLtN.a[j] <== scalar[j];
        sLtN.b[j] <== ordSig[j];
    }
    sLtN.out === 1;

    // ---------- 4. the relation: u1 + u2*L == s*(v1 + v2*L) (mod n) ----------
    component sLam = BigMultModP(64, 4);   // s*L
    component u2L  = BigMultModP(64, 4);   // u2*L
    component sv1  = BigMultModP(64, 4);   // s*v1
    component sLv2 = BigMultModP(64, 4);   // (s*L)*v2
    for (var j = 0; j < 4; j++) {
        sLam.a[j] <== scalar[j];  sLam.b[j] <== lamSig[j];  sLam.p[j] <== ordSig[j];
        u2L.a[j]  <== r[1][j];    u2L.b[j]  <== lamSig[j];  u2L.p[j]  <== ordSig[j];
        sv1.a[j]  <== scalar[j];  sv1.b[j]  <== r[2][j];    sv1.p[j]  <== ordSig[j];
    }
    for (var j = 0; j < 4; j++) {
        sLv2.a[j] <== sLam.out[j]; sLv2.b[j] <== r[3][j];   sLv2.p[j] <== ordSig[j];
    }

    component lhs = AddModN();   // u1 + u2*L
    component rhs = AddModN();   // s*v1 + s*L*v2
    for (var j = 0; j < 4; j++) {
        lhs.x[j] <== r[0][j];      lhs.y[j] <== u2L.out[j];   lhs.m[j] <== ordSig[j];
        rhs.x[j] <== sv1.out[j];   rhs.y[j] <== sLv2.out[j];  rhs.m[j] <== ordSig[j];
    }
    for (var j = 0; j < 4; j++) {
        lhs.out[j] === rhs.out[j];
    }

    // ---------- 5. Q is on the curve ----------
    // Q comes from the prover; without this the soundness argument has no
    // group to work in.
    component qOn = Secp256k1PointOnCurve32();
    for (var j = 0; j < 8; j++) {
        qOn.x[j] <== Q[0][j];
        qOn.y[j] <== Q[1][j];
    }

    // ---------- 6. the four bases, sign folded into the point ----------
    // phi(X) = (beta*x mod p, y): one modular multiplication per point.
    component phiPx = Secp256k1MulModP32();
    component phiQx = Secp256k1MulModP32();
    for (var j = 0; j < 8; j++) {
        phiPx.a[j] <== betSig[j]; phiPx.b[j] <== P[0][j];
        phiQx.a[j] <== betSig[j]; phiQx.b[j] <== Q[0][j];
    }

    // y(phi(X)) == y(X), so one negation per point covers two bases.
    component negPy = BigSub(32, 8);
    component negQy = BigSub(32, 8);
    for (var j = 0; j < 8; j++) {
        negPy.a[j] <== primeSig[j]; negPy.b[j] <== P[1][j];
        negQy.a[j] <== primeSig[j]; negQy.b[j] <== Q[1][j];
    }

    // The Q terms enter the relation with a minus, so their sign is flipped:
    //   [u1]P + [u2]phi(P) - [v1]Q - [v2]phi(Q) == O
    signal A[4][2][8];
    for (var j = 0; j < 8; j++) {
        A[0][0][j] <== P[0][j];
        A[1][0][j] <== phiPx.out[j];
        A[2][0][j] <== Q[0][j];
        A[3][0][j] <== phiQx.out[j];

        A[0][1][j] <== P[1][j] + sgn[0] * (negPy.out[j] - P[1][j]);
        A[1][1][j] <== P[1][j] + sgn[1] * (negPy.out[j] - P[1][j]);
        A[2][1][j] <== negQy.out[j] + sgn[2] * (Q[1][j] - negQy.out[j]);
        A[3][1][j] <== negQy.out[j] + sgn[3] * (Q[1][j] - negQy.out[j]);
    }

    // ---------- 7. the loop + the =O assertion ----------
    component loop = GLV4StrausLoop(64);
    for (var i = 0; i < 4; i++) {
        for (var b = 0; b < 64; b++) {
            loop.bits[i][b] <== n2b[i].out[b];
        }
        for (var c = 0; c < 2; c++) {
            for (var j = 0; j < 8; j++) {
                loop.A[i][c][j] <== A[i][c][j];
            }
        }
    }
}
