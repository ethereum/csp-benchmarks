pragma circom 2.0.2;

/*
    P-256 scalar multiplication at witness-generation time, used to derive
    R = [u1]G + [u2]Q. Costs no constraints: every result enters the circuit
    through <-- and is checked by constraints that exist anyway.

    Jacobian coordinates, x = X/Z^2 and y = Y/Z^3, with one inversion at the
    end of the whole multiplication. Z == 0 is the point at infinity. The
    modular helpers are curve-agnostic; the doubling is specific to a = -3.
*/

include "./scalarmul_func.circom";
include "./p256_func.circom";
include "./bigint_func.circom";

// Doubling in Jacobian coordinates for a = -3:
//   delta = Z^2, gamma = Y^2, beta = X*gamma, alpha = 3*(X - delta)*(X + delta)
//   X3 = alpha^2 - 8*beta
//   Z3 = (Y + Z)^2 - gamma - delta
//   Y3 = alpha*(4*beta - X3) - 8*gamma^2
// Z == 0 stays 0: then delta == 0 and (Y + Z)^2 - gamma == 0.
// out[0] = X3, out[1] = Y3, out[2] = Z3
function p256_jac_double(N, K, X1, Y1, Z1, p) {
    var delta[100] = prod_mod_p(N, K, Z1, Z1, p);
    var gamma[100] = prod_mod_p(N, K, Y1, Y1, p);
    var beta[100] = prod_mod_p(N, K, X1, gamma, p);

    var xmd[100] = sm_sub_mod(N, K, X1, delta, p);
    var xpd[100] = sm_add_mod(N, K, X1, delta, p);
    var m1[100] = prod_mod_p(N, K, xmd, xpd, p);
    var m2[100] = sm_add_mod(N, K, m1, m1, p);
    var alpha[100] = sm_add_mod(N, K, m2, m1, p);

    var alphaSq[100] = prod_mod_p(N, K, alpha, alpha, p);
    var beta2[100] = sm_add_mod(N, K, beta, beta, p);
    var beta4[100] = sm_add_mod(N, K, beta2, beta2, p);
    var beta8[100] = sm_add_mod(N, K, beta4, beta4, p);
    var X3[100] = sm_sub_mod(N, K, alphaSq, beta8, p);

    var yz[100] = sm_add_mod(N, K, Y1, Z1, p);
    var yzSq[100] = prod_mod_p(N, K, yz, yz, p);
    var zPre[100] = sm_sub_mod(N, K, yzSq, gamma, p);
    var Z3[100] = sm_sub_mod(N, K, zPre, delta, p);

    var bx[100] = sm_sub_mod(N, K, beta4, X3, p);
    var abx[100] = prod_mod_p(N, K, alpha, bx, p);
    var gammaSq[100] = prod_mod_p(N, K, gamma, gamma, p);
    var g2[100] = sm_add_mod(N, K, gammaSq, gammaSq, p);
    var g4[100] = sm_add_mod(N, K, g2, g2, p);
    var g8[100] = sm_add_mod(N, K, g4, g4, p);
    var Y3[100] = sm_sub_mod(N, K, abx, g8, p);

    var out[3][100];
    for (var i = 0; i < 100; i++) {
        out[0][i] = 0;
        out[1][i] = 0;
        out[2][i] = 0;
    }
    for (var i = 0; i < K; i++) {
        out[0][i] = X3[i];
        out[1][i] = Y3[i];
        out[2][i] = Z3[i];
    }
    return out;
}

// Jacobian point plus affine point (x2, y2), with Z2 = 1. H == 0 means equal
// x: the same point (r == 0, answer is the doubling) or its negation (answer
// is infinity, Z == 0).
// out[0] = X3, out[1] = Y3, out[2] = Z3
function p256_jac_madd(N, K, X1, Y1, Z1, x2, y2, p) {
    var out[3][100];
    for (var i = 0; i < 100; i++) {
        out[0][i] = 0;
        out[1][i] = 0;
        out[2][i] = 0;
    }

    var Z1Z1[100] = prod_mod_p(N, K, Z1, Z1, p);
    var U2[100] = prod_mod_p(N, K, x2, Z1Z1, p);
    var y2z[100] = prod_mod_p(N, K, y2, Z1, p);
    var S2[100] = prod_mod_p(N, K, y2z, Z1Z1, p);

    var H[100] = sm_sub_mod(N, K, U2, X1, p);
    var rHalf[100] = sm_sub_mod(N, K, S2, Y1, p);
    var r[100] = sm_add_mod(N, K, rHalf, rHalf, p);

    var hIsZero = sm_is_zero(K, H);
    if (hIsZero == 1) {
        var rIsZero = sm_is_zero(K, r);
        if (rIsZero == 1) {
            var dbl[3][100] = p256_jac_double(N, K, X1, Y1, Z1, p);
            return dbl;
        }
        return out;
    }

    var HH[100] = prod_mod_p(N, K, H, H, p);
    var HH2[100] = sm_add_mod(N, K, HH, HH, p);
    var I[100] = sm_add_mod(N, K, HH2, HH2, p);
    var J[100] = prod_mod_p(N, K, H, I, p);
    var V[100] = prod_mod_p(N, K, X1, I, p);

    var rSq[100] = prod_mod_p(N, K, r, r, p);
    var rSqJ[100] = sm_sub_mod(N, K, rSq, J, p);
    var V2[100] = sm_add_mod(N, K, V, V, p);
    var X3[100] = sm_sub_mod(N, K, rSqJ, V2, p);

    var vx[100] = sm_sub_mod(N, K, V, X3, p);
    var rvx[100] = prod_mod_p(N, K, r, vx, p);
    var yj[100] = prod_mod_p(N, K, Y1, J, p);
    var yj2[100] = sm_add_mod(N, K, yj, yj, p);
    var Y3[100] = sm_sub_mod(N, K, rvx, yj2, p);

    var zh[100] = sm_add_mod(N, K, Z1, H, p);
    var zhSq[100] = prod_mod_p(N, K, zh, zh, p);
    var zPre[100] = sm_sub_mod(N, K, zhSq, Z1Z1, p);
    var Z3[100] = sm_sub_mod(N, K, zPre, HH, p);

    for (var i = 0; i < K; i++) {
        out[0][i] = X3[i];
        out[1][i] = Y3[i];
        out[2][i] = Z3[i];
    }
    return out;
}

// out[0] = x, out[1] = y, out[2][0] = 1 when the result is the point at infinity
function p256_scalarmul_func(N, K, scalar, x, y) {
    var p[100] = get_p256_prime(N, K);
    var px[100] = sm_reduce(N, K, x, p);
    var py[100] = sm_reduce(N, K, y, p);

    var accX[100];
    var accY[100];
    var accZ[100];
    for (var i = 0; i < 100; i++) {
        accX[i] = 0;
        accY[i] = 0;
        accZ[i] = 0;
    }

    for (var limb = K - 1; limb >= 0; limb--) {
        for (var bit = N - 1; bit >= 0; bit--) {
            var d[3][100] = p256_jac_double(N, K, accX, accY, accZ, p);
            accX = d[0];
            accY = d[1];
            accZ = d[2];

            var b = (scalar[limb] \ (1 << bit)) % 2;
            if (b == 1) {
                var atInfinity = sm_is_zero(K, accZ);
                if (atInfinity == 1) {
                    for (var i = 0; i < 100; i++) {
                        accX[i] = 0;
                        accY[i] = 0;
                        accZ[i] = 0;
                    }
                    for (var i = 0; i < K; i++) {
                        accX[i] = px[i];
                        accY[i] = py[i];
                    }
                    accZ[0] = 1;
                } else {
                    var a[3][100] = p256_jac_madd(N, K, accX, accY, accZ, px, py, p);
                    accX = a[0];
                    accY = a[1];
                    accZ = a[2];
                }
            }
        }
    }

    var out[3][100];
    for (var i = 0; i < 100; i++) {
        out[0][i] = 0;
        out[1][i] = 0;
        out[2][i] = 0;
    }

    var isInf = sm_is_zero(K, accZ);
    if (isInf == 1) {
        out[2][0] = 1;
        return out;
    }

    var zInv[100] = mod_inv(N, K, accZ, p);
    var zInv2[100] = prod_mod_p(N, K, zInv, zInv, p);
    var zInv3[100] = prod_mod_p(N, K, zInv2, zInv, p);
    var xAff[100] = prod_mod_p(N, K, accX, zInv2, p);
    var yAff[100] = prod_mod_p(N, K, accY, zInv3, p);
    for (var i = 0; i < K; i++) {
        out[0][i] = xAff[i];
        out[1][i] = yAff[i];
    }
    return out;
}

// R = [u1]G + [u2]Q. When R is the point at infinity the signature is invalid
// and zeros are returned; the constraints on R reject them.
function p256_ecdsa_R_func(N, K, u1, u2, qx, qy) {
    var out[2][100];
    for (var i = 0; i < 100; i++) {
        out[0][i] = 0;
        out[1][i] = 0;
    }
    var gx[100] = get_p256_gx(N, K);
    var gy[100] = get_p256_gy(N, K);

    var A[3][100] = p256_scalarmul_func(N, K, u1, gx, gy);
    var B[3][100] = p256_scalarmul_func(N, K, u2, qx, qy);

    if (A[2][0] == 1) {
        out[0] = B[0];
        out[1] = B[1];
        return out;
    }
    if (B[2][0] == 1) {
        out[0] = A[0];
        out[1] = A[1];
        return out;
    }

    var sameX = 1;
    var sameY = 1;
    for (var i = 0; i < K; i++) {
        if (A[0][i] != B[0][i]) { sameX = 0; }
        if (A[1][i] != B[1][i]) { sameY = 0; }
    }
    if (sameX == 1) {
        if (sameY == 1) {
            var d[2][100] = p256_double_func(N, K, A[0], A[1]);
            out[0] = d[0];
            out[1] = d[1];
        }
        return out;
    }
    var s[2][100] = p256_addunequal_func(N, K, A[0], A[1], B[0], B[1]);
    out[0] = s[0];
    out[1] = s[1];
    return out;
}
