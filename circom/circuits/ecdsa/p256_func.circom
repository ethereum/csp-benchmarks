pragma circom 2.0.2;

/*
    secp256r1 (NIST P-256) constants, least significant limb first, and the
    affine point operations used at witness-generation time.

        p = 2^256 - 2^224 + 2^192 + 2^96 - 1,   a = -3,   cofactor 1

    Two limb layouts are in use. Point coordinates live in (32, 8) inside the
    circuit: p is aligned to 32 bits, which keeps the reduction coefficients
    small. Scalars modulo n, and the witness-time point arithmetic, use
    (64, 4). The base-field getters serve both layouts; n and isqrt(n) are
    (64, 4) only.

    Differences go through sm_sub_mod rather than long_sub_mod_p, which
    returns p instead of 0 when its operands are equal.
*/

include "./bigint_func.circom";
include "./scalarmul_func.circom";

function get_p256_prime(n, k) {
    assert((n == 64 && k == 4) || (n == 32 && k == 8));
    var ret[100];
    for (var i = 0; i < 100; i++) { ret[i] = 0; }
    if (n == 64) {
        ret[0] = 18446744073709551615;
        ret[1] = 4294967295;
        ret[2] = 0;
        ret[3] = 18446744069414584321;
    } else {
        ret[0] = 4294967295;
        ret[1] = 4294967295;
        ret[2] = 4294967295;
        ret[3] = 0;
        ret[4] = 0;
        ret[5] = 0;
        ret[6] = 1;
        ret[7] = 4294967295;
    }
    return ret;
}

function get_p256_order(n, k) {
    assert(n == 64 && k == 4);
    var ret[100];
    for (var i = 0; i < 100; i++) { ret[i] = 0; }
    ret[0] = 17562291160714782033;
    ret[1] = 13611842547513532036;
    ret[2] = 18446744073709551615;
    ret[3] = 18446744069414584320;
    return ret;
}

function get_p256_b(n, k) {
    assert((n == 64 && k == 4) || (n == 32 && k == 8));
    var ret[100];
    for (var i = 0; i < 100; i++) { ret[i] = 0; }
    if (n == 64) {
        ret[0] = 4309448131093880907;
        ret[1] = 7285987128567378166;
        ret[2] = 12964664127075681980;
        ret[3] = 6540974713487397863;
    } else {
        ret[0] = 668098635;
        ret[1] = 1003371582;
        ret[2] = 3428036854;
        ret[3] = 1696401072;
        ret[4] = 1989707452;
        ret[5] = 3018571093;
        ret[6] = 2855965671;
        ret[7] = 1522939352;
    }
    return ret;
}

function get_p256_gx(n, k) {
    assert((n == 64 && k == 4) || (n == 32 && k == 8));
    var ret[100];
    for (var i = 0; i < 100; i++) { ret[i] = 0; }
    if (n == 64) {
        ret[0] = 17627433388654248598;
        ret[1] = 8575836109218198432;
        ret[2] = 17923454489921339634;
        ret[3] = 7716867327612699207;
    } else {
        ret[0] = 3633889942;
        ret[1] = 4104206661;
        ret[2] = 770388896;
        ret[3] = 1996717441;
        ret[4] = 1671708914;
        ret[5] = 4173129445;
        ret[6] = 3777774151;
        ret[7] = 1796723186;
    }
    return ret;
}

function get_p256_gy(n, k) {
    assert((n == 64 && k == 4) || (n == 32 && k == 8));
    var ret[100];
    for (var i = 0; i < 100; i++) { ret[i] = 0; }
    if (n == 64) {
        ret[0] = 14678990851816772085;
        ret[1] = 3156516839386865358;
        ret[2] = 10297457778147434006;
        ret[3] = 5756518291402817435;
    } else {
        ret[0] = 935285237;
        ret[1] = 3417718888;
        ret[2] = 1798397646;
        ret[3] = 734933847;
        ret[4] = 2081398294;
        ret[5] = 2397563722;
        ret[6] = 4263149467;
        ret[7] = 1340293858;
    }
    return ret;
}

// floor(sqrt(n)). n is not a perfect square, so r < sqrt(n) exactly when
// r <= floor(sqrt(n)). Below 2^128.
function get_p256_isqrt_order() {
    var ret[100];
    for (var i = 0; i < 100; i++) { ret[i] = 0; }
    ret[0] = 6917529028446388223;
    ret[1] = 18446744071562067968;
    return ret;
}

// [2]G: a fixed canonical point whose x coordinate differs from G's. Supplies
// distinct-x operands to P256AddUnequal where an exceptional addition is
// selected away.
function get_p256_dummy_point(n, k) {
    assert((n == 64 && k == 4) || (n == 32 && k == 8));
    var ret[2][100];
    for (var i = 0; i < 100; i++) { ret[0][i] = 0; ret[1][i] = 0; }
    if (n == 64) {
        ret[0][0] = 11964737083406719352;
        ret[0][1] = 13873736548487404341;
        ret[0][2] = 9967090510939364035;
        ret[0][3] = 9003393950442278782;
        ret[1][0] = 11386427643415524305;
        ret[1][1] = 13438088067519447593;
        ret[1][2] = 2971701507003789531;
        ret[1][3] = 537992211385471040;
    } else {
        ret[0][0] = 1197906296;
        ret[0][1] = 2785757436;
        ret[0][2] = 2012355381;
        ret[0][3] = 3230231010;
        ret[0][4] = 78977731;
        ret[0][5] = 2320644099;
        ret[0][6] = 2365804414;
        ret[0][7] = 2096266008;
        ret[1][0] = 578319313;
        ret[1][1] = 2651109277;
        ret[1][2] = 1021936169;
        ret[1][3] = 3128798694;
        ret[1][4] = 2675192027;
        ret[1][5] = 691903174;
        ret[1][6] = 3683569728;
        ret[1][7] = 125261072;
    }
    return ret;
}

// Four 64-bit limbs to eight 32-bit limbs, for witness-time results computed in
// (64, 4) that are assigned to (32, 8) signals.
function p256_split64to32(x) {
    var out[100];
    for (var i = 0; i < 100; i++) { out[i] = 0; }
    for (var i = 0; i < 4; i++) {
        out[2 * i] = x[i] % (1 << 32);
        out[2 * i + 1] = x[i] \ (1 << 32);
    }
    return out;
}

// The k low limbs of x, zero-extended and reduced mod p. The sm_* helpers
// assume operands below p.
function p256_load(n, k, x, p) {
    var t[100];
    for (var i = 0; i < 100; i++) { t[i] = 0; }
    for (var i = 0; i < k; i++) { t[i] = x[i]; }
    var r[100] = sm_reduce(n, k, t, p);
    return r;
}

// (x1, y1) + (x2, y2) for x1 != x2 (mod p), in either layout
function p256_addunequal_func(n, k, x1, y1, x2, y2) {
    var p[100] = get_p256_prime(n, k);
    var ax[100] = p256_load(n, k, x1, p);
    var ay[100] = p256_load(n, k, y1, p);
    var bx[100] = p256_load(n, k, x2, p);
    var by[100] = p256_load(n, k, y2, p);

    var dy[100] = sm_sub_mod(n, k, by, ay, p);
    var dx[100] = sm_sub_mod(n, k, bx, ax, p);
    var dxInv[100] = mod_inv(n, k, dx, p);
    var lambda[100] = prod_mod_p(n, k, dy, dxInv, p);

    var lambdaSq[100] = prod_mod_p(n, k, lambda, lambda, p);
    var x3Pre[100] = sm_sub_mod(n, k, lambdaSq, ax, p);
    var x3[100] = sm_sub_mod(n, k, x3Pre, bx, p);

    var dx3[100] = sm_sub_mod(n, k, ax, x3, p);
    var ldx[100] = prod_mod_p(n, k, lambda, dx3, p);
    var y3[100] = sm_sub_mod(n, k, ldx, ay, p);

    var out[2][100];
    for (var i = 0; i < 100; i++) { out[0][i] = 0; out[1][i] = 0; }
    for (var i = 0; i < k; i++) { out[0][i] = x3[i]; out[1][i] = y3[i]; }
    return out;
}

// 2*(x1, y1) + (x2, y2) as (P + Q) + P, without the y of P + Q. Returns the
// two slopes and x of P + Q along with the result:
// [lambda1, x3, lambda2, x4, y4], with
//   lambda1 = (y2 - y1) / (x2 - x1),   x3 = lambda1^2 - x1 - x2,
//   lambda2 = -lambda1 - 2*y1 / (x3 - x1),
//   x4 = lambda2^2 - x1 - x3,   y4 = lambda2*(x1 - x4) - y1.
function p256_double_add_func(n, k, x1, y1, x2, y2) {
    var p[100] = get_p256_prime(n, k);
    var ax[100] = p256_load(n, k, x1, p);
    var ay[100] = p256_load(n, k, y1, p);
    var bx[100] = p256_load(n, k, x2, p);
    var by[100] = p256_load(n, k, y2, p);

    var dy[100] = sm_sub_mod(n, k, by, ay, p);
    var dx[100] = sm_sub_mod(n, k, bx, ax, p);
    var dxInv[100] = mod_inv(n, k, dx, p);
    var l1[100] = prod_mod_p(n, k, dy, dxInv, p);

    var l1Sq[100] = prod_mod_p(n, k, l1, l1, p);
    var x3Pre[100] = sm_sub_mod(n, k, l1Sq, ax, p);
    var x3[100] = sm_sub_mod(n, k, x3Pre, bx, p);

    var d3[100] = sm_sub_mod(n, k, x3, ax, p);
    var d3Inv[100] = mod_inv(n, k, d3, p);
    var twoY[100] = sm_add_mod(n, k, ay, ay, p);
    var q[100] = prod_mod_p(n, k, twoY, d3Inv, p);
    var zero[100];
    for (var i = 0; i < 100; i++) { zero[i] = 0; }
    var negL1[100] = sm_sub_mod(n, k, zero, l1, p);
    var l2[100] = sm_sub_mod(n, k, negL1, q, p);

    var l2Sq[100] = prod_mod_p(n, k, l2, l2, p);
    var x4Pre[100] = sm_sub_mod(n, k, l2Sq, ax, p);
    var x4[100] = sm_sub_mod(n, k, x4Pre, x3, p);

    var d4[100] = sm_sub_mod(n, k, ax, x4, p);
    var ld[100] = prod_mod_p(n, k, l2, d4, p);
    var y4[100] = sm_sub_mod(n, k, ld, ay, p);

    var out[5][100];
    for (var i = 0; i < 100; i++) {
        for (var r = 0; r < 5; r++) { out[r][i] = 0; }
    }
    for (var i = 0; i < k; i++) {
        out[0][i] = l1[i];
        out[1][i] = x3[i];
        out[2][i] = l2[i];
        out[3][i] = x4[i];
        out[4][i] = y4[i];
    }
    return out;
}

// 2*(x1, y1) on y^2 = x^3 - 3x + b, in either layout
function p256_double_func(n, k, x1, y1) {
    var t[3][100] = p256_double_slope_func(n, k, x1, y1);
    var out[2][100];
    for (var i = 0; i < 100; i++) { out[0][i] = t[1][i]; out[1][i] = t[2][i]; }
    return out;
}

// 2*(x1, y1) with its tangent slope: [lambda, x3, y3], with
// lambda = (3*x1^2 - 3) / (2*y1), in either layout
function p256_double_slope_func(n, k, x1, y1) {
    var p[100] = get_p256_prime(n, k);
    var ax[100] = p256_load(n, k, x1, p);
    var ay[100] = p256_load(n, k, y1, p);

    var three[100];
    for (var i = 0; i < 100; i++) { three[i] = 0; }
    three[0] = 3;

    var xx[100] = prod_mod_p(n, k, ax, ax, p);
    var xx2[100] = sm_add_mod(n, k, xx, xx, p);
    var xx3[100] = sm_add_mod(n, k, xx2, xx, p);
    var num[100] = sm_sub_mod(n, k, xx3, three, p);
    var den[100] = sm_add_mod(n, k, ay, ay, p);
    var denInv[100] = mod_inv(n, k, den, p);
    var lambda[100] = prod_mod_p(n, k, num, denInv, p);

    var lambdaSq[100] = prod_mod_p(n, k, lambda, lambda, p);
    var x3Pre[100] = sm_sub_mod(n, k, lambdaSq, ax, p);
    var x3[100] = sm_sub_mod(n, k, x3Pre, ax, p);

    var dx3[100] = sm_sub_mod(n, k, ax, x3, p);
    var ldx[100] = prod_mod_p(n, k, lambda, dx3, p);
    var y3[100] = sm_sub_mod(n, k, ldx, ay, p);

    var out[3][100];
    for (var i = 0; i < 100; i++) { out[0][i] = 0; out[1][i] = 0; out[2][i] = 0; }
    for (var i = 0; i < k; i++) { out[0][i] = lambda[i]; out[1][i] = x3[i]; out[2][i] = y3[i]; }
    return out;
}
