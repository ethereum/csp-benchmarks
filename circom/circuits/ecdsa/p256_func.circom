pragma circom 2.0.2;

/*
    secp256r1 (NIST P-256) constants in 64-bit limbs, least significant first,
    and the affine point operations used at witness-generation time.

        p = 2^256 - 2^224 + 2^192 + 2^96 - 1,   a = -3,   cofactor 1

    Differences go through sm_sub_mod rather than long_sub_mod_p, which
    returns p instead of 0 when its operands are equal.
*/

include "./bigint_func.circom";
include "./scalarmul_func.circom";

function get_p256_prime(n, k) {
    assert(n == 64 && k == 4);
    var ret[100];
    for (var i = 0; i < 100; i++) { ret[i] = 0; }
    ret[0] = 18446744073709551615;
    ret[1] = 4294967295;
    ret[2] = 0;
    ret[3] = 18446744069414584321;
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
    assert(n == 64 && k == 4);
    var ret[100];
    for (var i = 0; i < 100; i++) { ret[i] = 0; }
    ret[0] = 4309448131093880907;
    ret[1] = 7285987128567378166;
    ret[2] = 12964664127075681980;
    ret[3] = 6540974713487397863;
    return ret;
}

function get_p256_gx(n, k) {
    assert(n == 64 && k == 4);
    var ret[100];
    for (var i = 0; i < 100; i++) { ret[i] = 0; }
    ret[0] = 17627433388654248598;
    ret[1] = 8575836109218198432;
    ret[2] = 17923454489921339634;
    ret[3] = 7716867327612699207;
    return ret;
}

function get_p256_gy(n, k) {
    assert(n == 64 && k == 4);
    var ret[100];
    for (var i = 0; i < 100; i++) { ret[i] = 0; }
    ret[0] = 14678990851816772085;
    ret[1] = 3156516839386865358;
    ret[2] = 10297457778147434006;
    ret[3] = 5756518291402817435;
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
    assert(n == 64 && k == 4);
    var ret[2][100];
    for (var i = 0; i < 100; i++) { ret[0][i] = 0; ret[1][i] = 0; }
    ret[0][0] = 11964737083406719352;
    ret[0][1] = 13873736548487404341;
    ret[0][2] = 9967090510939364035;
    ret[0][3] = 9003393950442278782;
    ret[1][0] = 11386427643415524305;
    ret[1][1] = 13438088067519447593;
    ret[1][2] = 2971701507003789531;
    ret[1][3] = 537992211385471040;
    return ret;
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

// (x1, y1) + (x2, y2) for x1 != x2 (mod p)
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

// 2*(x1, y1) on y^2 = x^3 - 3x + b: lambda = (3*x1^2 - 3) / (2*y1)
function p256_double_func(n, k, x1, y1) {
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

    var out[2][100];
    for (var i = 0; i < 100; i++) { out[0][i] = 0; out[1][i] = 0; }
    for (var i = 0; i < k; i++) { out[0][i] = x3[i]; out[1][i] = y3[i]; }
    return out;
}
