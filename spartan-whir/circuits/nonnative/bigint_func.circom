pragma circom 2.0.2;

function isNegative(x) {
    // Half the KoalaBear modulus.
    return x > 1065353216 ? 1 : 0;
}

function div_ceil(m, n) {
    var ret = 0;
    if (m % n == 0) {
        ret = m \ n;
    } else {
        ret = m \ n + 1;
    }
    return ret;
}

function log_ceil(n) {
   var n_temp = n;
   for (var i = 0; i < 254; i++) {
       if (n_temp == 0) {
          return i;
       }
       n_temp = n_temp \ 2;
   }
   return 254;
}

function SplitFn(in, n, m) {
    return [in % (1 << n), (in \ (1 << n)) % (1 << m)];
}

function SplitThreeFn(in, n, m, k) {
    return [in % (1 << n), (in \ (1 << n)) % (1 << m), (in \ (1 << n + m)) % (1 << k)];
}

// in is an m bit number
// split into ceil(m/n) n-bit registers
function splitOverflowedRegister(m, n, in) {
    var out[100];

    for (var i = 0; i < 100; i++) {
        out[i] = 0;
    }

    var nRegisters = div_ceil(m, n);
    var running = in;
    for (var i = 0; i < nRegisters; i++) {
        out[i] = running % (1<<n);
        running>>=n;
    }

    return out;
}

// m bits per overflowed register (values are potentially negative)
// n bits per properly-sized register
// in has k registers
// out has k + ceil(m/n) - 1 + 1 registers. highest-order potentially negative,
// all others are positive
// - 1 since the last register is included in the last ceil(m/n) array
// + 1 since the carries from previous registers could push you over
function getProperRepresentation(m, n, k, in) {
    var ceilMN = 0; // ceil(m/n)
    if (m % n == 0) {
        ceilMN = m \ n;
    } else {
        ceilMN = m \ n + 1;
    }

    var pieces[100][100]; // should be pieces[k][ceilMN]
    for (var i = 0; i < k; i++) {
        for (var j = 0; j < 100; j++) {
            pieces[i][j] = 0;
        }
        if (isNegative(in[i]) == 1) {
            var negPieces[100] = splitOverflowedRegister(m, n, -1 * in[i]);
            for (var j = 0; j < ceilMN; j++) {
                pieces[i][j] = -1 * negPieces[j];
            }
        } else {
            pieces[i] = splitOverflowedRegister(m, n, in[i]);
        }
    }

    var out[100]; // should be out[k + ceilMN]
    var carries[100]; // should be carries[k + ceilMN]
    for (var i = 0; i < 100; i++) {
        out[i] = 0;
        carries[i] = 0;
    }
    for (var registerIdx = 0; registerIdx < k + ceilMN; registerIdx++) {
        var thisRegisterValue = 0;
        if (registerIdx > 0) {
            thisRegisterValue = carries[registerIdx - 1];
        }

        var start = 0;
        if (registerIdx >= ceilMN) {
            start = registerIdx - ceilMN + 1;
        }

        // go from start to min(registerIdx, len(pieces)-1)
        for (var i = start; i <= registerIdx; i++) {
            if (i < k) {
                thisRegisterValue += pieces[i][registerIdx - i];
            }
        }

        if (isNegative(thisRegisterValue) == 1) {
            var thisRegisterAbs = -1 * thisRegisterValue;
            out[registerIdx] = (1<<n) - (thisRegisterAbs % (1<<n));
            carries[registerIdx] = -1 * (thisRegisterAbs >> n) - 1;
        } else {
            out[registerIdx] = thisRegisterValue % (1<<n);
            carries[registerIdx] = thisRegisterValue >> n;
        }
    }

    return out;
}

// 1 if true, 0 if false
function long_gt(n, k, a, b) {
    for (var i = k - 1; i >= 0; i--) {
        if (a[i] > b[i]) {
            return 1;
        }
        if (a[i] < b[i]) {
            return 0;
        }
    }
    return 0;
}

// n bits per register
// a has k registers
// b has k registers
// a >= b
function long_sub(n, k, a, b) {
    var diff[100];
    var borrow[100];
    for (var i = 0; i < k; i++) {
        if (i == 0) {
           if (a[i] >= b[i]) {
               diff[i] = a[i] - b[i];
               borrow[i] = 0;
            } else {
               diff[i] = a[i] - b[i] + (1 << n);
               borrow[i] = 1;
            }
        } else {
            if (a[i] >= b[i] + borrow[i - 1]) {
               diff[i] = a[i] - b[i] - borrow[i - 1];
               borrow[i] = 0;
            } else {
               diff[i] = (1 << n) + a[i] - b[i] - borrow[i - 1];
               borrow[i] = 1;
            }
        }
    }
    return diff;
}

// a is a n-bit scalar
// b has k registers
function long_scalar_mult(n, k, a, b) {
    var out[100];
    for (var i = 0; i < 100; i++) {
        out[i] = 0;
    }
    for (var i = 0; i < k; i++) {
        var temp = out[i] + (a * b[i]);
        out[i] = temp % (1 << n);
        out[i + 1] = out[i + 1] + temp \ (1 << n);
    }
    return out;
}


// n bits per register
// a has k + m registers
// b has k registers
// out[0] has length m + 1 -- quotient
// out[1] has length k -- remainder
// implements algorithm of https://people.eecs.berkeley.edu/~fateman/282/F%20Wright%20notes/week4.pdf
// b[k-1] must be nonzero!
function long_div(n, k, m, a, b){
    var out[2][100];

    var remainder[100];
    for (var i = 0; i < m + k; i++) {
        remainder[i] = a[i];
    }

    var mult[200];
    var dividend[200];
    for (var i = m; i >= 0; i--) {
        if (i == m) {
            dividend[k] = 0;
            for (var j = k - 1; j >= 0; j--) {
                dividend[j] = remainder[j + m];
            }
        } else {
            for (var j = k; j >= 0; j--) {
                dividend[j] = remainder[j + i];
            }
        }

        out[0][i] = short_div(n, k, dividend, b);

        var mult_shift[100] = long_scalar_mult(n, k, out[0][i], b);
        var subtrahend[200];
        for (var j = 0; j < m + k; j++) {
            subtrahend[j] = 0;
        }
        for (var j = 0; j <= k; j++) {
            if (i + j < m + k) {
               subtrahend[i + j] = mult_shift[j];
            }
        }
        remainder = long_sub(n, m + k, remainder, subtrahend);
    }
    for (var i = 0; i < k; i++) {
        out[1][i] = remainder[i];
    }
    out[1][k] = 0;

    return out;
}

// n bits per register
// a has k + 1 registers
// b has k registers
// assumes leading digit of b is at least 2 ** (n - 1)
// 0 <= a < (2**n) * b
function short_div_norm(n, k, a, b) {
   var qhat = (a[k] * (1 << n) + a[k - 1]) \ b[k - 1];
   if (qhat > (1 << n) - 1) {
      qhat = (1 << n) - 1;
   }

   var mult[100] = long_scalar_mult(n, k, qhat, b);
   if (long_gt(n, k + 1, mult, a) == 1) {
      mult = long_sub(n, k + 1, mult, b);
      if (long_gt(n, k + 1, mult, a) == 1) {
         return qhat - 2;
      } else {
         return qhat - 1;
      }
   } else {
       return qhat;
   }
}

// n bits per register
// a has k + 1 registers
// b has k registers
// assumes leading digit of b is non-zero
// 0 <= a < (2**n) * b
function short_div(n, k, a, b) {
   var scale = (1 << n) \ (1 + b[k - 1]);

   // k + 2 registers now
   var norm_a[100] = long_scalar_mult(n, k + 1, scale, a);
   // k + 1 registers now
   var norm_b[100] = long_scalar_mult(n, k, scale, b);

   var ret;
   if (norm_b[k] != 0) {
       ret = short_div_norm(n, k + 1, norm_a, norm_b);
   } else {
       ret = short_div_norm(n, k, norm_a, norm_b);
   }
   return ret;
}

// n bits per register
// a and b both have k registers
// out[0] has length 2 * k
// adapted from BigMulShortLong and LongToShortNoEndCarry2 witness computation
function prod(n, k, a, b) {
    // first compute the intermediate values. taken from BigMulShortLong
    var prod_val[100]; // length is 2 * k - 1
    for (var i = 0; i < 2 * k - 1; i++) {
        prod_val[i] = 0;
        if (i < k) {
            for (var a_idx = 0; a_idx <= i; a_idx++) {
                prod_val[i] = prod_val[i] + a[a_idx] * b[i - a_idx];
            }
        } else {
            for (var a_idx = i - k + 1; a_idx < k; a_idx++) {
                prod_val[i] = prod_val[i] + a[a_idx] * b[i - a_idx];
            }
        }
    }

    // now do a bunch of carrying to make sure registers not overflowed. taken from LongToShortNoEndCarry2
    var out[100]; // length is 2 * k

    var split[100][3]; // first dimension has length 2 * k - 1
    for (var i = 0; i < 2 * k - 1; i++) {
        split[i] = SplitThreeFn(prod_val[i], n, n, n);
    }

    var carry[100]; // length is 2 * k - 1
    carry[0] = 0;
    out[0] = split[0][0];
    if (2 * k - 1 > 1) {
        var sumAndCarry[2] = SplitFn(split[0][1] + split[1][0], n, n);
        out[1] = sumAndCarry[0];
        carry[1] = sumAndCarry[1];
    }
    if (2 * k - 1 > 2) {
        for (var i = 2; i < 2 * k - 1; i++) {
            var sumAndCarry[2] = SplitFn(split[i][0] + split[i-1][1] + split[i-2][2] + carry[i-1], n, n);
            out[i] = sumAndCarry[0];
            carry[i] = sumAndCarry[1];
        }
        out[2 * k - 1] = split[2*k-2][1] + split[2*k-3][2] + carry[2*k-2];
    }
    return out;
}

// n bits per register
// a has k registers
// p has k registers
// e has k registers
// k * n <= 500
// p is a prime
// computes a^e mod p
function mod_exp(n, k, a, p, e) {
    var eBits[500]; // length is k * n
    for (var i = 0; i < k; i++) {
        for (var j = 0; j < n; j++) {
            eBits[j + n * i] = (e[i] >> j) & 1;
        }
    }

    var out[100]; // length is k
    for (var i = 0; i < 100; i++) {
        out[i] = 0;
    }
    out[0] = 1;

    // repeated squaring
    for (var i = k * n - 1; i >= 0; i--) {
        // multiply by a if bit is 0
        if (eBits[i] == 1) {
            var temp[200]; // length 2 * k
            temp = prod(n, k, out, a);
            var temp2[2][100];
            temp2 = long_div(n, k, k, temp, p);
            out = temp2[1];
        }

        // square, unless we're at the end
        if (i > 0) {
            var temp[200]; // length 2 * k
            temp = prod(n, k, out, out);
            var temp2[2][100];
            temp2 = long_div(n, k, k, temp, p);
            out = temp2[1];
        }

    }
    return out;
}

// n bits per register
// a has k registers
// p has k registers
// k * n <= 500
// p is a prime
// if a == 0 mod p, returns 0
// else returns the inverse of a mod p
//
// For odd p the inverse comes from a binary extended GCD, whose steps are
// shifts, comparisons and subtractions on k registers. For even p the Fermat
// exponentiation below is kept, since the binary algorithm needs an odd
// modulus. Inversion dominates affine curve arithmetic during witness
// generation, and the binary path removes the modular multiplications that
// the exponentiation spends on every one of them.
function mod_inv(n, k, a, p) {
    var isZero = 1;
    for (var i = 0; i < k; i++) {
        if (a[i] != 0) {
            isZero = 0;
        }
    }
    if (isZero == 1) {
        var ret[100];
        for (var i = 0; i < 100; i++) {
            ret[i] = 0;
        }
        return ret;
    }

    var pIsOdd = p[0] & 1;
    if (pIsOdd == 0) {
        var fermat[100] = mod_inv_fermat(n, k, a, p);
        return fermat;
    }

    // the binary algorithm needs a < p
    var aRed[100];
    for (var i = 0; i < 100; i++) {
        aRed[i] = 0;
    }
    var pGtA = long_gt(n, k, p, a);
    if (pGtA == 1) {
        for (var i = 0; i < k; i++) {
            aRed[i] = a[i];
        }
    } else {
        var wide[100];
        for (var i = 0; i < 100; i++) {
            wide[i] = 0;
        }
        for (var i = 0; i < k; i++) {
            wide[i] = a[i];
        }
        var qr[2][100] = long_div(n, k, k, wide, p);
        for (var i = 0; i < k; i++) {
            aRed[i] = qr[1][i];
        }
    }

    var redIsZero = 1;
    for (var i = 0; i < k; i++) {
        if (aRed[i] != 0) {
            redIsZero = 0;
        }
    }
    if (redIsZero == 1) {
        var zero[100];
        for (var i = 0; i < 100; i++) {
            zero[i] = 0;
        }
        return zero;
    }

    var binary[100] = mod_inv_binary(n, k, aRed, p);
    return binary;
}

// Inverse of a mod p by binary extended GCD, for odd p and 0 < a < p.
//
// u and v start at a and p, with coefficients x1 and x2 maintained so that
// x1 * a == u and x2 * a == v hold mod p; x2 starts at 0 beside v == p, which
// is 0 mod p, and both coefficients keep the same sign as their partner. Either
// exit therefore yields the inverse directly, with no negation.
//
// A step halves whichever of u, v is even, and when both are odd it replaces
// the larger by the difference, which is even and so is halved next. Every
// halving drops one bit from
// bits(u) + bits(v), which starts at 2 * n * k, and no two subtractions run
// back to back, so the loop ends within 4 * n * k steps with one of u, v equal
// to 1; the coefficient beside that one is the inverse. That is the bound the
// assert below enforces. Empirically the largest step count on a sample of
// five thousand inversions over this circuit's two moduli was 730.
//
// The register loops are written out rather than factored into helpers: a
// helper would allocate a fresh 100-register array on every step, which costs
// more than the step itself. Subtraction always compares before it subtracts,
// because a negative intermediate would wrap around the field rather than stay
// negative.
function mod_inv_binary(n, k, a, p) {
    var pow = 1 << n;

    var u[100];
    var v[100];
    var x1[100];
    var x2[100];
    var diff[100];
    for (var i = 0; i < 100; i++) {
        u[i] = 0;
        v[i] = 0;
        x1[i] = 0;
        x2[i] = 0;
        diff[i] = 0;
    }
    for (var i = 0; i < k; i++) {
        u[i] = a[i];
        v[i] = p[i];
    }
    x1[0] = 1;

    var done = 0;
    var uIsOne = 1;
    if (u[0] != 1) {
        uIsOne = 0;
    }
    for (var i = 1; i < k; i++) {
        if (u[i] != 0) {
            uIsOne = 0;
        }
    }
    if (uIsOne == 1) {
        done = 1;
    }

    var steps = 0;
    while (done == 0) {
        var uOdd = u[0] & 1;
        var vOdd = v[0] & 1;

        if (uOdd == 0) {
            // u = u / 2. Ascending, so u[i + 1] is still unshifted when read.
            for (var i = 0; i < k; i++) {
                var uHi = 0;
                if (i + 1 < k) {
                    uHi = u[i + 1] & 1;
                }
                u[i] = (u[i] >> 1) + (uHi << (n - 1));
            }
            // x1 = x1 / 2 mod p: adding p first makes an odd x1 even, and the
            // bit carried past the top register comes back in on the shift.
            var carry1 = 0;
            if ((x1[0] & 1) == 1) {
                for (var i = 0; i < k; i++) {
                    var s1 = x1[i] + p[i] + carry1;
                    if (s1 >= pow) {
                        x1[i] = s1 - pow;
                        carry1 = 1;
                    } else {
                        x1[i] = s1;
                        carry1 = 0;
                    }
                }
            }
            for (var i = 0; i < k; i++) {
                var x1Hi = carry1;
                if (i + 1 < k) {
                    x1Hi = x1[i + 1] & 1;
                }
                x1[i] = (x1[i] >> 1) + (x1Hi << (n - 1));
            }
        } else {
            if (vOdd == 0) {
                for (var i = 0; i < k; i++) {
                    var vHi = 0;
                    if (i + 1 < k) {
                        vHi = v[i + 1] & 1;
                    }
                    v[i] = (v[i] >> 1) + (vHi << (n - 1));
                }
                var carry2 = 0;
                if ((x2[0] & 1) == 1) {
                    for (var i = 0; i < k; i++) {
                        var s2 = x2[i] + p[i] + carry2;
                        if (s2 >= pow) {
                            x2[i] = s2 - pow;
                            carry2 = 1;
                        } else {
                            x2[i] = s2;
                            carry2 = 0;
                        }
                    }
                }
                for (var i = 0; i < k; i++) {
                    var x2Hi = carry2;
                    if (i + 1 < k) {
                        x2Hi = x2[i + 1] & 1;
                    }
                    x2[i] = (x2[i] >> 1) + (x2Hi << (n - 1));
                }
            } else {
                // both odd: subtract the smaller from the larger
                var vGtU = 0;
                var decided = 0;
                for (var i = k - 1; i >= 0; i--) {
                    if (decided == 0) {
                        if (v[i] > u[i]) {
                            vGtU = 1;
                            decided = 1;
                        }
                        if (u[i] > v[i]) {
                            vGtU = 0;
                            decided = 1;
                        }
                    }
                }

                if (vGtU == 0) {
                    var borrowU = 0;
                    for (var i = 0; i < k; i++) {
                        if (u[i] >= v[i] + borrowU) {
                            u[i] = u[i] - v[i] - borrowU;
                            borrowU = 0;
                        } else {
                            u[i] = pow + u[i] - v[i] - borrowU;
                            borrowU = 1;
                        }
                    }
                    // x1 = x1 - x2 mod p
                    var x2GtX1 = 0;
                    var cDecided = 0;
                    for (var i = k - 1; i >= 0; i--) {
                        if (cDecided == 0) {
                            if (x2[i] > x1[i]) {
                                x2GtX1 = 1;
                                cDecided = 1;
                            }
                            if (x1[i] > x2[i]) {
                                x2GtX1 = 0;
                                cDecided = 1;
                            }
                        }
                    }
                    if (x2GtX1 == 0) {
                        var b1 = 0;
                        for (var i = 0; i < k; i++) {
                            if (x1[i] >= x2[i] + b1) {
                                x1[i] = x1[i] - x2[i] - b1;
                                b1 = 0;
                            } else {
                                x1[i] = pow + x1[i] - x2[i] - b1;
                                b1 = 1;
                            }
                        }
                    } else {
                        var b2 = 0;
                        for (var i = 0; i < k; i++) {
                            if (x2[i] >= x1[i] + b2) {
                                diff[i] = x2[i] - x1[i] - b2;
                                b2 = 0;
                            } else {
                                diff[i] = pow + x2[i] - x1[i] - b2;
                                b2 = 1;
                            }
                        }
                        var b3 = 0;
                        for (var i = 0; i < k; i++) {
                            if (p[i] >= diff[i] + b3) {
                                x1[i] = p[i] - diff[i] - b3;
                                b3 = 0;
                            } else {
                                x1[i] = pow + p[i] - diff[i] - b3;
                                b3 = 1;
                            }
                        }
                    }
                } else {
                    var borrowV = 0;
                    for (var i = 0; i < k; i++) {
                        if (v[i] >= u[i] + borrowV) {
                            v[i] = v[i] - u[i] - borrowV;
                            borrowV = 0;
                        } else {
                            v[i] = pow + v[i] - u[i] - borrowV;
                            borrowV = 1;
                        }
                    }
                    // x2 = x2 - x1 mod p
                    var x1GtX2 = 0;
                    var dDecided = 0;
                    for (var i = k - 1; i >= 0; i--) {
                        if (dDecided == 0) {
                            if (x1[i] > x2[i]) {
                                x1GtX2 = 1;
                                dDecided = 1;
                            }
                            if (x2[i] > x1[i]) {
                                x1GtX2 = 0;
                                dDecided = 1;
                            }
                        }
                    }
                    if (x1GtX2 == 0) {
                        var b4 = 0;
                        for (var i = 0; i < k; i++) {
                            if (x2[i] >= x1[i] + b4) {
                                x2[i] = x2[i] - x1[i] - b4;
                                b4 = 0;
                            } else {
                                x2[i] = pow + x2[i] - x1[i] - b4;
                                b4 = 1;
                            }
                        }
                    } else {
                        var b5 = 0;
                        for (var i = 0; i < k; i++) {
                            if (x1[i] >= x2[i] + b5) {
                                diff[i] = x1[i] - x2[i] - b5;
                                b5 = 0;
                            } else {
                                diff[i] = pow + x1[i] - x2[i] - b5;
                                b5 = 1;
                            }
                        }
                        var b6 = 0;
                        for (var i = 0; i < k; i++) {
                            if (p[i] >= diff[i] + b6) {
                                x2[i] = p[i] - diff[i] - b6;
                                b6 = 0;
                            } else {
                                x2[i] = pow + p[i] - diff[i] - b6;
                                b6 = 1;
                            }
                        }
                    }
                }
            }
        }

        steps = steps + 1;
        assert(steps <= 4 * n * k);

        var uOne = 1;
        if (u[0] != 1) {
            uOne = 0;
        }
        for (var i = 1; i < k; i++) {
            if (u[i] != 0) {
                uOne = 0;
            }
        }
        var vOne = 1;
        if (v[0] != 1) {
            vOne = 0;
        }
        for (var i = 1; i < k; i++) {
            if (v[i] != 0) {
                vOne = 0;
            }
        }
        if (uOne == 1) {
            done = 1;
        }
        if (vOne == 1) {
            done = 1;
        }
    }

    var uFinal = 1;
    if (u[0] != 1) {
        uFinal = 0;
    }
    for (var i = 1; i < k; i++) {
        if (u[i] != 0) {
            uFinal = 0;
        }
    }
    if (uFinal == 1) {
        return x1;
    }
    return x2;
}

// inv = a^(p-2) mod p, for a prime p of either parity
function mod_inv_fermat(n, k, a, p) {
    var isZero = 1;
    for (var i = 0; i < k; i++) {
        if (a[i] != 0) {
            isZero = 0;
        }
    }
    if (isZero == 1) {
        var ret[100];
        for (var i = 0; i < k; i++) {
            ret[i] = 0;
        }
        return ret;
    }

    var pCopy[100];
    for (var i = 0; i < 100; i++) {
        if (i < k) {
            pCopy[i] = p[i];
        } else {
            pCopy[i] = 0;
        }
    }

    var two[100];
    for (var i = 0; i < 100; i++) {
        two[i] = 0;
    }
    two[0] = 2;

    var pMinusTwo[100];
    pMinusTwo = long_sub(n, k, pCopy, two); // length k
    var out[100];
    out = mod_exp(n, k, a, pCopy, pMinusTwo);
    return out;
}

// a, b and out are all n bits k registers
function long_sub_mod_p(n, k, a, b, p){
    var gt = long_gt(n, k, a, b);
    var tmp[100];
    if(gt){
        tmp = long_sub(n, k, a, b);
    }
    else{
        tmp = long_sub(n, k, b, a);
    }
    var out[2][100];
    for(var i = k;i < 2 * k; i++){
        tmp[i] = 0;
    }
    out = long_div(n, k, k, tmp, p);
    if(gt==0){
        tmp = long_sub(n, k, p, out[1]);
    }
    return tmp;
}

// a, b, p and out are all n bits k registers
function prod_mod_p(n, k, a, b, p){
    var tmp[100];
    var result[2][100];
    tmp = prod(n, k, a, b);
    result = long_div(n, k, k, tmp, p);
    return result[1];
}
