"""Independent integer reference for private comb/fake-GLV circuit inputs.

`augment(curve, values)` accepts the existing (p, n, a, gx, gy) curve tuple
and 160 byte-valued fields, and returns all 252 circuit input fields. Only
the standard library is required. The circuit must constrain these hints.
"""

from math import isqrt


def _add(left, right, prime, a):
    if left is None:
        return right
    if right is None:
        return left
    x, y = left
    xx, yy = right
    if x == xx:
        if (y + yy) % prime == 0:
            return None
        slope = (3*x*x + a) * pow(2*y, -1, prime) % prime
    else:
        slope = (yy-y) * pow(xx-x, -1, prime) % prime
    rx = (slope*slope-x-xx) % prime
    return rx, (slope*(x-rx)-y) % prime


def _multiply(scalar, point, prime, a):
    out = None
    while scalar:
        if scalar & 1:
            out = _add(out, point, prime, a)
        point = _add(point, point, prime, a)
        scalar >>= 1
    return out


def _eis_mul(left, right):
    x, y = left
    xx, yy = right
    return x*xx-y*yy, x*yy+y*xx-y*yy


def _eis_norm(value):
    x, y = value
    return x*x-x*y+y*y


def _round_div(value, denominator):
    quotient = (abs(value) + denominator//2)//denominator
    return -quotient if value < 0 else quotient


def _eis_quotient(left, right):
    x, y = right
    numerator = _eis_mul(left, (x-y, -y))
    denominator = _eis_norm(right)
    return tuple(_round_div(value, denominator) for value in numerator)


def _eis_add(left, right):
    return tuple(x+y for x, y in zip(left, right))


def _eis_sub(left, right):
    return tuple(x-y for x, y in zip(left, right))


def decompose_k1(scalar, order):
    """Eisenstein Euclid with the existing three-convergent short search."""
    if scalar == 0:
        return 0, 0, 1, 0
    assert 0 < scalar < order
    r0 = (367917413016453100223835821029139468248,
          64502973549206556628585045361533709077)
    r1, t0, t1 = (scalar, 0), (0, 0), (1, 0)
    rows, cross = [], None
    while r1 != (0, 0):
        if cross is None and _eis_norm(r1) < 1 << 128:
            cross = len(rows)
        rows.append((r1, t1))
        quotient = _eis_quotient(r0, r1)
        r0, r1 = r1, _eis_sub(r0, _eis_mul(quotient, r1))
        t0, t1 = t1, _eis_sub(t0, _eis_mul(quotient, t1))
    if cross is None:
        cross = len(rows)-1
    lo, hi = max(0, cross-1), min(len(rows)-1, cross+1)
    coefficients = [(x, y) for x in range(-1, 2) for y in range(-1, 2)]
    best, best_bits = None, 1000

    def consider(u, v):
        nonlocal best, best_bits
        if v != (0, 0):
            values = (*u, *v)
            bits = max(abs(x).bit_length() for x in values)
            if bits < best_bits:
                best, best_bits = values, bits

    for i in range(lo, hi+1):
        u, v = rows[i]
        for alpha in coefficients:
            if alpha != (0, 0):
                consider(_eis_mul(u, alpha), _eis_mul(v, alpha))
        if i < hi:
            uu, vv = rows[i+1]
            for alpha in coefficients:
                au, av = _eis_mul(u, alpha), _eis_mul(v, alpha)
                for beta in coefficients:
                    if alpha != (0, 0) or beta != (0, 0):
                        consider(_eis_add(au, _eis_mul(uu, beta)),
                                 _eis_add(av, _eis_mul(vv, beta)))
    assert best_bits <= 64, "fake-GLV search exceeded the component bound"
    lam = 0x5363AD4CC05C30E0A5261C028812645A122E22EA20816678DF02967C1B23BD72
    a, b, c, d = best
    assert (c+d*lam) % order != 0
    assert (a+b*lam-scalar*(c+d*lam)) % order == 0
    return best


def decompose_p256(scalar, order):
    assert 0 <= scalar < order
    r0, r1, t0, t1 = order, scalar, 0, 1
    while r1 > isqrt(order):
        quotient = r0//r1
        r0, r1 = r1, r0-quotient*r1
        t0, t1 = t1, t0-quotient*t1
    assert max(abs(r1), abs(t1)) < 1 << 128
    assert t1 != 0 and (r1-scalar*t1) % order == 0
    return r1, t1, 0, 0


def augment(curve, values):
    prime, order, a, gx, gy = curve
    assert len(values) == 160 and all(0 <= value < 256 for value in values)
    digest, qx, qy, r, s = [
        int.from_bytes(bytes(values[i:i+32]), "little")
        for i in range(0, 160, 32)
    ]
    inverse = pow(s, -1, order)
    u1, u2 = digest*inverse % order, r*inverse % order
    result = _add(_multiply(u1, (gx, gy), prime, a),
                  _multiply(u2, (qx, qy), prime, a), prime, a)
    assert result is not None
    decomposition = (decompose_p256(u2, order) if a == -3
                     else decompose_k1(u2, order))
    limbs = lambda value, count: [(abs(value) >> (12*i)) & 4095
                                 for i in range(count)]
    return (list(values)
            + sum((limbs(value, 22) for value in result), [])
            + sum((limbs(value, 11) for value in decomposition), [])
            + [int(value < 0) for value in decomposition])
