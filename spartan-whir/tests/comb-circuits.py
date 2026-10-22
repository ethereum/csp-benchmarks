#!/usr/bin/env python3
"""Validate both fixed-base combs against independent integer curve arithmetic.

Compile tests/ecdsa/comb_{k1,p256}.circom and their linked witness libraries
into matching comb_k1/comb_p256 directories. Pass those directories here.
The native libraries must include the compact table constructor used by the
benchmark; its values remain bound by the compiled R1CS lookup constraints.
"""

from __future__ import annotations

import importlib.util
import random
import sys
from pathlib import Path

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location(
    "ecdsa_circuits", Path(__file__).with_name("ecdsa-circuits.py")
)
assert spec and spec.loader
ecdsa = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ecdsa)
helpers = ecdsa.helpers

# These scalars make the final comb accumulation a doubling. Complete
# addition must handle them using the same group law as ordinary scalars.
FINAL_DOUBLE = {
    "comb_k1": 0xE00000000000000000000000000000014551231950B75FC4402DA1732FC9BEBF,
    "comb_p256": 0xE0000000FFFFFFFF00000000000000004319055258E8617B0C46353D039CDAAF,
}


def limbs(value):
    return [(value >> (12*i)) & 4095 for i in range(22)]


def check_recoding(value, order):
    """Check the integer prefix invariant independently of curve arithmetic."""
    folded = value if value & 1 else value+order
    assert 0 < folded < 2*order and folded & 1
    prefix = 0
    final = None
    for window in range(22):
        sign = 1 if window == 21 else (folded >> (12*window+12)) & 1
        index = sum((1-((folded >> (12*window+bit+1)) & 1)-sign
                     +2*((folded >> (12*window+bit+1)) & 1)*sign) << bit
                    for bit in range(11))
        digit = (2*sign-1)*(2*index+1)
        incoming = digit << (12*window)
        assert digit & 1 and 1 <= abs(digit) <= 4095
        if 1 <= window <= 20:
            assert prefix & 1 and incoming % 2 == 0
            assert 0 < abs(prefix) <= (1 << (12*window))-1
            bound = (1 << (12*(window+1)))-1
            assert bound < 1 << 252 < order
            assert 0 < abs(prefix+incoming) <= bound
            assert 0 < abs(prefix-incoming) <= bound
        if window == 21:
            final = prefix, incoming
        prefix += incoming
    assert prefix == folded
    return final


def check_addition(directory):
    """The finite helper itself rejects equal and inverse input points."""
    name = directory.name
    p256 = name == "comb_add_p256"
    p, n, a, gx, gy = ecdsa.CURVES["ecdsa_p256_32" if p256 else "ecdsa_32"]
    generator = (gx, gy)
    constraints = helpers.Constraints(directory/f"{name}.r1cs", (44, 0))
    calculator = helpers.Calculator(directory, constraints)
    pairs = [(1, 2), (1, 3), (n-1, 2), (n-2, 1), (n//2, 1),
             ((1 << 240)-1, 1 << 240), ((1 << 240)+1, n-(1 << 240)),
             ((1 << 252)-1, 1 << 252)]
    try:
        for left, right in pairs:
            aa = ecdsa.multiply(left, generator, p, a)
            bb = ecdsa.multiply(right, generator, p, a)
            expected = ecdsa.add(aa, bb, p, a)
            assert aa is not None and bb is not None and expected is not None
            assert aa[0] != bb[0]
            values = limbs(aa[0])+limbs(aa[1])+limbs(bb[0])+limbs(bb[1])
            witness = calculator.witness(values, [])
            assert witness is not None, calculator.error.value
            assert witness[1:45] == limbs(expected[0])+limbs(expected[1])
            assert constraints.satisfied(witness)
            forged = witness.copy()
            forged[1] ^= 1
            assert not constraints.satisfied(forged)
        for scalar in (1, 1 << 240):
            point = ecdsa.multiply(scalar, generator, p, a)
            assert point is not None
            for other in (point, (point[0], -point[1] % p)):
                values = limbs(point[0])+limbs(point[1])+limbs(other[0])+limbs(other[1])
                assert calculator.witness(values, []) is None
        print(f"{name}: {constraints.count} constraints; 8 unequal additions, forged outputs, and 4 equal/inverse rejections passed", flush=True)
    finally:
        calculator.close()


def check_window(directory):
    """Check every address against (2*index+1)G across the decoder split."""
    name = directory.name
    p256 = name == "comb_window_p256"
    p, _, a, gx, gy = ecdsa.CURVES["ecdsa_p256_32" if p256 else "ecdsa_32"]
    generator = (gx, gy)
    step = ecdsa.add(generator, generator, p, a)
    expected = generator
    constraints = helpers.Constraints(directory/f"{name}.r1cs", (44, 0))
    calculator = helpers.Calculator(directory, constraints)
    # Check the complete R1CS at both sides of each 8-bit decoder boundary,
    # together with the old 7-bit boundary and the extreme addresses.
    r1cs_indices = {0, 1, 127, 128, 2046, 2047}
    for boundary in range(256, 2048, 256):
        r1cs_indices.update((boundary-1, boundary, boundary+1))
    try:
        for index in range(2048):
            bits = [(index >> bit) & 1 for bit in range(11)]
            witness = calculator.witness(bits, [])
            assert witness is not None, (name, index, calculator.error.value)
            assert witness[1:45] == limbs(expected[0])+limbs(expected[1]), (name, index)
            if index in r1cs_indices:
                assert constraints.satisfied(witness), (name, index)
                forged = witness.copy()
                forged[1] ^= 1
                assert not constraints.satisfied(forged)
            expected = ecdsa.add(expected, step, p, a)
        for bit in range(11):
            invalid = [0]*11
            invalid[bit] = 2
            assert calculator.witness(invalid, []) is None, (name, bit)
        print(f"{name}: {constraints.count} constraints; 2048 lookup addresses, "
              f"{len(r1cs_indices)} full R1CS and forged outputs, and 11 nonbinary inputs passed",
              flush=True)
    finally:
        calculator.close()


def check(directory):
    directory = directory.resolve()
    name = directory.name
    if name in ("comb_window_k1", "comb_window_p256"):
        return check_window(directory)
    if name in ("comb_add_k1", "comb_add_p256"):
        return check_addition(directory)
    assert name in FINAL_DOUBLE, name
    p256 = name == "comb_p256"
    curve = ecdsa.CURVES["ecdsa_p256_32" if p256 else "ecdsa_32"]
    p, n, a, gx, gy = curve
    generator = (gx, gy)
    constraints = helpers.Constraints(directory/f"{name}.r1cs", (45, 0))
    calculator = helpers.Calculator(directory, constraints)
    rng = random.Random(13819+int(p256))
    # n-1 is even: adding n during parity folding must retain bit 256.
    values = [0, 1, 2, 3, 4095, 4096, n-2, n-1, 1 << 255, FINAL_DOUBLE[name]]
    values += [rng.randrange(n) for _ in range(8)]
    # Exercise both parities around every 12-bit comb-window boundary.
    for window in range(1, 22):
        boundary = 1 << (12*window)
        values.extend((boundary-1, boundary, boundary+1))
    values.extend(((1 << 253)-1, (1 << 253)+1))
    values = list(dict.fromkeys(values))
    try:
        for value in values:
            final_prefix, final_digit = check_recoding(value, n)
            if value == 0:
                assert (final_prefix+final_digit) % n == 0
            if value == FINAL_DOUBLE[name]:
                assert (final_prefix-final_digit) % n == 0
            witness = calculator.witness(limbs(value), [])
            assert witness is not None, (name, hex(value), calculator.error.value)
            expected = ecdsa.multiply(value, generator, p, a)
            coordinates = generator if expected is None else expected
            output = limbs(coordinates[0])+limbs(coordinates[1])+[int(expected is None)]
            assert witness[1:46] == output, (name, hex(value))
            assert constraints.satisfied(witness), (name, hex(value))
            forged = witness.copy()
            forged[1] ^= 1
            assert not constraints.satisfied(forged)
            if value in (0, 1, n-1, FINAL_DOUBLE[name]):
                forged = witness.copy()
                forged[45] ^= 1
                assert not constraints.satisfied(forged)
            print(f"{name}: k={value:#x}, reference, R1CS, and forged output checks passed", flush=True)
        for value in (n, n+1, (1 << 256)-1):
            assert calculator.witness(limbs(value), []) is None
        # Every limb remains bounded by KbCanonical after the parity
        # decomposition is restricted to k[0]. Reject both the first
        # out-of-range integer and a native field representative per limb.
        for limb in range(22):
            for value in ((16 if limb == 21 else 4096), helpers.KOALABEAR-1):
                invalid = limbs(0)
                invalid[limb] = value
                assert calculator.witness(invalid, []) is None, (name, limb, value)
        print(f"{name}: {constraints.count} constraints; {len(values)} valid and 47 invalid scalars passed; 4 forged infinity flags rejected", flush=True)
    finally:
        calculator.close()


if __name__ == "__main__":
    assert len(sys.argv) > 1, __doc__
    for argument in sys.argv[1:]:
        check(Path(argument))
