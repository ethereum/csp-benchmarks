#!/usr/bin/env python3
"""Check adapted canonicality, modular addition, and modular subtraction.

Pass compiled arithmetic_{k1p,k1n,p256p,p256n} directories containing their
R1CS, generated C++ data, and linked witness shared library.
"""

from __future__ import annotations

import importlib.util
import random
import sys
from pathlib import Path

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("hash_circuits", Path(__file__).with_name("hash-circuits.py"))
helpers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helpers)

MODULI = {
    "k1p": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
    "k1n": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
    "p256p": 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
    "p256n": 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
}


def limbs(value):
    return [(value >> (12*i)) & 4095 for i in range(22)]


def check(directory):
    directory = Path(directory).resolve()
    modulus = MODULI[directory.name.removeprefix("arithmetic_")]
    constraints = helpers.Constraints(directory / f"{directory.name}.r1cs", (44, 0))
    calculator = helpers.Calculator(directory, constraints)
    try:
        edges = [0, 1, 4095, 4096, modulus//2, modulus-2, modulus-1]
        pairs = [(a, b) for a in edges for b in edges]
        # Propagate a carry or borrow across every possible 12-bit boundary.
        for boundary in range(1, 22):
            power = 1 << (12*boundary)
            pairs.extend([(power-1, 1), (power, 1)])
        rng = random.Random(371)
        pairs += [(rng.randrange(modulus), rng.randrange(modulus)) for _ in range(64)]
        for a, b in pairs:
            witness = calculator.witness(limbs(a) + limbs(b), [])
            assert witness is not None, (a, b)
            assert witness[1:45] == limbs((a+b) % modulus) + limbs((a-b) % modulus)
            assert constraints.satisfied(witness)
        for invalid in (modulus, modulus+1, (1 << 256)-1):
            assert calculator.witness(limbs(invalid) + limbs(0), []) is None
        invalid_limb = limbs(0)
        invalid_limb[0] = 4096
        assert calculator.witness(invalid_limb + limbs(0), []) is None
        invalid_limb = limbs(0)
        invalid_limb[21] = 16
        assert calculator.witness(invalid_limb + limbs(0), []) is None
        witness[1] ^= 1
        assert not constraints.satisfied(witness)
        print(f"{directory.name}: {len(pairs)} canonical edge/random pairs passed bigint reference and R1CS checks; noncanonical values, limbs, and forged output rejected", flush=True)
    finally:
        calculator.close()


if __name__ == "__main__":
    assert len(sys.argv) > 1, __doc__
    for argument in sys.argv[1:]:
        check(argument)
