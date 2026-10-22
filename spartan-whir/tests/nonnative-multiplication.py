#!/usr/bin/env python3
"""Validate modular multiplication against Python integers and every R1CS row.

Compile tests/nonnative/multiplication_{k1p,k1n,p256p,p256n}.circom with
--sym and its linked witness library into matching directories. Pass those
directories here. Coefficient forgeries use the compiler's symbol map.
"""

from __future__ import annotations

import importlib.util
import random
import sys
from pathlib import Path

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location(
    "nonnative_arithmetic", Path(__file__).with_name("nonnative-arithmetic.py")
)
assert spec and spec.loader
arithmetic = importlib.util.module_from_spec(spec)
spec.loader.exec_module(arithmetic)
helpers = arithmetic.helpers


def check(directory):
    directory = Path(directory).resolve()
    name = directory.name
    modulus = arithmetic.MODULI[name.removeprefix("multiplication_")]
    constraints = helpers.Constraints(directory/f"{name}.r1cs", (22, 0))
    calculator = helpers.Calculator(directory, constraints)
    try:
        limit = (1 << 256)-1
        edges = [0, 1, 2, 4095, 4096, modulus//2, modulus-1, limit]
        pairs = [(a, b) for a in edges for b in edges]
        for boundary in range(1, 22):
            power = 1 << (12*boundary)
            pairs.extend([(power-1, power-1), (power-1, limit),
                          (power, power), (modulus-power, modulus-power)])
        rng = random.Random(57021)
        pairs += [(rng.randrange(1 << 256), rng.randrange(1 << 256))
                  for _ in range(128)]
        for a, b in pairs:
            witness = calculator.witness(arithmetic.limbs(a)+arithmetic.limbs(b), [])
            assert witness is not None, (name, a, b, calculator.error.value)
            assert witness[1:23] == arithmetic.limbs(a*b % modulus), (name, a, b)
            assert constraints.satisfied(witness), (name, a, b)

        symbols = {}
        for line in (directory/f"{name}.sym").read_text().splitlines():
            _, wire, _, symbol = line.split(",", 3)
            symbols[symbol] = int(wire)
        for index in range(43):
            wire = symbols[f"main.mul.convolution[{index}]"]
            assert wire > 0, (name, index, wire)
            forged = witness.copy()
            forged[wire] ^= 1
            assert not constraints.satisfied(forged), (name, index)
        for index in range(1, 23):
            forged = witness.copy()
            forged[index] ^= 1
            assert not constraints.satisfied(forged), (name, index)

        for value, index in [(4096, 0), (16, 21)]:
            invalid = arithmetic.limbs(0)+arithmetic.limbs(0)
            invalid[index] = value
            assert calculator.witness(invalid, []) is None, (name, index, value)
        print(f"{name}: {len(pairs)} boundary/random products passed integer reference "
              f"and all {constraints.count} R1CS equations; 43 coefficient forgeries, "
              "22 output forgeries, and invalid limbs rejected", flush=True)
    finally:
        calculator.close()


if __name__ == "__main__":
    assert len(sys.argv) > 1, __doc__
    for argument in sys.argv[1:]:
        check(argument)
