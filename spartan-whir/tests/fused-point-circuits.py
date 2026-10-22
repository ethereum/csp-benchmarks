#!/usr/bin/env python3
"""Validate native KbPointDoubleAdd/KbPointQuadAdd probes and all equations.

Pass compiled fused_k1/fused_p256 or quad_k1/quad_p256 directories.
"""

from __future__ import annotations

import importlib.util
import random
import sys
from pathlib import Path

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("ecdsa_circuits", Path(__file__).with_name("ecdsa-circuits.py"))
assert spec and spec.loader
ecdsa = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ecdsa)


def limbs(value):
    return [(value >> (12*i)) & 4095 for i in range(22)]


def internal_wires(directory):
    if directory.name not in ("quad_p256", "fused_k1", "quad_k1"):
        return []
    symbols = directory/f"{directory.name}.sym"
    assert symbols.is_file(), f"Compile with --sym: {symbols}"
    entries = {}
    for line in symbols.read_text().splitlines():
        _, wire, _, name = line.split(",", 3)
        if int(wire) > 0:
            entries[name] = int(wire)
    if directory.name == "quad_p256":
        suffixes = (
            "initialTangent.check.qMagnitude[0]", "initialTangent.check.qSign",
            "initialTangent.check.carry[1]", "firstSlope.check.qMagnitude[0]", "firstSlope.check.carry[1]",
            "yWide.digitRange[0].out[0]", "yWide.carry[1]",
            "value[0][0]", "value[2][0]", "value[4][0]", "equalY", "ordinary2",
        )
    else:
        suffixes = (
            "firstSlope.qMagnitude[0]", "firstSlope.qSign", "firstSlope.carry[1]",
            "firstChord.qMagnitude[0]", "secondSlope.qMagnitude[0]",
            "secondChord.carry[1]", "finalLine.qSign",
            "value[0][0]", "value[1][0]", "value[2][0]", "value[3][0]", "value[4][0]",
            "tangent", "cancel", "ordinary2", "finite2",
        )
    selected = []
    for suffix in suffixes:
        matches = [(name, wire) for name, wire in entries.items() if name.endswith("."+suffix)]
        assert len(matches) == 1, (suffix, matches)
        selected.append(matches[0])
    return selected


def check(directory):
    p256 = "p256" in directory.name
    factor = 4 if directory.name.startswith("quad") else 2
    p, n, a, gx, gy = ecdsa.CURVES["ecdsa_p256_32" if p256 else "ecdsa_32"]
    generator = gx, gy
    multiply = lambda k: ecdsa.multiply(k % n, generator, p, a)
    cases = [("ordinary", 7, 11), ("equal points", 7, 7),
             ("opposite points", 7, -7), ("zero output", 7, -factor*7),
             ("left infinity", 0, 7), ("right infinity", 7, 0),
             ("left infinity negative", 0, -7), ("right infinity negative", -7, 0),
             ("both infinity", 0, 0), ("negative output", 7, -(factor+1)*7)]
    if factor == 4:
        cases += [("B=2A first tangent", 7, 14),
                  ("B=-2A first cancellation", 7, -14),
                  ("B=-4A second cancellation", 7, -28),
                  ("B=-6A", 7, -42)]
    rng = random.Random(739)
    cases += [(f"random {i}", rng.randrange(1, n), rng.randrange(1, n)) for i in range(20)]
    constraints = ecdsa.helpers.Constraints(directory/f"{directory.name}.r1cs", (45, 0))
    calculator = ecdsa.helpers.Calculator(directory, constraints)
    mutations = internal_wires(directory)
    try:
        for name, left_scalar, right_scalar in cases:
            left, right = multiply(left_scalar), multiply(right_scalar)
            point_a, point_b = left or generator, right or generator
            values = sum(map(limbs, (*point_a, *point_b)), [])+[int(left is None), int(right is None)]
            expected = multiply(factor*left_scalar+right_scalar)
            expected_point = expected or generator
            witness = calculator.witness(values, [])
            assert witness is not None, (name, calculator.error.value)
            outputs = sum(map(limbs, expected_point), [])+[int(expected is None)]
            assert witness[1:46] == outputs, name
            assert constraints.satisfied(witness), name
            for symbol, wire in mutations:
                saved = witness[wire]
                witness[wire] = (saved+1) % constraints.prime
                assert not constraints.satisfied(witness), (name, symbol)
                witness[wire] = saved
            witness[1] ^= 1
            assert not constraints.satisfied(witness), name
            witness[1] ^= 1
            witness[45] ^= 1
            assert not constraints.satisfied(witness), (name, "forged infinity output")
        print(f"{directory.name}: {len(cases)} complete group cases passed integer reference, all R1CS equations, forged-output rejection, and {len(cases)*len(mutations)} internal wire mutations", flush=True)
    finally:
        calculator.close()


if __name__ == "__main__":
    assert len(sys.argv) > 1, __doc__
    for argument in sys.argv[1:]:
        check(Path(argument).resolve())
