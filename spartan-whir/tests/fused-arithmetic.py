#!/usr/bin/env python3
"""Validate signed 11-bit modular certificates using Python integer arithmetic.

Pass a compiled fused_modzero11 directory containing its R1CS, symbol map,
generated C++ data, and linked native witness library.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("hash_circuits", Path(__file__).with_name("hash-circuits.py"))
assert spec and spec.loader
helpers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helpers)
P256 = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
K1 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
BOUND = 502825083
BASE = 2048


def check(directory):
    modulus = K1 if directory.name.endswith("_k1") else P256
    prime = [(modulus >> (11*i)) & 2047 for i in range(24)]
    cases = [("zero", [0]*71)]
    for shift in (0, 47):
        coefficients = [0]*71
        coefficients[shift:shift+24] = prime
        cases += [(f"positive quotient at limb {shift}", coefficients),
                  (f"negative quotient at limb {shift}", [-c for c in coefficients])]
    dense = [0]*71
    for i in range(48):
        for j in range(24):
            dense[i+j] += 2047*prime[j]
    cases += [("dense maximum quotient digits", dense),
              ("dense negative quotient digits", [-c for c in dense])]
    carried = dense.copy()
    for i in range(70):
        carry = 190000 if i % 2 == 0 else -190000
        carried[i] += BASE*carry
        carried[i+1] -= carry
    cases += [("alternating signed carries", carried),
              ("negative alternating signed carries", [-c for c in carried])]
    boundary = [0]*71
    boundary[0], boundary[1] = 245520*BASE, -245520
    cases += [("coefficient near positive bound", boundary),
              ("coefficient near negative bound", [-c for c in boundary])]
    constraints = helpers.Constraints(directory/f"{directory.name}.r1cs", (0, 0))
    calculator = helpers.Calculator(directory, constraints)
    entries = {}
    for line in (directory/f"{directory.name}.sym").read_text().splitlines():
        _, wire, _, name = line.split(",", 3)
        if int(wire) > 0:
            entries[name] = int(wire)
    mutations = []
    for suffix in ("qMagnitude[0]", "qMagnitude[47]", "qSign", "carry[1]", "carry[70]"):
        matches = [wire for name, wire in entries.items() if name.endswith(f".{suffix}")]
        assert len(matches) == 1, (suffix, matches)
        mutations.append(matches[0])
    try:
        for name, coefficients in cases:
            assert all(abs(c) <= BOUND for c in coefficients), name
            integer = sum(c*BASE**i for i, c in enumerate(coefficients))
            assert integer % modulus == 0, name
            values = [c % constraints.prime for c in coefficients]
            witness = calculator.witness(values, [])
            assert witness is not None, (name, calculator.error.value)
            assert constraints.satisfied(witness), name
            for wire in mutations:
                saved = witness[wire]
                witness[wire] = (saved+1) % constraints.prime
                assert not constraints.satisfied(witness), (name, wire)
                witness[wire] = saved
            altered = values.copy()
            altered[0] = (altered[0]+1) % constraints.prime
            forged = calculator.witness(altered, [])
            assert forged is None or not constraints.satisfied(forged), name
        print(f"{directory.name}: {len(cases)} signed quotient/carry/boundary cases passed integer and R1CS checks; {len(cases)*len(mutations)} internal mutations and altered residues rejected", flush=True)
    finally:
        calculator.close()


if __name__ == "__main__":
    assert len(sys.argv) > 1, __doc__
    for argument in sys.argv[1:]:
        check(Path(argument).resolve())
