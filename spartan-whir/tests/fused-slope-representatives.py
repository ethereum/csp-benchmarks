#!/usr/bin/env python3
"""Check fused ECDSA slope bounds and noncanonical representatives.

Pass compiled fused_k1 and/or quad_p256 probe directories. Temporary witness
generators lift a zero chord slope by p, add p or 255*p to all slopes, or force
their highest limb to 8. Their R1CS equations must match the production probe.
"""

from __future__ import annotations

import importlib.util
import os
import random
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True
TESTS = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("fused_point_circuits", TESTS/"fused-point-circuits.py")
assert spec and spec.loader
fused = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fused)
spec = importlib.util.spec_from_file_location("run_probes", TESTS/"ecdsa/run-probes.py")
assert spec and spec.loader
probes = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probes)


def symbols(directory):
    result = {}
    for line in (directory/f"{directory.name}.sym").read_text().splitlines():
        _, wire, _, name = line.split(",", 3)
        if int(wire) > 0:
            result[name] = int(wire)
    return result


def suffix_wire(entries, suffix):
    matches = [wire for name, wire in entries.items() if name.endswith("."+suffix)]
    assert len(matches) == 1, (suffix, matches)
    return matches[0]


def compile_variant(output, mode, probe="quad_p256"):
    p256 = probe == "quad_p256"
    circuits = TESTS.parent/"circuits/ecdsa"
    circuit = "p256_quad" if p256 else "k1_double_add"
    source = (circuits/f"{circuit}.circom").read_text()
    assignment = "value[row][j] <-- hint[row][j];"
    assert source.count(assignment) == 1
    # The added code changes witness computations only. Dependent convolution,
    # normalization, quotient, and carry witnesses are generated normally.
    anchor = ("    // Rows: initial slope, xD, first fused slope, xS, final slope, xout,yout."
              if p256 else "    // Rows: first slope, xS, second slope, xout, yout.")
    assert source.count(anchor) == 1
    if mode == "top8":
        changed_hints = """    for (var row = 0; row <= LAST_ROW; row += 2) {
        hint[row][23] = 8;
    }
"""
    else:
        assert mode in ("zero_plus_p", "plus_p", "plus_255p"), mode
        first_row = (2 if p256 else 0) if mode == "zero_plus_p" else 0
        last_row = first_row if mode == "zero_plus_p" else (4 if p256 else 2)
        changed_hints = """    var liftPrime[24] = kb_fused_prime11_for(CURVE);
    for (var row = FIRST_ROW; row <= LAST_ROW; row += 2) {
        var carry = 0;
        for (var j = 0; j < 24; j++) {
            var digit = hint[row][j]+liftPrime[j]*LIFT_MULTIPLE+carry;
            hint[row][j] = digit % 2048;
            carry = digit \\ 2048;
        }
    }
""".replace("CURVE", str(int(p256))).replace("FIRST_ROW", str(first_row)).replace(
            "LAST_ROW", str(last_row)).replace("LIFT_MULTIPLE", "255" if mode == "plus_255p" else "1")
    changed_hints = changed_hints.replace("LAST_ROW", "4" if p256 else "2")
    source = source.replace(anchor, changed_hints+anchor)
    source = source.replace('include "fused_arithmetic.circom";',
                            f'include "{circuits/"fused_arithmetic.circom"}";')
    changed_source = output/f"{circuit}_lifted.circom"
    changed_source.write_text(source)
    wrapper = (circuits/"fused.circom").read_text()
    wrapper = wrapper.replace('include "curve.circom";', f'include "{circuits/"curve.circom"}";')
    wrapper = wrapper.replace(f'include "{circuit}.circom";', f'include "{changed_source}";')
    # Includes used by the secp256k1 implementation remain relative to its source.
    for line in tuple(wrapper.splitlines()):
        if line.startswith('include "'):
            include = line.split('"')[1]
            if not Path(include).is_absolute():
                wrapper = wrapper.replace(line, f'include "{circuits/include}";')
    (output/"fused_lifted.circom").write_text(wrapper)
    name = output.name
    (output/f"{name}.circom").write_text(
        f'pragma circom 2.2.0;\ninclude "{output/"fused_lifted.circom"}";\n'
        f'component main = {"KbPointQuadAdd(1)" if p256 else "KbPointDoubleAdd(0)"};\n')
    circom = os.environ.get("SPARTAN_WHIR_CIRCOM", "circom")
    probes.command_with_log([circom, str(output/f"{name}.circom"), "--prime", "koalabear",
                             "--r1cs", "--c", "--sym", "--O1", "-o", str(output)], output/"circom.log")
    cpp = output/f"{name}_cpp"
    command = [os.environ.get("CXX", "c++"), *probes.CXX_FLAGS, "-I", str(cpp)]
    for include in ("/opt/homebrew/include", "/usr/local/include"):
        if Path(include).is_dir():
            command += ["-I", include]
    command += [str(cpp/file) for file in ("calcwit.cpp", "fr.cpp", "main.cpp", f"{name}.cpp")]
    for library in ("/opt/homebrew/lib", "/usr/local/lib"):
        if Path(library).is_dir():
            command += ["-L", library]
    command += ["-lgmp", "-dynamiclib" if sys.platform == "darwin" else "-shared"]
    extension = "dylib" if sys.platform == "darwin" else "so"
    command += ["-o", str(output/f"lib{name}_witness.{extension}")]
    probes.command_with_log(command, output/"cxx.log")


def slope(witness, entries, row):
    return sum(witness[suffix_wire(entries, f"value[{row}][{limb}]")] << (11*limb)
               for limb in range(24))


def horizontal_chord_cases(p256, curve):
    """Construct actual curve points with a zero slope in an active chord."""
    p, n, a, gx, gy = curve
    generator = gx, gy
    if p256:
        curve_b = (gy*gy-gx*gx*gx-a*gx) % p
        # For D=(x,y), the other intersections of its horizontal line solve
        # X^2+x*X+x^2+a=0, whose discriminant is -3*x^2-4*a.
        for x in range(100):
            yy = (x*x*x+a*x+curve_b) % p
            y = pow(yy, (p+1)//4, p)
            discriminant = (-3*x*x-4*a) % p
            root = pow(discriminant, (p+1)//4, p)
            if y and y*y % p == yy and root*root % p == discriminant:
                other_x = (-x+root)*pow(2, -1, p) % p
                if other_x != x:
                    doubled = x, y
                    point_a = fused.ecdsa.multiply((n+1)//2, doubled, p, a)
                    assert point_a and fused.ecdsa.add(point_a, point_a, p, a) == doubled
                    point_b = other_x, y
                    assert (point_b[1]**2-point_b[0]**3-a*point_b[0]-curve_b) % p == 0
                    break
        else:
            raise AssertionError("No P-256 horizontal chord found")
    else:
        beta = pow(2, (p-1)//3, p)
        assert beta != 1 and pow(beta, 3, p) == 1
        point_a = generator
        point_b = beta*gx % p, gy
        assert point_b[0] != point_a[0]
        assert (point_b[1]**2-point_b[0]**3-7) % p == 0
    # Negation supplies a second coordinate pair with the same
    # zero chord slope; the unreduced representative p still fits in 256 bits.
    return [(point_a, point_b), ((point_a[0], -point_a[1] % p),
                                (point_b[0], -point_b[1] % p))]


def check(ordinary):
    assert ordinary.name in ("quad_p256", "fused_k1"), ordinary
    p256 = ordinary.name == "quad_p256"
    rows = (0, 2, 4) if p256 else (0, 2)
    original = fused.ecdsa.helpers.sections((ordinary/f"{ordinary.name}.r1cs").read_bytes(), b"r1cs")
    curve = fused.ecdsa.CURVES["ecdsa_p256_32" if p256 else "ecdsa_32"]
    p, n, a, gx, gy = curve
    generator = gx, gy
    rng = random.Random(839)
    scalars = [(7, 11), (7, 7), (7, -21), (7, -7 if p256 else -28)]
    scalars += [(rng.randrange(1, n), rng.randrange(1, n)) for _ in range(12)]
    cases = [(fused.ecdsa.multiply(left % n, generator, p, a),
              fused.ecdsa.multiply(right % n, generator, p, a)) for left, right in scalars]
    horizontal = horizontal_chord_cases(p256, curve)
    target_row = 2 if p256 else 0
    ordinary_constraints = fused.ecdsa.helpers.Constraints(ordinary/f"{ordinary.name}.r1cs", (45, 0))
    ordinary_calculator = fused.ecdsa.helpers.Calculator(ordinary, ordinary_constraints)
    ordinary_entries = symbols(ordinary)
    inputs = []
    try:
        for point_a, point_b in cases+horizontal:
            assert point_a and point_b
            repeated_a = fused.ecdsa.multiply(4 if p256 else 2, point_a, p, a)
            expected = fused.ecdsa.add(repeated_a, point_b, p, a)
            assert expected
            values = sum(map(fused.limbs, (*point_a, *point_b)), [])+[0, 0]
            outputs = sum(map(fused.limbs, expected), [])+[0]
            witness = ordinary_calculator.witness(values, [])
            assert witness is not None, ordinary_calculator.error.value
            assert witness[1:46] == outputs and ordinary_constraints.satisfied(witness)
            slopes = [slope(witness, ordinary_entries, row) for row in rows]
            assert all(0 <= value < p for value in slopes), slopes
            if len(inputs) >= len(cases):
                assert slope(witness, ordinary_entries, target_row) == 0
            inputs.append((values, outputs, slopes))
    finally:
        ordinary_calculator.close()
    with tempfile.TemporaryDirectory(prefix="spartan-whir-fused-slopes-") as temporary:
        for mode in ("zero_plus_p", "plus_p", "plus_255p", "top8"):
            directory = Path(temporary)/f"{ordinary.name}_{mode}"
            directory.mkdir()
            compile_variant(directory, mode, ordinary.name)
            changed = fused.ecdsa.helpers.sections((directory/f"{directory.name}.r1cs").read_bytes(), b"r1cs")
            assert original[1] == changed[1], "Changed hints changed R1CS header"
            assert original[2] == changed[2], "Changed hints changed R1CS equations"
            constraints = fused.ecdsa.helpers.Constraints(directory/f"{directory.name}.r1cs", (45, 0))
            calculator = fused.ecdsa.helpers.Calculator(directory, constraints)
            entries = symbols(directory)
            mutations = [suffix_wire(entries, f"value[{row}][{limb}]")
                         for row in rows for limb in (0, 23)]
            selected = inputs[len(cases):] if mode == "zero_plus_p" else inputs
            try:
                for index, (values, outputs, slopes) in enumerate(selected):
                    witness = calculator.witness(values, [])
                    if mode != "zero_plus_p":
                        if mode in ("plus_p", "plus_255p"):
                            multiple = 255 if mode == "plus_255p" else 1
                            assert any(value+multiple*p >= 1 << 256 for value in slopes), (mode, slopes)
                        assert witness is None or not constraints.satisfied(witness), (mode, index)
                        continue
                    assert witness is not None, (mode, index, calculator.error.value)
                    assert witness[1:46] == outputs and constraints.satisfied(witness), (mode, index)
                    assert slope(witness, entries, target_row) == p < 1 << 256
                    for wire in mutations:
                        saved = witness[wire]
                        witness[wire] = (saved+1) % constraints.prime
                        assert not constraints.satisfied(witness)
                        witness[wire] = saved
                if mode == "zero_plus_p":
                    print(f"{ordinary.name}: identical R1CS accepts {len(selected)} zero chord slopes "
                          f"represented by p and rejects {len(selected)*len(mutations)} slope mutations", flush=True)
                else:
                    print(f"{ordinary.name}: identical R1CS rejects {len(selected)} {mode} slope hints "
                          "above the 256-bit bound", flush=True)
            finally:
                calculator.close()


if __name__ == "__main__":
    assert len(sys.argv) > 1, __doc__
    for argument in sys.argv[1:]:
        check(Path(argument).resolve())
