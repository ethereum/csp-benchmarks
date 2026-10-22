#!/usr/bin/env python3
"""Check KbFakeGlvVerify probes using independent integer curve arithmetic.

Compile main=KbFakeGlvVerify(0/1) to fakeglv_k1/fakeglv_p256, including the
linked native witness library. Pass the two R1CS paths to this script.
"""

from __future__ import annotations

import array
import ctypes
import importlib.util
import struct
import sys
from pathlib import Path

sys.dont_write_bytecode = True


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ecdsa = load_module("ecdsa_circuits", Path(__file__).with_name("ecdsa-circuits.py"))
helpers = ecdsa.helpers


def limbs(value, count=22):
    return [(value >> (12*i)) & 4095 for i in range(count)]


class Calculator:
    def __init__(self, path):
        self.constraints = helpers.Constraints(path, (0, 0))
        name = path.stem
        libraries = list(path.parent.glob(f"*{name}*.dylib"))
        libraries += list(path.parent.glob(f"*{name}*.so"))
        assert len(libraries) == 1, libraries
        self.library = ctypes.CDLL(str(libraries[0].resolve()))
        self.load = getattr(self.library, f"{name}_load_circuit")
        self.load.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t]
        self.load.restype = ctypes.c_void_p
        self.free = getattr(self.library, f"{name}_free_circuit")
        self.free.argtypes = [ctypes.c_void_p]
        self.calculate = getattr(self.library, f"{name}_linked_witness")
        self.calculate.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                                   ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p,
                                   ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t]
        self.calculate.restype = ctypes.c_int
        self.error = ctypes.create_string_buffer(4096)
        self.data = (path.parent/f"{name}_cpp"/f"{name}.dat").read_bytes()
        self.handle = self.load(self.data, len(self.data), self.error, len(self.error))
        assert self.handle, self.error.value

    def witness(self, values):
        encoded = struct.pack(f"<{len(values)}I", *values)
        private = (ctypes.c_uint32 * (self.constraints.wires-1))()
        public = (ctypes.c_uint32 * 0)()
        result = self.calculate(self.handle, encoded, len(encoded), private, len(private),
                                public, 0, self.error, len(self.error))
        if result:
            return None
        witness = array.array("I", [1])
        witness.frombytes(bytes(private))
        return witness

    def close(self):
        self.free(self.handle)


def inputs(scalar, point, result, signed_magnitudes):
    signs = [int(value < 0) for value in signed_magnitudes]
    return (limbs(scalar) + sum(map(limbs, point), []) + sum(map(limbs, result), [])
            + sum((limbs(abs(value), 11) for value in signed_magnitudes), []) + signs)


def check(path):
    p256 = "p256" in path.stem
    curve = ecdsa.CURVES["ecdsa_p256_32" if p256 else "ecdsa_32"]
    p, n, a, gx, gy = curve
    generator = (gx, gy)
    multiply = lambda scalar, point: ecdsa.multiply(scalar, point, p, a)
    ordinary = multiply(7, generator)
    assert ordinary is not None
    boundary = (1 << (128 if p256 else 64))-1
    signed_vectors = [
        ("small positive", 3, ordinary, [3, 1, 0, 0] if p256 else [3, 0, 1, 0]),
        ("negative numerator and denominator", 3, ordinary, [-3, -1, 0, 0] if p256 else [-3, 0, -1, 0]),
        ("negative scalar", n-3, ordinary, [-3, 1, 0, 0] if p256 else [-3, 0, 1, 0]),
        ("maximum magnitude", boundary, ordinary, [boundary, 1, 0, 0] if p256 else [boundary, 0, 1, 0]),
    ]
    sentinel = multiply(12345678901234567890, generator)
    assert sentinel is not None
    negative_sentinel = (sentinel[0], -sentinel[1] % p)
    signed_vectors.append(("sentinel table infinity", 1, negative_sentinel,
                           [1, 1, 0, 0] if p256 else [1, 0, 1, 0]))
    if not p256:
        lam = 0x5363AD4CC05C30E0A5261C028812645A122E22EA20816678DF02967C1B23BD72
        signed_vectors.append(("endomorphism numerator", lam, ordinary, [0, 1, 1, 0]))
        signed_vectors.append(("endomorphism denominator", pow(lam, -1, n), ordinary, [1, 0, 0, 1]))
    calculator = Calculator(path)
    try:
        first = None
        for name, scalar, point, magnitudes in signed_vectors:
            result = multiply(scalar, point)
            assert result is not None
            values = inputs(scalar, point, result, magnitudes)
            if first is None:
                first = values
            witness = calculator.witness(values)
            assert witness is not None, (name, calculator.error.value)
            assert calculator.constraints.satisfied(witness), name
            print(f"{path.stem}: {name} witness and all R1CS equations passed", flush=True)
        assert first is not None
        negatives = []
        for name, index in (("altered scalar", 0), ("altered magnitude", 110)):
            values = first.copy()
            values[index] ^= 1
            negatives.append((name, values))
        values = first.copy()
        wrong = multiply(5, ordinary)
        values[66:110] = sum(map(limbs, wrong), [])
        negatives.append(("wrong finite result", values))
        values = first.copy()
        values[110:158] = [0]*48
        negatives.append(("zero denominator", values))
        values = first.copy()
        zero_magnitude = 2 if p256 else 1
        values[154+zero_magnitude] = 1
        negatives.append(("noncanonical zero sign", values))
        values = first.copy()
        values[154] = 2
        negatives.append(("nonboolean sign", values))
        values = first.copy()
        values[110+(10 if p256 else 5)] = 1 << (8 if p256 else 4)
        negatives.append(("magnitude outside bit range", values))
        values = first.copy()
        values[110+(22 if p256 else 6)] = 1
        negatives.append(("nonzero unused hint limb", values))
        for name, values in negatives:
            witness = calculator.witness(values)
            assert witness is None or not calculator.constraints.satisfied(witness), name
            print(f"{path.stem}: rejected {name}", flush=True)
    finally:
        calculator.close()


if __name__ == "__main__":
    assert len(sys.argv) > 1, __doc__
    for argument in sys.argv[1:]:
        check(Path(argument).resolve())
