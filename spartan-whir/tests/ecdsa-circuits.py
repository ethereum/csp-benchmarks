#!/usr/bin/env python3
"""Validate the adapted ECDSA circuits using linked native witness libraries.

Pass generated ecdsa_32.r1cs and/or ecdsa_p256_32.r1cs paths. The matching
<stem>_cpp directory and native shared library must be beside each R1CS file.
Only the Python standard library is required.
"""

from __future__ import annotations

import array
import ctypes
import hashlib
import importlib.util
import struct
import sys
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "hash_circuits", Path(__file__).with_name("hash-circuits.py")
)
assert spec and spec.loader
helpers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helpers)
spec = importlib.util.spec_from_file_location(
    "ecdsa_hints", Path(__file__).with_name("ecdsa-hints.py")
)
assert spec and spec.loader
hints = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hints)

CURVES = {
    "ecdsa_32": (
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
        0,
        0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
        0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
    ),
    "ecdsa_p256_32": (
        0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
        0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
        -3,
        0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
        0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
    ),
}


def add(left, right, p, a):
    if left is None:
        return right
    if right is None:
        return left
    x, y = left
    xx, yy = right
    if x == xx:
        if (y + yy) % p == 0:
            return None
        slope = (3*x*x + a) * pow(2*y, -1, p) % p
    else:
        slope = (yy-y) * pow(xx-x, -1, p) % p
    result_x = (slope*slope-x-xx) % p
    return result_x, (slope*(x-result_x)-y) % p


def multiply(scalar, point, p, a):
    result = None
    while scalar:
        if scalar & 1:
            result = add(result, point, p, a)
        point = add(point, point, p, a)
        scalar >>= 1
    return result


def byte_limbs(value):
    return list(value.to_bytes(32, "little"))


def signature(curve, secret, nonce, digest):
    p, n, a, gx, gy = curve
    public_key = multiply(secret, (gx, gy), p, a)
    nonce_point = multiply(nonce, (gx, gy), p, a)
    assert public_key is not None and nonce_point is not None
    r = nonce_point[0] % n
    s = ((digest + r*secret) * pow(nonce, -1, n)) % n
    assert r and s
    inverse = pow(s, -1, n)
    verification = add(
        multiply(digest*inverse % n, (gx, gy), p, a),
        multiply(r*inverse % n, public_key, p, a), p, a,
    )
    assert verification is not None and verification[0] % n == r
    return sum(map(byte_limbs, (digest, *public_key, r, s)), [])


class Calculator:
    def __init__(self, path):
        self.constraints = helpers.Constraints(path, public_layout=(0, 96))
        self.stem = path.stem
        directory = path.parent
        libraries = list(directory.glob(f"*{self.stem}*.dylib"))
        libraries += list(directory.glob(f"*{self.stem}*.so"))
        assert len(libraries) == 1, libraries
        self.library = ctypes.CDLL(str(libraries[0].resolve()))
        self.load = getattr(self.library, f"{self.stem}_load_circuit")
        self.load.argtypes = [ctypes.c_void_p, ctypes.c_size_t,
                              ctypes.c_void_p, ctypes.c_size_t]
        self.load.restype = ctypes.c_void_p
        self.free = getattr(self.library, f"{self.stem}_free_circuit")
        self.free.argtypes = [ctypes.c_void_p]
        self.calculate = getattr(self.library, f"{self.stem}_linked_witness")
        self.calculate.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                                   ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p,
                                   ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t]
        self.calculate.restype = ctypes.c_int
        self.error = ctypes.create_string_buffer(4096)
        self.data = (directory / f"{self.stem}_cpp/{self.stem}.dat").read_bytes()
        self.handle = self.load(self.data, len(self.data), self.error, len(self.error))
        assert self.handle, self.error.value
        self.last_auxiliary = None

    def witness(self, values):
        if len(values) == 160:
            try:
                values = hints.augment(CURVES[self.stem], values)
                self.last_auxiliary = values[160:]
            except (AssertionError, ValueError, ZeroDivisionError):
                # Still send malformed statements to the circuit. Host-side
                # rejection alone does not establish its constraints.
                assert self.last_auxiliary is not None
                values = list(values) + self.last_auxiliary
        assert len(values) == 252
        encoded = struct.pack("<252I", *values)
        public = (ctypes.c_uint32 * 96)()
        private = (ctypes.c_uint32 * (self.constraints.wires - 97))()
        result = self.calculate(self.handle, encoded, len(encoded), private,
                                len(private), public, len(public), self.error,
                                len(self.error))
        if result:
            return None
        witness = array.array("I", [1])
        witness.frombytes(bytes(public))
        witness.frombytes(bytes(private))
        assert list(public) == values[:96]
        return witness

    def close(self):
        self.free(self.handle)


def check(path):
    curve = CURVES[path.stem]
    p, n, _, _, _ = curve
    calculator = Calculator(path)
    try:
        digest = int.from_bytes(hashlib.sha256(b"KoalaBear ECDSA circuit").digest(), "big")
        cases = (
            ("ordinary", 3, 7, digest),
            ("zero prehash and Q=G", 1, 1, 0),
            ("prehash above order and Q=-G", n-1, 2, n+1),
            ("maximum prehash and Q=-3G", n-3, 5, (1 << 256)-1),
        )
        bad_comb = int(
            "e0000000ffffffff00000000000000004319055258e8617b0c46353d039cdaaf"
            if curve[2] == -3 else
            "e00000000000000000000000000000014551231950b75fc4402da1732fc9bebf",
            16,
        )
        # Force u1 = h/s to the scalar whose original comb needs doubling.
        secret, nonce = 3, 7
        nonce_point = multiply(nonce, (curve[3], curve[4]), p, curve[2])
        r = nonce_point[0] % n
        prehash = bad_comb*r*secret*pow(nonce-bad_comb, -1, n) % n
        cases += (("comb final doubling", secret, nonce, prehash),)
        prehash = -r*secret*pow(2, -1, n) % n
        cases += (("R equals negative fixed-base point", secret, nonce, prehash),)
        first = None
        for name, secret, nonce, prehash in cases:
            values = signature(curve, secret, nonce, prehash)
            if first is None:
                first = values
            witness = calculator.witness(values)
            assert witness is not None, (name, calculator.error.value)
            assert calculator.constraints.satisfied(witness), name
            print(f"{path.stem}: {name}, witness and R1CS passed", flush=True)

        assert first is not None
        negatives = []
        for name, offset, value in (
            ("zero r", 96, 0), ("zero s", 128, 0),
            ("r equal to order", 96, n), ("s equal to order", 128, n),
            ("x equal to field modulus", 32, p),
        ):
            values = first.copy()
            values[offset:offset+32] = byte_limbs(value)
            negatives.append((name, values))
        for name, offset in (("altered prehash", 0), ("altered public key", 64),
                             ("altered signature", 96)):
            values = first.copy()
            values[offset] ^= 1
            negatives.append((name, values))
        values = first.copy()
        values[96] = 256
        negatives.append(("signature byte outside range", values))
        for name, values in negatives:
            witness = calculator.witness(values)
            assert witness is None or not calculator.constraints.satisfied(witness), name
            print(f"{path.stem}: rejected {name}", flush=True)

        original = hints.augment(curve, first)
        for name, index, value in (
            ("changed result x", 160, original[160] ^ 1),
            ("changed result y", 182, original[182] ^ 1),
            ("result limb outside range", 160, 4096),
            ("changed decomposition", 204, original[204] ^ 1),
            ("non-Boolean sign", 248, 2),
            ("changed decomposition sign", 248, original[248] ^ 1),
            ("magnitude limb outside range", 204, 4096),
            ("magnitude exceeds short-scalar bound", 214 if curve[2] == -3 else 209,
             256 if curve[2] == -3 else 16),
        ):
            values = original.copy()
            values[index] = value
            witness = calculator.witness(values)
            assert witness is None or not calculator.constraints.satisfied(witness), name
            print(f"{path.stem}: rejected {name}", flush=True)
        values = original[:204] + [0]*48
        witness = calculator.witness(values)
        assert witness is None or not calculator.constraints.satisfied(witness), "zero fake-GLV denominator"
        print(f"{path.stem}: rejected zero fake-GLV denominator", flush=True)
        values = original.copy()
        result_y = sum(values[182+i] << (12*i) for i in range(22))
        values[182:204] = [((p-result_y) >> (12*i)) & 4095 for i in range(22)]
        witness = calculator.witness(values)
        assert witness is None or not calculator.constraints.satisfied(witness), "negated result point"
        print(f"{path.stem}: rejected negated result point", flush=True)

        point = multiply(7, (curve[3], curve[4]), p, curve[2])
        values = sum(map(byte_limbs, (7, curve[3], curve[4], point[0] % n, 1)), [])
        values = hints.augment(curve, values)
        values[160:204] = [
            (coordinate >> (12*i)) & 4095 for coordinate in point for i in range(22)
        ]
        witness = calculator.witness(values)
        assert witness is None or not calculator.constraints.satisfied(witness), "infinite S"
        print(f"{path.stem}: rejected infinite S with canonical on-curve R and matching r", flush=True)
    finally:
        calculator.close()


if __name__ == "__main__":
    assert len(sys.argv) > 1, "Pass generated ecdsa_32.r1cs and/or ecdsa_p256_32.r1cs"
    for argument in sys.argv[1:]:
        check(Path(argument))
