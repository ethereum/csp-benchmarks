#!/usr/bin/env python3
"""Check adapted KoalaBear hash circuits and their linked witness generators.

Pass directories containing <name>.r1cs, <name>_cpp/<name>.dat, and one linked
witness shared library. Names must be sha256_<bytes>, keccak_<bytes>, or
poseidon_<field_elements>.
The tests use only Python's standard library.
"""

from __future__ import annotations

import ctypes
import hashlib
import re
import struct
import sys
from pathlib import Path

KOALABEAR = 2_130_706_433
MASK64 = (1 << 64) - 1
ROTATIONS = (
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43,
    25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
)
ROUND_CONSTANTS = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)


def keccak256(message: bytes) -> bytes:
    """Reference Keccak-256 with its original 0x01 domain suffix."""
    padded = bytearray(message)
    padded.append(1)
    padded.extend(bytes((-len(padded)) % 136))
    padded[-1] |= 0x80
    state = [0] * 25
    for offset in range(0, len(padded), 136):
        for lane in range(17):
            state[lane] ^= int.from_bytes(padded[offset + lane*8:offset + lane*8 + 8], "little")
        for constant in ROUND_CONSTANTS:
            parity = [state[x] ^ state[x+5] ^ state[x+10] ^ state[x+15] ^ state[x+20] for x in range(5)]
            delta = [parity[(x-1) % 5] ^ ((parity[(x+1) % 5] << 1 | parity[(x+1) % 5] >> 63) & MASK64) for x in range(5)]
            permuted = [0] * 25
            for x in range(5):
                for y in range(5):
                    lane = x + 5*y
                    value = state[lane] ^ delta[x]
                    shift = ROTATIONS[lane]
                    permuted[y + 5*((2*x + 3*y) % 5)] = ((value << shift) | (value >> ((64-shift) % 64))) & MASK64
            for x in range(5):
                for y in range(5):
                    state[x+5*y] = permuted[x+5*y] ^ ((~permuted[(x+1) % 5 + 5*y]) & permuted[(x+2) % 5 + 5*y])
            state[0] ^= constant
    return b"".join(value.to_bytes(8, "little") for value in state)[:32]


def poseidon_permutation(state: list[int]) -> list[int]:
    """Textbook Poseidon1, checked against the pinned Plonky3 test vector."""
    source = (Path(__file__).resolve().parents[1] / "circuits/poseidon/constants.circom").read_text()
    text = source.split("var constants[28][16] = [", 1)[1].split("];", 1)[0]
    constants = list(map(int, re.findall(r"\d+", text)))
    assert len(constants) == 28*16
    first_row = [1, 1, 51, 1, 11, 17, 2, 1, 101, 63, 15, 2, 67, 22, 13, 3]
    for round_index in range(28):
        state = [(value + constants[round_index*16+lane]) % KOALABEAR for lane, value in enumerate(state)]
        for lane in range(16):
            if round_index < 4 or round_index >= 24 or lane == 0:
                state[lane] = pow(state[lane], 3, KOALABEAR)
        state = [sum(first_row[(column-lane) % 16] * state[column] for column in range(16)) % KOALABEAR for lane in range(16)]
    return state


def poseidon(inputs: list[int]) -> list[int]:
    """Plonky3 Pad10Sponge with width 16, rate 8, output 8, Increment(1)."""
    state = [0]*16
    blocks = (len(inputs) + 7) // 8
    for block in range(blocks):
        chunk = inputs[block*8:block*8+8]
        state[:len(chunk)] = chunk
        if len(chunk) < 8:
            state[len(chunk):8] = [1] + [0]*(7-len(chunk))
        elif block == blocks-1:
            state[8] = (state[8] + 1) % KOALABEAR
        state = poseidon_permutation(state)
    return state[:8]


def sections(binary: bytes, magic: bytes):
    assert binary[:4] == magic
    offset = 12
    result = {}
    for _ in range(struct.unpack_from("<I", binary, 8)[0]):
        kind, size = struct.unpack_from("<IQ", binary, offset)
        offset += 12
        result[kind] = memoryview(binary)[offset:offset+size]
        offset += size
    assert offset == len(binary)
    return result


class Constraints:
    def __init__(self, path: Path, public_layout=None):
        blocks = sections(path.read_bytes(), b"r1cs")
        header = blocks[1]
        width = struct.unpack_from("<I", header)[0]
        assert width == 4
        self.prime = struct.unpack_from("<I", header, 4)[0]
        assert self.prime == KOALABEAR
        self.wires, outputs, public_inputs, _ = struct.unpack_from("<4I", header, 8)
        self.public = outputs + public_inputs
        if public_layout is None:
            assert outputs == 0
            assert public_inputs in (8, 32)
        else:
            assert (outputs, public_inputs) == public_layout
        self.count = struct.unpack_from("<I", header, 32)[0]
        self.data = blocks[2]

    def satisfied(self, witness: list[int]) -> bool:
        assert len(witness) == self.wires
        offset = 0
        for _ in range(self.count):
            values = []
            for _ in range(3):
                count = struct.unpack_from("<I", self.data, offset)[0]
                offset += 4
                value = 0
                for _ in range(count):
                    wire, coefficient = struct.unpack_from("<II", self.data, offset)
                    offset += 8
                    value += coefficient * witness[wire]
                values.append(value % self.prime)
            if (values[0]*values[1] - values[2]) % self.prime:
                return False
        assert offset == len(self.data)
        return True


class Calculator:
    def __init__(self, directory: Path, constraints: Constraints):
        self.constraints = constraints
        name = directory.name
        libraries = list(directory.glob("*.dylib")) + list(directory.glob("*.so"))
        assert len(libraries) == 1, f"Expected one linked library in {directory}"
        self.library = ctypes.CDLL(str(libraries[0]))
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
        self.data = (directory / f"{name}_cpp" / f"{name}.dat").read_bytes()
        self.handle = self.load(self.data, len(self.data), self.error, len(self.error))
        assert self.handle, self.error.value

    def witness(self, message: list[int], digest) -> list[int] | None:
        # Circom lays out the public hash before the private message.
        values = list(digest) + message
        encoded = struct.pack(f"<{len(values)}I", *values)
        public = (ctypes.c_uint32 * self.constraints.public)()
        private = (ctypes.c_uint32 * (self.constraints.wires - 1 - self.constraints.public))()
        result = self.calculate(self.handle, encoded, len(encoded), private, len(private),
                                public, len(public), self.error, len(self.error))
        if result:
            return None
        return [1] + list(public) + list(private)

    def close(self):
        self.free(self.handle)


def check(directory: Path):
    directory = directory.resolve()
    match = re.fullmatch(r"(sha256|keccak|poseidon)_(\d+)", directory.name)
    assert match, directory
    algorithm, size = match[1], int(match[2])
    if algorithm == "poseidon":
        digest = poseidon
        vectors = [[0]*size, [KOALABEAR-1]*size, [(i*1_234_567 + 89_123) % KOALABEAR for i in range(size)]]
    else:
        digest = (lambda message: hashlib.sha256(message).digest()) if algorithm == "sha256" else keccak256
        vectors = [bytes(size), bytes([255])*size, bytes((i*73 + 19) & 255 for i in range(size))]
    constraints = Constraints(directory / f"{directory.name}.r1cs")
    calculator = Calculator(directory, constraints)
    try:
        for message in vectors:
            expected = digest(message)
            witness = calculator.witness(list(message), expected)
            assert witness is not None
            assert witness[1:1+constraints.public] == list(expected)
            assert constraints.satisfied(witness)
        message = vectors[-1]
        expected = digest(message)
        wrong = list(expected)
        wrong[0] ^= 1
        assert calculator.witness(list(message), wrong) is None
        if size:
            changed = list(message)
            changed[0] ^= 1
            assert calculator.witness(changed, expected) is None
            for invalid in (() if algorithm == "poseidon" else (256, 511, KOALABEAR-1)):
                changed = list(message)
                changed[0] = invalid
                truncated = bytes([invalid & 255]) + message[1:]
                assert calculator.witness(changed, digest(truncated)) is None
        witness[1] ^= 1
        assert not constraints.satisfied(witness)
        print(f"{directory.name}: {constraints.count} constraints; 3 reference digests and all R1CS equations passed; altered digest, message, and witness rejected", flush=True)
    finally:
        calculator.close()


if __name__ == "__main__":
    assert keccak256(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    assert keccak256(b"abc").hex() == "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
    # Plonky3 koala-bear/src/poseidon1.rs, revision 458ef546a251ab4d9d73c453d24a414334786ca0.
    assert poseidon_permutation(list(range(16))) == [
        610090613, 935319874, 1893335292, 796792199, 356405232, 552237741, 55134556,
        1215104204, 1823723405, 1133298033, 1780633798, 1453946561, 710069176, 1128629550,
        1917333254, 1175481618,
    ]
    assert len(sys.argv) > 1, __doc__
    for argument in sys.argv[1:]:
        check(Path(argument))
