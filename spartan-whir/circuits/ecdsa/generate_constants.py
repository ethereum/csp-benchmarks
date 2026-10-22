#!/usr/bin/env python3
"""Generate the 12-bit curve constants and fixed two-bit generator tables."""

from pathlib import Path


CURVES = (
    {
        "prime": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
        "order": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
        "a": 0,
        "b": 7,
        "gx": 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
        "gy": 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
    },
    {
        "prime": 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
        "order": 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
        "a": -3,
        "b": 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
        "gx": 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
        "gy": 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
    },
)


def limbs(value):
    assert 0 <= value < 1 << 256
    return [(value >> (12*i)) & 4095 for i in range(22)]


def generator_table(curve):
    p, a, b = curve["prime"], curve["a"], curve["b"]
    g = (curve["gx"], curve["gy"])

    def add(left, right):
        x, y = left
        xx, yy = right
        slope = ((3*x*x+a)*pow(2*y, -1, p) if left == right
                 else (yy-y)*pow(xx-x, -1, p)) % p
        result_x = (slope*slope-x-xx) % p
        return result_x, (slope*(x-result_x)-y) % p

    twice = add(g, g)
    thrice = add(twice, g)
    result = (g, g, twice, thrice)
    assert all((y*y-x*x*x-a*x-b) % p == 0 for x, y in result)
    return [[limbs(x), limbs(y)] for x, y in result]


def assignments(value, index="out"):
    if isinstance(value, list):
        return "".join(assignments(child, f"{index}[{i}]")
                       for i, child in enumerate(value))
    return f"        {index} = {value};\n"


def function(name, dimensions, values):
    return (
        f"function {name}(p256) {{\n    var out{dimensions};\n"
        "    if (p256 == 1) {\n"
        + assignments(values[1])
        + "    } else {\n"
        + assignments(values[0])
        + "    }\n    return out;\n}\n\n"
    )


def source():
    result = "pragma circom 2.2.0;\n\n"
    for name in ("prime", "order", "b"):
        result += function(f"ecdsa_{name}", "[22]",
                           [limbs(curve[name]) for curve in CURVES])
    result += function("ecdsa_generator", "[2][22]",
                       [[limbs(curve["gx"]), limbs(curve["gy"])] for curve in CURVES])
    result += "\n"
    result += function("ecdsa_fixed_table", "[4][2][22]",
                       [generator_table(curve) for curve in CURVES]).rstrip() + "\n"
    return result


if __name__ == "__main__":
    Path(__file__).with_name("constants.circom").write_text(source())
