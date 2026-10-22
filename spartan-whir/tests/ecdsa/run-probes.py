#!/usr/bin/env python3
"""Compile and validate the standalone fake-GLV and complete group probes."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True

PROBES = ("fakeglv_k1", "fakeglv_p256", "fused_k1", "fused_p256", "quad_k1", "quad_p256")
FUSED_ARITHMETIC_PROBES = ("fused_modzero11", "fused_modzero11_k1")
COMB_PROBES = ("comb_k1", "comb_p256", "comb_add_k1", "comb_add_p256",
               "comb_window_k1", "comb_window_p256")
MULTIPLICATION_PROBES = tuple(f"multiplication_{modulus}" for modulus in
                              ("k1p", "k1n", "p256p", "p256n"))
SOURCE_DIR = Path(__file__).resolve().parent
REPOSITORY = SOURCE_DIR.parents[2]
CXX_FLAGS = ("-std=c++11", "-O3", "-fPIC", "-fvisibility=hidden", "-UNDEBUG",
             "-DCIRCOM_LINKED_WITNESS_ONLY")


def command_with_log(command, log):
    with log.open("w") as output:
        result = subprocess.run(command, cwd=REPOSITORY, stdout=output, stderr=subprocess.STDOUT)
    if result.returncode:
        raise RuntimeError(f"Command failed ({result.returncode}): {command!r}\n{log.read_text()}")


def run(output, with_comb=False, with_multiplication=False):
    circom = os.environ.get("SPARTAN_WHIR_CIRCOM", "circom")
    cxx = os.environ.get("CXX", "c++")
    extension = "dylib" if sys.platform == "darwin" else "so"
    probes = (PROBES + FUSED_ARITHMETIC_PROBES + (COMB_PROBES if with_comb else ())
              + (MULTIPLICATION_PROBES if with_multiplication else ()))
    for name in probes:
        directory = output/name
        directory.mkdir(parents=True, exist_ok=True)
        print(f"Compiling {name}", flush=True)
        source = (SOURCE_DIR.parent/"nonnative" if name in MULTIPLICATION_PROBES
                  else SOURCE_DIR)/f"{name}.circom"
        command_with_log([circom, str(source), "--prime", "koalabear",
                          "--r1cs", "--c", "--sym", "--O1", "-o", str(directory)], directory/"circom.log")
        cpp = directory/f"{name}_cpp"
        if name in ("comb_k1", "comb_p256", "comb_window_k1", "comb_window_p256"):
            command_with_log([
                "cargo", "run", "--release", "--locked", "-p", "spartan-whir-bench",
                "--example", "compact_comb_witness", "--", str(cpp/f"{name}.cpp"),
            ], directory/"compact.log")
        command = [cxx, *CXX_FLAGS, "-I", str(cpp)]
        for include in ("/opt/homebrew/include", "/usr/local/include"):
            if Path(include).is_dir():
                command += ["-I", include]
        command += [str(cpp/file) for file in ("calcwit.cpp", "fr.cpp", "main.cpp", f"{name}.cpp")]
        for library in ("/opt/homebrew/lib", "/usr/local/lib"):
            if Path(library).is_dir():
                command += ["-L", library]
        command += ["-lgmp"]
        library_name = f"lib{name}_witness.{extension}"
        if sys.platform == "darwin":
            command += ["-dynamiclib", f"-Wl,-install_name,@rpath/{library_name}"]
        else:
            command += ["-shared"]
        command += ["-o", str(directory/library_name)]
        command_with_log(command, directory/"cxx.log")
    tests = SOURCE_DIR.parent
    subprocess.run([sys.executable, "-B", str(tests/"fake-glv-circuits.py"),
                    *(str(output/name/f"{name}.r1cs") for name in PROBES[:2])],
                   cwd=REPOSITORY, check=True)
    subprocess.run([sys.executable, "-B", str(tests/"fused-point-circuits.py"),
                    *(str(output/name) for name in PROBES[2:])],
                   cwd=REPOSITORY, check=True)
    subprocess.run([sys.executable, "-B", str(tests/"fused-slope-representatives.py"),
                    str(output/"fused_k1"), str(output/"quad_p256")],
                   cwd=REPOSITORY, check=True)
    subprocess.run([sys.executable, "-B", str(tests/"fused-arithmetic.py"),
                    *(str(output/name) for name in FUSED_ARITHMETIC_PROBES)],
                   cwd=REPOSITORY, check=True)
    if with_comb:
        subprocess.run([sys.executable, "-B", str(tests/"comb-circuits.py"),
                        *(str(output/name) for name in COMB_PROBES)],
                       cwd=REPOSITORY, check=True)
    if with_multiplication:
        subprocess.run([sys.executable, "-B", str(tests/"nonnative-multiplication.py"),
                        *(str(output/name) for name in MULTIPLICATION_PROBES)],
                       cwd=REPOSITORY, check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path,
                        help="Keep generated artifacts and compiler logs in this directory")
    parser.add_argument("--with-comb", action="store_true",
                        help="Also validate fixed-base comb multiplication and unequal-point addition")
    parser.add_argument("--with-multiplication", action="store_true",
                        help="Also validate modular multiplication for both curves' fields and scalar orders")
    args = parser.parse_args()
    if sys.platform not in ("darwin", "linux"):
        parser.error("The linked witness probes support macOS and Linux")
    if args.output_dir:
        run(args.output_dir.resolve(), args.with_comb, args.with_multiplication)
    else:
        with tempfile.TemporaryDirectory(prefix="spartan-whir-ecdsa-") as output:
            run(Path(output), args.with_comb, args.with_multiplication)


if __name__ == "__main__":
    main()
