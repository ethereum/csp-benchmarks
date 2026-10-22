# ECDSA arithmetic probes

These eight standalone circuits test fake-GLV verification, complete `2A+B` and `4A+B` operations for secp256k1 and secp256r1, and both curves' signed modular certificates. They use the same KoalaBear arithmetic as the benchmark circuits. Python's standard library supplies independent integer curve arithmetic and evaluates every generated R1CS equation.

## Prerequisites

Install the pinned [KoalaBear Circom compiler and native dependencies](../../README.md#prerequisites). The compiler revision is `bb7ae6d406debbfe8afc68305cbd6106fda945bc` from `Client-Side-Proving/circom`. Set `SPARTAN_WHIR_CIRCOM` to its executable; `CXX` optionally selects the C++ compiler. Initialize the `circom/circomlib` submodule as described in those instructions.

## Compile and run

From the repository root:

```bash
export SPARTAN_WHIR_CIRCOM="$HOME/.circom-koalabear/bin/circom"
python3 -B spartan-whir/tests/ecdsa/run-probes.py
```

The runner compiles eight default entrypoints into a temporary directory, builds their linked native witness libraries, runs the Python validation scripts, and removes the generated directory when it exits. Compilation runs from the repository root and resolves each circuit's relative includes. Its Circom options are `--prime koalabear --r1cs --c --sym --O1`; the symbol maps identify internal wires for mutation tests. The C++ options match benchmark preparation: `-std=c++11 -O3 -fPIC -fvisibility=hidden -UNDEBUG -DCIRCOM_LINKED_WITNESS_ONLY`, with GMP linkage and shared-library flags for macOS or Linux.

Add `--with-comb` to compile and validate fixed-base comb multiplication, its finite unequal-point addition helper, and individual lookup windows for both curves. The full comb and window probes use the Rust toolchain to apply the same native table representation as benchmark preparation, retaining the Circom sanity checks and the original R1CS lookup constraints:

```bash
python3 -B spartan-whir/tests/ecdsa/run-probes.py --with-comb
```

Add `--with-multiplication` to check polynomial-identity multiplication for both curves' base fields and scalar orders. Both flags can be combined:

```bash
python3 -B spartan-whir/tests/ecdsa/run-probes.py --with-comb --with-multiplication
```

To retain artifacts and compiler logs under the repository's ignored `target` directory:

```bash
python3 -B spartan-whir/tests/ecdsa/run-probes.py \
  --output-dir target/spartan-whir-ecdsa-probes
```

Each probe directory contains its `.r1cs` and `.sym`, generated C++ sources and `.dat`, linked witness library, `circom.log`, and `cxx.log`. The runner rebuilds the circuits and native libraries on each invocation. The Python checks can also run against retained artifacts:

```bash
python3 -B spartan-whir/tests/fake-glv-circuits.py \
  target/spartan-whir-ecdsa-probes/fakeglv_k1/fakeglv_k1.r1cs \
  target/spartan-whir-ecdsa-probes/fakeglv_p256/fakeglv_p256.r1cs
python3 -B spartan-whir/tests/fused-point-circuits.py \
  target/spartan-whir-ecdsa-probes/fused_k1 \
  target/spartan-whir-ecdsa-probes/fused_p256 \
  target/spartan-whir-ecdsa-probes/quad_k1 \
  target/spartan-whir-ecdsa-probes/quad_p256
```

## Coverage

The fake-GLV probes cover signed magnitudes, maximum 64-bit and 128-bit magnitudes, secp256k1 endomorphism terms, and a sentinel table entry at infinity. Invalid cases alter the scalar, magnitude, or claimed finite result; use a zero denominator; violate sign or magnitude ranges; or set unused hint limbs. The template's caller supplies canonical finite curve points, matching the benchmark's circuit checks.

Each complete group probe checks ordinary addition, equal and inverse points, a result at infinity, either input at infinity, both inputs at infinity, a negative result, and 20 deterministic random pairs. The `4A+B` probes also check `B=2A`, `B=-2A`, `B=-4A`, and `B=-6A`. Each probe compares every output to the independent integer result, evaluates every R1CS equation, and rejects forged coordinates and infinity flags. The secp256k1 fused and quad probes and the P-256 quad probe also reject mutations of quotient, carry, slope, and branch witnesses; the P-256 probe checks its normalized y-coordinate. Temporary witness generators check canonical slopes and active horizontal chords with slope zero represented by the curve prime, within the 256-bit bound. They reject representatives above that bound, including an explicit highest limb of eight. Each temporary generator has identical R1CS headers and equations to the production probe. Expected assertion diagnostics from malformed fake-GLV witnesses are followed by explicit rejection messages. A failed test exits nonzero.

The comb probes check zero, scalar-order boundaries, values around every 12-bit carry boundary, the exceptional final-doubling scalar, and deterministic random scalars for each curve. Every valid result is compared with independent integer multiplication and checked against all R1CS equations; forged outputs and out-of-range values in every scalar limb are rejected. The window probes compare all 2,048 lookup addresses with independent integer multiplication and check R1CS satisfaction, forged outputs, and nonbinary bits at decoder boundaries. The unequal-point helper probes reject equal and inverse operands explicitly. The comb circuit documents the scalar and parity bounds that permit this helper in its first 20 additions; the final addition uses the complete group law.

The multiplication probes admit the complete 256-bit input range, including prehashes above the scalar order. They check 276 boundary and deterministic random pairs per modulus, compare the result with Python integer multiplication, evaluate every R1CS equation, and reject altered convolution coefficients, altered outputs, and invalid input limbs.

The signed modular-certificate probes check positive and negative quotients, maximum quotient digits, alternating signed carries, and coefficients near their magnitude bound for both curve primes. They reject internal witness mutations and altered residues.
