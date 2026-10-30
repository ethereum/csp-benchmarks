# Spartan-WHIR benchmarks

This crate benchmarks [Spartan-WHIR](https://github.com/ethereum/spartan-whir) at revision [`14d6da4`](https://github.com/ethereum/spartan-whir/commit/14d6da4211eda59e65cfd0af5e2dcd89d523edc3). It proves SHA-256, Keccak-256, native KoalaBear Poseidon, and ECDSA circuits with full-ZK DirectSparse, a quintic extension, Poseidon2 proof hashing, and a 115-bit security target under the Johnson bound. Upstream setup checks the composed security budget for each circuit.

Every circuit uses the same 115-bit composed security target. Upstream setup allocates the error budget across algebraic checks, WHIR arguments, and Poseidon commitment binding events using the actual circuit dimensions and selected parameters.

## Prerequisites

Use the repository's Rust toolchain; Cargo fetches the pinned Spartan-WHIR dependency. Circuit compilation requires the [KoalaBear Circom fork](https://github.com/Client-Side-Proving/circom) at revision [`bb7ae6d4`](https://github.com/Client-Side-Proving/circom/commit/bb7ae6d406debbfe8afc68305cbd6106fda945bc), a C++ compiler, GMP, and the nlohmann JSON headers.

From the repository root, fetch the circuit library and install the compiler:

```bash
git submodule update --init circom/circomlib
cargo install \
  --git https://github.com/Client-Side-Proving/circom \
  --rev bb7ae6d406debbfe8afc68305cbd6106fda945bc \
  --locked \
  --root "$HOME/.circom-koalabear" \
  circom
export SPARTAN_WHIR_CIRCOM="$HOME/.circom-koalabear/bin/circom"
```

On macOS, install the native dependencies and expose Homebrew's headers and libraries:

```bash
brew install gmp nlohmann-json
export CPLUS_INCLUDE_PATH="$(brew --prefix)/include${CPLUS_INCLUDE_PATH:+:$CPLUS_INCLUDE_PATH}"
export LIBRARY_PATH="$(brew --prefix)/lib${LIBRARY_PATH:+:$LIBRARY_PATH}"
```

On Debian or Ubuntu, install `g++`, `libgmp-dev`, and `nlohmann-json3-dev`.

## Run

Run from this crate directory so the shared harness resolves its memory binaries and measurement script:

```bash
cd spartan-whir
BENCH_INPUT_PROFILE=reduced RUSTFLAGS="-C target-cpu=native" cargo bench
BENCH_INPUT_PROFILE=full RUSTFLAGS="-C target-cpu=native" cargo bench
```

Select an individual target with `--bench sha256_bench`, `--bench keccak_bench`, `--bench poseidon_bench`, `--bench ecdsa_bench`, or `--bench ecdsa_p256_bench`. The shared harness records timings, proof and preprocessing sizes, constraint counts, and proving memory through dedicated memory binaries. Running `cargo bench` from this directory selects this benchmark crate.

## WHIR parameters

[parameters.rs](src/parameters.rs) selects a measured configuration from the logarithms of the padded witness length and constraint count. Every supported circuit has equal witness and constraint logarithms. The table covers all SHA-256, Keccak, Poseidon, and ECDSA inputs in both input profiles. Setup rejects dimensions outside this table. These explicit parameters apply to the pinned upstream revision.

| Log₂ dimension | Variables folded per step | Initial log₂ inverse rate | Initial reduction parameter | PoW budget (bits) | Explicit round log₂ inverse rates |
| ---: | --- | ---: | ---: | ---: | --- |
| 9 | 3 | 4 | 1 | 0 | Derived |
| 10 | 4 | 4 | 1 | 1 | Derived |
| 16 | 6, 4 | 1 | 3 | 1 | Derived |
| 17 | 7, 4 | 1 | 4 | 1 | Derived |
| 18 | 8, 4 | 1 | 5 | 1 | Derived |
| 19 | 8, 5 | 1 | 7 | 4 | 4 |
| 20 | 8, 6 | 1 | 6 | 4 | 4 |
| 21 | 8, 4, 4 | 1 | 7 | 4 | Derived |

The PoW budget is an upper bound used to derive query counts and actual grinding difficulty. Every configuration retains full-ZK DirectSparse, the quintic extension, Poseidon2 proof hashing, the Johnson bound, `ell_zk=3`, `mask_log_inv_rate=3`, and the 115-bit application and Merkle targets. Key setup checks the composed security budget and full-ZK masking capacity for each actual circuit.

Explicit round rates determine the backend's domain changes. At dimensions 19 and 20, the explicit rate of four gives an actual first-round reduction of five; the table records the separate `rs_domain_initial_reduction_factor` parameter exactly as measured.

Configurations were selected using Criterion proving times and fresh-process peak RAM on an Apple M4 Pro. Selection favors lower RAM when timing confidence intervals overlap.

## Circuits

The circuits start from this repository's [Circom circuits](../circom/circuits/). Each hash benchmark proves knowledge of a private preimage for a public digest. ECDSA proves knowledge of a private signature for a public message digest and public key.

| Target | Inputs | Public statement |
| --- | --- | --- |
| SHA-256 | 128, 256, 512, 1,024, or 2,048 bytes | 32 digest bytes |
| Keccak-256 | 128, 256, 512, 1,024, or 2,048 bytes | 32 digest bytes |
| Poseidon | 2, 4, 8, 12, or 16 KoalaBear elements | Eight digest elements |
| ECDSA secp256k1 | One signature | 32-byte message digest and public key |
| ECDSA secp256r1 | One signature | 32-byte message digest and public key |

SHA-256 uses 16-bit limbs for additions so that every integer sum remains below the KoalaBear modulus. SHA-256 and Keccak split their round constants into 16-bit limbs before extracting bits. Poseidon uses the pinned Plonky3 KoalaBear Poseidon1 permutation: width 16, exponent 3, eight full rounds, 20 partial rounds, and a sponge with rate eight and capacity eight. The eight-element digest has approximately 123 bits of generic collision security. Inputs use the shared deterministic field-element samples reduced modulo KoalaBear.

ECDSA uses 22 limbs of 12 bits for non-native scalar and curve arithmetic, with constrained carries and canonical residues. A width-12 signed-digit comb computes the fixed-base multiple with 22 precomputed windows. Each window splits its 11 lookup bits into eight low bits and three high bits. The scalar's canonical range check bounds every input limb; a separate decomposition of its low limb supplies parity. The first 20 additions use finite unequal-point formulas: the signed scalar prefixes and parity bound both operands' sum and difference below the curve order. The final addition uses the complete group law, including zero-scalar and doubling cases.

Modular multiplication fixes its 43 convolution coefficients through polynomial identities at 43 distinct KoalaBear points. Both input polynomials have degree at most 21, so these identities determine their product exactly. Each integer coefficient is bounded by `22*4095^2 = 368,918,550`, below the KoalaBear modulus; the quotient, canonical remainder, and signed carry constraints establish the integer modular multiplication.

The variable-base relation uses four-dimensional fake-GLV with 64-bit signed magnitudes for secp256k1, and two-dimensional fake-GLV with 128-bit signed magnitudes for secp256r1. Both use 64 Straus steps and complete group operations. Secp256k1 checks fused `2A+B` through five combined modular equations, omitting the intermediate y-coordinate. P-256 combines the three slopes for `4A+B` with direct modular equations and a normalized 48-limb intermediate y-coordinate without reducing it modulo the curve field. Both operations use 24 internal limbs. Slope limbs have eleven bits each, except the highest limb has three bits, bounding slopes by `2^256`; the equations interpret them modulo the curve prime. Intermediate x-coordinates and outputs are canonical and retain the 22-limb interface. The complete signed carry equalities have magnitude at most `1,677,656,211`, below KoalaBear's modulus `2,130,706,433`. The circuit explicitly checks that the fake-GLV denominator is nonzero modulo the scalar order. Signatures require canonical nonzero `r` and `s`; low-`s` normalization is not required.

The comb and fake-GLV algorithms adapt the zk.golf-derived implementations in the [Circom ECDSA circuits](../circom/circuits/ecdsa/). The prover generates the result point and scalar decomposition with native integer arithmetic during the timed witness-generation phase. These auxiliary inputs are private and independently constrained by the circuit. The public statement remains the message digest and public key. The comb tables and endomorphism constants have reproducible Python generators alongside the circuit sources.

The ECDSA circuits compiled with the pinned KoalaBear compiler have the following sizes. Matrix entries count coefficients across all three R1CS matrices.

| Curve | Constraints | R1CS wires | Matrix entries |
| --- | ---: | ---: | ---: |
| secp256k1 | 1,177,351 | 1,130,077 | 10,220,044 |
| secp256r1 | 1,676,362 | 1,614,526 | 13,787,356 |

SHA-256, Keccak, and Poseidon compile with `--O2`. ECDSA compiles with `--O1` to retain sparse intermediate equations.

Circuit compilation and native witness-library compilation run during preparation and cache their outputs under this crate's `target` directory. The cache covers the transitive circuit sources, compiler executables, compilation flags, platform, and the native comb-table transformation. The generated witness library represents comb constants as immutable arrays and copies them with loops, preserving the Circom lookup constraints and native sanity checks.

## Measurements

Circuit import, key setup, and native witness-library loading run during preparation, outside the proving timer. Proving measurements include auxiliary ECDSA hints, native witness generation, and Spartan-WHIR proving. Verification checks the proof against public values selected by the benchmark, including digests computed with native hash implementations. Fresh upstream blinding randomness varies the proof transcript across samples.

Proof size is the bincode-serialized size of the complete `PoseidonZkProof`, including its public instance and commitment. Preprocessing size sums the bincode-serialized proving key, the native witness generator's `.dat` file, and its shared library. The memory binary performs preparation and proving, including witness generation.

## Validation

The circuit integration tests require the compiler and native dependencies above:

```bash
BENCH_INPUT_PROFILE=reduced cargo test --release -p spartan-whir-bench --lib -- --include-ignored --test-threads=1
```

Use `BENCH_INPUT_PROFILE=full` to cover every hash input size. Tests check circuit satisfaction against native reference values, full-ZK proof verification, and rejection of changed public values. The benchmarked full-ZK implementation is described in the [upstream README](https://github.com/ethereum/spartan-whir/blob/14d6da4211eda59e65cfd0af5e2dcd89d523edc3/README.md); the benchmark metadata records this configured proof mode and marks the system as unaudited.

The [ECDSA circuit helper](tests/ecdsa-circuits.py) checks native witnesses and every R1CS equation against an independent integer implementation for both curves. Set `ECDSA_R1CS` and `ECDSA_P256_R1CS` to the generated `.r1cs` files under `spartan-whir/target/circuits`; each file's native library and `<stem>_cpp` directory must be beside it.

```bash
python3 spartan-whir/tests/ecdsa-circuits.py "$ECDSA_R1CS" "$ECDSA_P256_R1CS"
```

The helper covers ordinary signatures, zero prehashes, prehash reduction, the comb final-doubling scalar, equal and inverse curve points, malformed scalars and coordinates, changed statements, and forged result/decomposition witnesses. The curve constants can be reproduced with [generate_constants.py](circuits/ecdsa/generate_constants.py), the comb tables with [comb_generator.py](circuits/ecdsa/comb_generator.py), and the fake-GLV constants with [generate_fake_glv_constants.py](circuits/ecdsa/generate_fake_glv_constants.py).

The [standalone ECDSA probes](tests/ecdsa/README.md) check comb multiplication, fake-GLV relations, complete fused group operations, signed modular certificates, and polynomial-identity multiplication against independent integer arithmetic and every R1CS equation. Their runner uses the same native table transformation and compilation flags as benchmark preparation.
