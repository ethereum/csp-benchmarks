# gnark benchmarks

The benchmarks use [gnark v0.16.4](https://github.com/Consensys/gnark/tree/v0.16.4) and the gnark-crypto revision it requires, [`1409fe592052`](https://github.com/Consensys/gnark-crypto/tree/1409fe592052). Circuits compile to R1CS and are proved with Groth16 over BN254.

## Prerequisites

Install Go 1.26.8 or newer, plus the Rust, `jq` and Hyperfine setup described in the [root README](../README.MD).

## Run the benchmarks

From the repository root:

```bash
(cd gnark && go test ./... && go build -o gnark-bench .)
cargo build --release -p utils
BENCH_INPUT_PROFILE=reduced bash ./benchmark.sh --system-dir ./gnark --logging --quick --no-ram
```

Omit `--quick --no-ram` for ten timing samples and RAM measurement, and use `BENCH_INPUT_PROFILE=full` for the complete input range. The tests check that each circuit accepts the benchmark inputs and rejects changed public or private values, and that verification uses only public artifacts.

## Circuits

Each hash benchmark proves knowledge of a private preimage for a public digest. ECDSA proves knowledge of a private signature for a public message digest and public key. All circuits use ordinary constraints, so no acceleration is reported.

| Target | Private input | Public input | Implementation |
| --- | --- | --- | --- |
| SHA-256 | Message bytes | 32 digest bytes | `std/hash/sha2` |
| Keccak-256 | Message bytes | 32 digest bytes | `std/hash/sha3.NewLegacyKeccak256` |
| Poseidon2 | BN254 field elements | One field-element digest | `std/hash/poseidon2` |
| ECDSA secp256r1 | Signature `(r, s)` | 32-byte digest and public key `(x, y)` | `std/signature/ecdsa`, complete arithmetic |

Poseidon2 hashes the field elements from `utils poseidon` with gnark's [default BN254 parameters](https://github.com/Consensys/gnark-crypto/blob/1409fe592052/ecc/bn254/fr/poseidon2/hash.go): width 2, 6 full rounds, 50 partial rounds, and Merkle–Damgård hashing from a zero state. The expected digest is computed natively with gnark-crypto. ECDSA verifies the prehashed digest from `utils ecdsa` and does not hash the message.

SHA-256, Keccak and ECDSA use gnark's range checks and lookups, which add one [BSB22 commitment](https://eprint.iacr.org/2022/1072) and its proof of knowledge to each Groth16 proof. Poseidon2 uses none.

## Measurement boundaries

- Preparation compiles the circuit, runs the Groth16 setup, and stores the R1CS, keys and public witness under `.bench_state/`.
- Proving loads the R1CS and proving key, generates the witness, proves, and writes the proof.
- Verification reads only the verification key, public witness and proof.
- Proof size is the serialized proof. Preprocessing size is the serialized R1CS, proving key and verification key. `num_constraints` comes from `GetNbConstraints()`.

## Trusted setup

Each preparation samples a fresh circuit-specific setup. These keys are suitable for benchmarking only; production deployments need an MPC ceremony.

## Proof mode

Security is recorded as 100 bits, matching the repository's other BN254 Groth16 benchmarks ([pairing-friendly curve estimates](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-pairing-friendly-curves-12)). `is_zk` is `true`: the [Groth16 prover](https://github.com/Consensys/gnark/blob/v0.16.4/backend/groth16/bn254/prove.go) samples fresh blinding scalars `r` and `s` for each proof, and the [commitment builder](https://github.com/Consensys/gnark/blob/v0.16.4/frontend/cs/r1cs/api.go#L799-L810) adds a random mask to the committed values. The audit status is `partially_audited`: gnark [lists audits](https://github.com/Consensys/gnark/tree/v0.16.4#audits) of its standard library, arithmetic and gnark-crypto, which do not cover this release as a whole.
