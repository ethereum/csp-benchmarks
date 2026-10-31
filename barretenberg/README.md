# Noir + Barretenberg benchmarks

These benchmarks use the shared Rust Criterion harness and [`barretenberg-rs` 5.2.1](https://crates.io/crates/barretenberg-rs/5.2.1). Its `PipeBackend` communicates with a persistent `bb msgpack run` child process. Nargo compiles the Noir circuits and generates witnesses.

## Prerequisites

Use the repository's Rust toolchain, Bash, `jq`, and `/usr/bin/time` for RAM measurement. Install the Nargo and Barretenberg versions used in [Rust benchmark CI](../.github/workflows/rust_benchmarks_parallel.yml):

```bash
curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash
export PATH="$HOME/.nargo/bin:$PATH"
noirup --version 1.0.0-beta.25

curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/refs/heads/next/barretenberg/bbup/install | bash
export PATH="$HOME/.bb:$PATH"
bbup -v 5.2.1
```

Cargo pins `barretenberg-rs` to `=5.2.1` with its `native` feature for `PipeBackend`. Set `BB_BIN` and `NARGO_BIN` to use explicit executable paths.

The Noir dependencies are SHA-256 `v0.3.0`, Keccak `v0.1.3`, and Poseidon `v0.3.0` (also used for Poseidon2).

## Run

From the repository root:

```bash
cd barretenberg
BENCH_INPUT_PROFILE=reduced cargo bench
```

Run one target with `BENCH_INPUT_PROFILE=reduced cargo bench --bench sha256_bench`. The other bench names are `blake3_bench`, `keccak_bench`, `ecdsa_bench`, `poseidon_bench`, and `poseidon2_bench`.

Use `BENCH_INPUT_PROFILE=full` for the complete input range:

| Target | Reduced | Full |
| --- | --- | --- |
| SHA-256 / Keccak (bytes) | 128, 256 | 128, 256, 512, 1024, 2048 |
| BLAKE3 (bytes) | 128, 256 | 128, 256, 512, 1024 |
| ECDSA secp256r1 (digest bytes) | 32 | 32 |
| Poseidon / Poseidon2 (field elements) | 2, 8 | 2, 4, 8, 12, 16 |

The BLAKE3 black box supports up to 1024 input bytes.

Check generated circuits, benchmark inputs, and public values through the adapter with the installed tools:

```bash
BENCH_INPUT_PROFILE=full cargo test --release -p barretenberg-bench \
  --test integration -- --ignored --test-threads=1
```

## Measurement boundaries

- Circuit compilation, gate counting, and verification-key preparation run before timing. Generated projects are stored under `target/noir/<target>_<size>`.
- Proving includes Nargo witness generation and the `circuit_prove` API call, including Barretenberg's construction of its prover instance.
- Verification uses the prepared key, proof, and public inputs. The benchmark requires a successful verification result.
- Each benchmark executable reuses one BB child process and its SRS cache. Session startup and shutdown occur outside timed proving and verification.
- Proof size is the sum of the proof field byte lengths. Preprocessing size is the compiled circuit JSON's file size. Gate counts come from `circuit_stats`.
- The shared RAM script averages ten runs of a dedicated memory binary. Each run loads the prepared bytecode and verification key, generates a witness, proves, and reaps the BB child before exiting.

The shared harness writes Criterion reports under `../target/criterion` and metrics and memory reports in this directory. ECDSA uses the `secp256r1` feature tag. All six workloads report `precompile` acceleration.
