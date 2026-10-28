# Halo2 SHA256 + Keccak benchmarks

The circuits come from Axiom's [`zkevm-hashes`](https://github.com/axiom-crypto/halo2-lib/tree/develop/hashes/zkevm) crate, Axiom's revision of the PSE zkEVM hash circuits.

Proofs use Halo2's KZG backend over BN254 with SHPLONK multi-open and Blake2b for Fiat-Shamir, matching the upstream tests.

The Axiom git dependencies use `branch = "develop"` so direct and transitive dependencies share the same `halo2-base` source. `Cargo.lock` pins their commits.

## Prerequisites

Use the [pinned Rust toolchain](../rust-toolchain.toml).

## Benchmarking

```bash
cd halo2

# Quick test with reduced inputs
BENCH_INPUT_PROFILE=reduced cargo bench -p halo2_circuits

# Single target
BENCH_INPUT_PROFILE=reduced cargo bench -p halo2_circuits --bench sha256

# Memory measurement binaries
cargo run --release --bin sha256_mem_halo2 -- --input-size 128
```

`gen_srs` deterministically generates and caches structured reference strings under `params/` (override with `PARAMS_DIR`). The directory is generated and gitignored, and the first run at a given `k` creates it. These parameters are intended for benchmarking; production deployments require trusted parameters.

## Circuit details

`src/circuits.rs` defines `Circuit` implementations that pass one private message to upstream's `multi_sha256` or `multi_keccak` and constrain the resulting digest to one public instance column containing two 128-bit limbs. The SHA-256 circuit fixes the cumulative message length at each block. The Keccak circuit fixes the initial byte count and constrains the selected output row to be final. Upstream defines equivalent wrappers inside `#[cfg(test)]` modules, so the benchmark supplies its own wrappers while retaining the upstream hash constraints.

Each circuit receives the exact block or permutation capacity required by the requested message, so upstream does not add empty-message hashes to fill the domain. The configured constraint system determines the unusable rows, and each input uses the smallest circuit degree `k` that fits those rows.

The `k` calculation is implemented by `sha256_dimensions` and `keccak_dimensions` in `src/bench.rs`.

| bytes | SHA256 `k` | Keccak `k` |
| ----: | ---------: | ---------: |
|   128 |          8 |         11 |
|   256 |          9 |         11 |
|   512 |         10 |         12 |
|  1024 |         11 |         13 |
|  2048 |         12 |         14 |

SHA-256 has no lookup tables and a fixed column count of approximately 130, so `k` sets the domain size. Keccak uses `rows_per_round = 28`, matching upstream's `packed_multi_keccak_simple` test case `(k: 14, rows_per_round: 28)`; this parameter trades circuit width against height, and `k` also sizes the lookup tables through `KeccakConfigParams`.

## Reported metrics

- `num_constraints` — row budget required by the requested hash, excluding Halo2's unusable rows and padding up to `2^k`.
- `preprocessing_size` — serialized proving key in `RawBytes` format. The universal KZG SRS is not part of the proving key and is not counted.
- `proof_size` — transcript length in bytes.

`is_zk` is `true`: [Axiom describes `halo2-axiom` v0.5.3 as a PLONK-based zero-knowledge proving system](https://github.com/axiom-crypto/halo2/blob/v0.5.3/halo2_proofs/Cargo.toml#L15-L20), and the benchmark calls its normal `create_proof` API with `OsRng`. Halo2 [computes enough blinding rows to hide every witness polynomial](https://github.com/axiom-crypto/halo2/blob/v0.5.3/halo2_proofs/src/plonk/circuit.rs#L2305-L2331), [fills those rows with random values](https://github.com/axiom-crypto/halo2/blob/v0.5.3/halo2_proofs/src/plonk/witness.rs#L445-L450), and [randomizes the vanishing argument](https://github.com/axiom-crypto/halo2/blob/v0.5.3/halo2_proofs/src/plonk/vanishing/prover.rs#L48-L60).
