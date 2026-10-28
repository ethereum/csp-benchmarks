# Binius64 hash benchmarks

The SHA-256, Keccak-256 and BLAKE3 benchmarks use circuits from the [Client-Side Proving Binius64 fork at revision 1bdf6a92](https://github.com/Client-Side-Proving/binius64/tree/1bdf6a9206b0ece76b721cad72ab188a406e4b93). The proof flow uses upstream `ZKProver` and `ZKVerifier` with 96-bit security.

`preprocessing_size` measures the serialized constraint system. The upstream frontend circuit and its witness evaluation state have no complete serialization interface, so this metric omits part of the state retained by `prepare`.

## Prerequisites

Use the [pinned Rust toolchain](../rust-toolchain.toml).

## Run the benchmarks

The [Cargo configuration](.cargo/config.toml) enables native CPU instructions, ThinLTO and debug information.

From the repository root:

```bash
cd binius64
BENCH_INPUT_PROFILE=reduced cargo bench --bench sha256_bench --bench keccak_bench --bench blake3_bench
```
