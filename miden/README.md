# Miden benchmarks

The benchmark uses Miden VM 0.34.0 through the ERE adapter at [revision `c9527535`](https://github.com/Client-Side-Proving/ere/commit/c9527535fb7976aee30727c3d3bd87a792c423d1) of the CSP fork. Its separate Cargo workspace uses Rust 1.98.1 and has a lockfile independent of the main benchmark workspace.

## Prerequisites

Cargo fetches the pinned ERE dependency automatically.

Rustup selects the toolchain in `miden/rust-toolchain.toml` when running commands from this directory.

## Benchmarking

```bash
mkdir -p ../target/release
cargo build --release
cp target/release/*_mem_miden ../target/release/
BENCH_INPUT_PROFILE=reduced cargo bench
```

The default suite includes SHA-256, BLAKE3, and secp256k1 ECDSA. The shared RAM harness reads memory binaries from `../target/release`. The SHA-256 and BLAKE3 guests prove knowledge of a private message for a public digest. Compiled guests are cached in `guest/<target>/target/<target>.bin`; delete those files after changing guest assembly or the SDK revision.

The ECDSA guest verifies a supplied secp256k1 prehash with Miden scalar and curve precompiles. It publishes the message digest and a Poseidon2 commitment to the public key coordinates. Verification checks both against the expected statement and requires a complete proof of all precompile work.
