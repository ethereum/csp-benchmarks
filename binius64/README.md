# Binius64 hash benchmarks

The SHA-256, Keccak-256 and BLAKE3 benchmarks use circuits from [Binius64 revision 3bab18d](https://github.com/IrreducibleOSS/binius64/tree/3bab18d86086b21682f12bb561a20b4a5e1b03b5). The proof flow uses upstream `ZKProver` and `ZKVerifier` with 96-bit security.

`preprocessing_size` measures the serialized constraint system. The upstream frontend circuit and its witness evaluation state have no complete serialization interface, so this metric omits part of the state retained by `prepare`.

## Prerequisites

Use the pinned toolchain from `rust-toolchain.toml`:

```bash
rustup toolchain install 1.98.1
```

## Run the benchmarks

```bash
RUSTFLAGS="-C target-cpu=native" cargo bench
```
