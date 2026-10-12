# RISC Zero benchmarks

## Prerequisites

Follow `.github/actions/install-risc0` to provision the vendor toolchain:

```bash
curl -fsSL --retry 5 --proto '=https' --tlsv1.2 https://risczero.com/install | bash
export PATH="$HOME/.risc0/bin:$PATH"

rzup install rust 1.97.0
rzup install cpp 2024.1.5
rzup install r0vm 3.0.6
rzup install cargo-risczero 3.0.6
```

The workspace host compiler is selected by the root `rust-toolchain.toml`. The guest compiler is RISC Zero Rust 1.97.0.

## Running the benchmarks

```bash
cargo bench
```
