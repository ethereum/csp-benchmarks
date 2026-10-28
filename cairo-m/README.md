# Cairo-M(kakarot zkVM) SHA256 benchmarks

This benchmark code is from: https://github.com/kkrt-labs/zkvm-benchmarks/tree/master/cairo-m

## Prerequisites

Use the [pinned Rust toolchain](rust-toolchain.toml). On macOS, install LLVM:

```bash
brew install llvm
```

The [LLVM wrapper](../.github/actions/install-llvm/with-llvm.sh) sets the Homebrew compiler tools and macOS SDK for each command. Compiler flags are defined in the [Cargo configuration](.cargo/config.toml). On other platforms, install LLD and run the Cargo commands below without the wrapper.

## Build and lint

From the repository root on macOS:

```bash
cd cairo-m
../.github/actions/install-llvm/with-llvm.sh cargo build
../.github/actions/install-llvm/with-llvm.sh cargo clippy --all-targets --all-features
```

## Run the benchmark

From the repository root on macOS, build the memory binary and copy it to the shared target directory used by the benchmark harness:

```bash
cd cairo-m
../.github/actions/install-llvm/with-llvm.sh cargo build --release --bin sha256_mem_cairo_m
mkdir -p ../target/release
cp target/release/sha256_mem_cairo_m ../target/release/
BENCH_INPUT_PROFILE=reduced ../.github/actions/install-llvm/with-llvm.sh cargo bench --bench sha256_bench
```
