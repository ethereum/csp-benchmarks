# Client-Side Proving Benchmarks

This repository contains benchmarks of zero-knowledge proving systems and zkVMs. The goal is to _continuously_ map the landscape of proving systems that are suitable for client-side environments.

All benchmark results are published on [ethproofs.org](https://ethproofs.org/csp-benchmarks) quarterly, where they are rendered into a user-friendly comparison interface.

## Why CSP benchmarking?

Client-side proving (CSP) is emerging as a requirement for privacy-preserving applications like anonymous credentials, private transfers, and more. Many systems claim to be “CSP-friendly,” but their real performance varies dramatically across four important dimensions:

- proving time
- peak memory
- proof size
- preprocessing size

This repository provides a unified benchmarking harness for comparing proving systems under identical conditions.

## What we benchmark

We aim to benchmark the canonical circuits that correspond to typical use cases or represent typical bottlenecks in client-side ZK proving, for example SHA-256, ECDSA, Keccak etc. The planned benchmarking scope can be found in this [spreadsheet](https://docs.google.com/spreadsheets/d/1LFG-icfQf4-3YoxoR4GPdkcbAmD01mLPhiM3x4ufmnU/edit?usp=sharing).

## How we run the benchmarks

As of Q3 2025, we run benchmarks quarterly on a dedicated AWS `mac2.metal` host which has the following specifications:

- Apple M1 CPU with 8 cores (arm64 architecture)
- 16 GB RAM

This hardware is one of the closest to a client-side device among the available cloud options (i.e., close to iPhone chip, has no CUDA, has no AVX, etc.).

Our future plans include running the benchmarks in a cloud device farm (Android and iOS mobile devices).

## How you can run benchmarks locally

1.  **Install the prerequisites**
    - Install Rust via `rustup` together with the toolchains used in [CI](./.github/workflows/rust_benchmarks_parallel.yml): `nightly-2026-03-04` (default), `1.98.1` for `binius64`, and `nightly-2025-04-06` for `cairo-m`. Add the `llvm-tools`, `rustc-dev`, `rustfmt`, and `clippy` components so `cargo bench` matches the workflow in `.github/workflows/rust_benchmarks_parallel.yml`.
    - Ensure `cargo`, `cmake`, and a recent `clang`/`lld` are available (the helper actions under [`.github/actions/install-llvm`](./.github/actions/install-llvm) show the expected setup). Install Homebrew packages `bash` and `jq`, plus `/usr/bin/time` for RAM measurements. Install the Hyperfine version specified in [`.hyperfine-version`](./.hyperfine-version) from its [release assets](https://github.com/sharkdp/hyperfine/releases) and ensure that binary is first on `PATH`.
    - Install per-system toolchains as needed: OpenMPI for `polyhedra-expander`, the Ligero prover stack for `ligetron`, Noir version >=1.0.0-beta.13 for `barretenberg`, and the RISC Zero SDK. Each folder documents its own bootstrap script and the matching GitHub Action ([`install-risc0`](./.github/actions/install-risc0), etc.) can be used as a reference.
2.  **Run the benchmarks**
    - Build the workspace once: `cargo build --release --workspace`. Rust crates with separate Cargo roots, such as `binius64/`, `provekit-groth16/`, `cairo-m/`, `rookie-numbers/`, and `stark-v/`, build from inside their own directories.
    - For Rust crates, run

    ```bash
    BENCH_INPUT_PROFILE=full cargo bench
    ```

    - Alternatively, to run individual benchmarks, `cd` into the crate directory and run `BENCH_INPUT_PROFILE=full cargo bench`.
    - Use `BENCH_INPUT_PROFILE=reduced` to run with a reduced set of input sizes.
    - For non-Rust systems, build the utilities crate (`cargo build --release -p utils`) and invoke `benchmark.sh`, e.g. `BENCH_INPUT_PROFILE=full bash ./benchmark.sh --system-dir ./barretenberg --logging --quick` (see [sh_benchmarks_parallel.yml](./.github/workflows/sh_benchmarks_parallel.yml)).

## Run a targeted Rust benchmark in GitHub Actions

For example, to run only `risc0` / `sha256` on a self-hosted runner:

1. Open **Actions** -> **Dispatch All Benchmarks (manual)** -> **Run workflow**.
2. Set:
   - `benchmark_crate`: `risc0`
   - `benchmark_target`: `sha256`
   - `prod-run`: `true`
   - `run_non_rust`: `false` (optional, keeps this run Rust-only)
3. Keep other inputs as needed (`run_all` is ignored when `benchmark_crate` is set).

Notes:

- You can also run **Rust Benchmarks (parallel)** directly with `benchmark_crate=risc0`, `benchmark_target=sha256`, and `prod_run=true`.
- If `run_non_rust=false`, the fan-in collector workflow may not auto-complete for that SHA because it waits for both Rust and Non-Rust parent workflows.

## Repository structure

- `utils/` – shared Rust crate that defines the benchmark harness, metadata about input sizes, common zkVM traits, and helper binaries (`utils`, `collect_benchmarks`, `format_hyperfine`).
- `mobile/` – mobile benchmarks for Android and iOS.
- `benchmark.sh` / `measure_mem_avg.sh` – orchestration scripts for non-Rust systems and RAM measurement.
- `results/` – storage for published benchmark results.
- Rust proving system and zkVM crates such as `binius64/`, `plonky2/`, `polyhedra-expander/`, `provekit/`, etc., each exposing a Criterion bench target registered through the shared harness. Some crates have separate Cargo roots and build from their own directories.
- Non-Rust proving system folders (`barretenberg/`, `ligetron/`, etc.) that contain the shell scripts required by `benchmark.sh`.

## Result format & metrics

- Every benchmark run produces `{target}_{input}_{system}_[optional_feature]_metrics.json`, following the schema implemented in `utils::bench::Metrics`: name, feature tag, target, input size, prove/verify wall-clock durations, optional execution cycles (for zkVMs), proof and preprocessing sizes, constraint counts, peak memory, optional `acceleration`, and the descriptive `BenchProperties` block (classification, security level, audit status, ISA, etc.). `acceleration` is either `precompile` or `inline`.
- Peak memory is captured separately via `{target}_{input}_{system}_[optional_feature]_mem_report.json`, which stores the average of 10 `/usr/bin/time` samples gathered by `measure_mem_avg.sh`. Non-Rust systems also emit `{target}_{input}_sizes.json` for proof/preprocessing and update a shared `circuit_sizes.json` keyed by target and input size.
- For non-Rust systems, raw `hyperfine_{target}_{input}_*.json` files are post-processed by the `format_hyperfine` binary so their timing data can be merged with size, RAM, constraint metadata, and optional `bench_flags.json` benchmark flags.
- When running in Github Actions, aggregated outputs are checked into `results/` and uploaded to [ethproofs.org](https://ethproofs.org/csp-benchmarks).

## Methodology

- Rust benchmarks register with the `utils::define_benchmark_harness!` macro (see `CONTRIBUTING.md`). The harness iterates over the canonical input sizes defined in `utils::metadata`, executes Criterion benches for prove and verify, records metrics, and invokes the dedicated memory binary.
- Non-Rust systems achieve the same by orchestrating `{target}_prepare.sh`, `{target}_prove.sh`, `{target}_verify.sh`, and `{target}_measure.sh` scripts in each system folder via `benchmark.sh`.
- Bench runs are parameterized by the `BENCH_INPUT_PROFILE` environment variable (`full` for full range of input sizes, `reduced` for PR/local smoke tests).

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for detailed instructions on adding new Rust or non-Rust systems, registering benchmarks in the workspace, and supplying the metadata required by the shared harness and orchestrator.

## About the authors

https://pse.dev/projects/client-side-proving

## Acknowledgements

We are thankful to

- [zkID team](https://pse.dev/projects/zk-id) for kickstarting the project
- [EthProofs team](https://ethproofs.org) for building the webpage and hosting the results
- [EF Applied Cryptography Team](https://github.com/eth-act) for the unified zkVM interface library - [ere](https://github.com/eth-act/ere)
- Everyone who helped us refine the benchmarking methodology and the results
