# How to Contribute

Howdy! Usual good software engineering practices apply. Write comments. If your codebase is written in Rust, follow standard Rust coding practices where possible, and use `cargo fmt` and `cargo clippy` to tidy up formatting.

## Benchmark Eligibility

- To keep benchmarks meaningful for practical deployments, we only include systems with at least 96 bits of security.

### Benchmark statements

- Hash benchmarks prove knowledge of a private preimage for a public digest.
- Signature benchmarks prove knowledge of a private signature that is valid for a public key and a public message digest.

If a system cannot separate public and private inputs, use the interface it provides and document what the verifier sees and checks.

## Reporting Issues and Review Findings

This repository benchmarks external systems as submitted and integrated. We do not guarantee their correctness, security, or completeness, and we do not act as a full auditor. System maintainers remain responsible for their own codebases. If credible issues are identified, benchmark results may be annotated, revised, or excluded.

### Use GitHub for reports

- Submit review findings via GitHub, not via DMs or other private channels.
- Keep technical discussion in GitHub issues and PRs so there is a durable public record of the claim, evidence, and outcome.
- We do not act as a relay between teams. Maintainers and reviewers should interact directly in the relevant GitHub thread.

### Where to report an issue

The deciding factor is where the relevant code lives.

- If the affected code lives in the system's own repository, file the issue there first.
- If the affected code lives in this repository, open the issue or PR here.
- If the issue is upstream but affects benchmark representation in this repository, open a linked tracking issue or PR here after filing upstream.

Examples of issues that belong upstream:

- incorrect security claims
- soundness or zero-knowledge violations
- protocol or implementation bugs independent of our harness

Examples of issues that belong here:

- circuits maintained in this repository
- benchmark harness or integration code
- parameterization or configuration errors in our setup
- metadata we publish, benchmark inclusion/exclusion, or result interpretation

Confirmed metadata errors may be corrected directly in this repository even when the root cause originates upstream.

## What's Expected in the Contribution/PR

Depending on whether your codebase is written in Rust or not, you should follow the corresponding instructions below.

### Rust Benchmarks

When you add a new benchmark for a certain proving system, you should add a benchmarking code directory at the top level and include it into the workspace(root-level `Cargo.toml`).

Use the shared benchmark harness in the `utils` crate to register Criterion benchmarks with consistent outputs.

#### What you write:

- A one-line set of settings passed to a macro: the target (e.g., `BenchTarget::Sha256`), the proving system (e.g., `ProvingSystem::Plonky2`), an optional feature tag (`None` or `Some("feature")`), a unique memory-measurement binary name (e.g., `"sha256_mem_plonky2"`), the system metadata, and a `|input_size| -> Option<Acceleration>` closure.
- Six small closures that perform the corresponding operations with your proving system: `prepare`, `num_constraints`, `prove`, `verify`, `preprocessing_size`, `proof_size`.

#### Input sizes:

- Variable-size targets (e.g., `sha256` or `keccak`) will use pre-defined input sizes from `utils::metadata`.
- Fixed‑size targets (e.g., ECDSA) will use a single input size value.

#### `acceleration` field:

- Set `acceleration` with the macro closure immediately after your benchmark properties.
- Return `Some(Acceleration::Precompile)` when the operation is proved using a dedicated implementation instead of the system's ordinary instructions or constraints.
- Return `Some(Acceleration::Inline)` when the operation is proved using specialized VM instructions that replace a longer sequence of ordinary VM instructions.
- Return `None` for fully explicit circuit or VM implementations.
- Use the `input_size` argument for mixed cases where only some inputs use acceleration.

#### RAM usage measurement:

- Ensure that your crate provides a binary that will be measured for RAM usage by the harness. Pass the binary name via `mem_binary_name` (e.g., `sha256_mem_plonky2`). This binary is expected to perform only the circuit preprocessing and proving (including witness generation).

#### Quickstart (no shared state)

Provide closures for the six operations; the harness handles looping, timing, and file outputs. Pass the benchmark settings directly as macro arguments.

```rust
use utils::harness::{BenchTarget, ProvingSystem};

utils::define_benchmark_harness!(
    BenchTarget::Sha256,            // target
    ProvingSystem::Binius64,        // proving system
    None,                           // optional feature tag
    "sha256_mem_binius64",         // memory-measurement binary name
    BINIUS64_BENCH_PROPERTIES,      // system metadata
    |_| None,                       // acceleration
    |input_size| { /* return prepared context for input_size */ },
    |prepared| { /* return number of constraints/gates as usize */ 0 },
    |prepared| { /* build and return proof */ },
    |prepared, proof| { /* verify */ },
    |prepared| { /* compute preprocessing size in bytes */ 0 },
    |proof| { /* compute proof size in bytes */ 0 }
);
```

#### Shared state

For systems that need some state that is shared among all closures, use the macro’s shared‑state form. The initializer runs once; closures receive a reference to the shared state. For example, in Polyhedra Expander:

```rust
use utils::harness::{BenchTarget, ProvingSystem};

utils::define_benchmark_harness!(
    BenchTarget::Sha256,        // target
    ProvingSystem::Expander,    // proving system
    None,                       // optional feature tag
    "sha256_mem_expander",     // memory-measurement binary name
    EXPANDER_BENCH_PROPERTIES,  // system metadata
    |_| None,                   // acceleration
    // Initialize shared state once (e.g., MPI universe/world)
    {
        let mpi_config = MPIConfig::init().expect("Failed to initialize MPI");
        let universe = mpi_config.universe();
        let world = mpi_config.world();
        (universe, world)
    },
    |size, _shared| { /* prepare */ },
    |prepared, shared| { /* prove using shared */ },
    |prepared, proof, shared| { /* verify using shared */ },
    |prepared, _shared| { /* preprocessing_size */ 0 },
    |proof, _shared| { /* proof_size */ 0 }
);
```

#### Outputs

The harness writes out Metrics JSON, Criterion reports, and a memory report with standardized names. No manual naming is needed.

## Contributing a Non-Rust Benchmark

We provide a generic orchestrator at the repo root (`./benchmark.sh`) and a CI workflow that will run non-Rust systems in parallel. This section explains how to add your own non-Rust benchmark, using `ligetron` as a concrete example.

### 1) Place your system under a top-level folder

- Create a top-level folder named after your system, e.g. `ligetron/`.
- Inside it, you will provide the code necessary to prove and verify your circuits, and shell scripts per target (e.g. `sha256`), described below.

### 2) Register your folder in CI

Add your folder name to the `FOLDERS` array in the non-Rust workflow so CI will pick it up when you open a PR:

- Edit `.github/workflows/sh_benchmarks_parallel.yml`
- Add your folder to the list (example shows `ligetron`):

https://github.com/privacy-ethereum/csp-benchmarks/blob/3ee2706d3dba930669fd813697576db1901649f8/.github/workflows/sh_benchmarks_parallel.yml#L63-L65

### 3) Implement 4 or 5 shell scripts per target

The orchestrator expects 4 or 5 scripts in your folder for each target name (e.g. `sha256`). The scripts must be executable and named:

- `[target]_prepare.sh` - prepare the input state for your prover/verifier
- `[target]_prove.sh` - prove the input state
- `[target]_prove_for_verify.sh` - prove the input state and prepare proof for verify (optional)
- `[target]_verify.sh` - verify the proof
- `[target]_measure.sh` - measure the proof and preprocessing sizes. By preprocessing we mean any circuit-specific state that a real application would need to persist between prover runs, e.g., proving key.

For `ligetron` with the `sha256` target, these are:

- `ligetron/sha256_prepare.sh`
- `ligetron/sha256_prove.sh`
- `ligetron/sha256_verify.sh`
- `ligetron/sha256_measure.sh`

For `barretenberg` with the `sha256` target, there is an extra script:

- `barretenberg/sha256_prove_for_verify.sh`

The root `./benchmark.sh` will invoke them in a fixed way via `hyperfine` and our helper scripts. Your scripts should follow the APIs below.

### 4) Add metadata to `bench_props.json`

- Each non-Rust benchmark folder MUST contain a `bench_props.json` file at its root. The root `benchmark.sh` will error out if this file is missing.
- The file should contain the metadata for the benchmark.
- You can copy the field structure from the example at `ligetron/bench_props.json`.
- The full list of supported fields and their semantics is defined by `BenchProperties` in `utils/src/harness.rs`.

#### `is_zk` policy

`is_zk` reports whether the exact proof mode exercised by the benchmark is implemented as zero-knowledge across the complete proving and verification flow. It records the configured proof mode; audit coverage and formal assurance are separate.

- Set `is_zk` to `true` when public documentation or source for the exact benchmarked path identifies it as zero-knowledge and shows that its required blinding or masking is enabled throughout that flow.
- Cite evidence that covers the exact benchmarked code path. A formal security argument strengthens the evidence but is not required for this property.
- Set `is_zk` to `false` when the benchmarked path omits or disables the zero-knowledge mechanism, exposes private inputs or witness-derived information to the verifier, or relies on a separate wrapper or proof mode that is not benchmarked.
- Set `is_zk` to `false` when the project publishes an unresolved privacy caveat that applies to the benchmarked mode, including pending implementation changes needed for its zero-knowledge claim.
- When the evidence for the exact benchmarked mode is inconclusive, set `is_zk` to `false`.

### 5) Add benchmark flags to `bench_flags.json`

Non-Rust systems may include an optional `bench_flags.json` file next to `bench_props.json`. This file is how contributors set per-benchmark feature tags and acceleration values.

Use `feat` for a measurement variant that shares a target name, such as the curve used by an ECDSA benchmark.
Adding a `feat` entry also adds `_[feature]` to that target's metrics filename.

`acceleration` is an enum with two values: `"precompile"` and `"inline"`. Omit the target when its implementation is fully explicit.

Example with both target-wide and input-size-specific values:

```json
{
  "feat": {
    "ecdsa": "secp256r1"
  },
  "acceleration": {
    "sha256": "precompile",
    "keccak": "precompile",
    "ecdsa": "precompile",
    "poseidon": "precompile",
    "poseidon2": {
      "by_input_size": {
        "4": "precompile"
      }
    }
  }
}
```

- A target value may be `"precompile"`, `"inline"`, or an object.
- `default` is optional and defaults to no acceleration.
- `by_input_size` keys are decimal input-size strings.
- `by_input_size` overrides the target `default`.
- Missing `feat` entries omit the feature tag.
- Missing `bench_flags.json` means feature tags and acceleration values are omitted.

#### API: `[target]_prepare.sh`

- Required environment variables:
  - `UTILS_BIN`: path to the `utils` binary in this repo (use it to generate inputs)
  - `INPUT_SIZE`: input size in bytes, if applicable
  - `STATE_JSON`: path to write a JSON file containing the input state for your prover/verifier
- Behavior:
  - Produce a single-line JSON (or pretty JSON) at `$STATE_JSON`. This JSON is opaque to the orchestrator; it is passed verbatim to your prover/verifier.
  - Exit non-zero on error.
- Example (Ligetron): builds a JSON containing the WASM program path, shader path, and args:

https://github.com/privacy-ethereum/csp-benchmarks/blob/3ee2706d3dba930669fd813697576db1901649f8/ligetron/sha256_prepare.sh#L13-L34

#### API: `[target]_prove.sh`

- Required environment variables:
  - `STATE_JSON`: path to the JSON produced by prepare
- Behavior:
  - Run the prover for the state described by `$STATE_JSON`.
  - Should produce a proof artifact in a predictable location for size measurement (see measure API).
  - Exit non-zero on error.
- Example (Ligetron):

https://github.com/privacy-ethereum/csp-benchmarks/blob/3ee2706d3dba930669fd813697576db1901649f8/ligetron/sha256_prove.sh#L9-L10

#### API: `[target]_prove_for_verify.sh`

- Required environment variables:
  - `STATE_JSON`: path to the JSON produced by prepare
- Behavior:
  - Run the prover for the state described by `$STATE_JSON`.
  - Should produce a proof artifact in a predictable location for size measurement (see measure API).
  - Should produce additional files for verification, if there is a need (e.g., verification key).
  - Exit non-zero on error.
- Example (Barretenberg):

https://github.com/privacy-ethereum/csp-benchmarks/blob/3ee2706d3dba930669fd813697576db1901649f8/barretenberg/sha256_prove_for_verify.sh#L19-L24

#### API: `[target]_verify.sh`

- Required environment variables:
  - `STATE_JSON`: path to the JSON produced by prepare (and for CI, a proof will be generated beforehand)
- Behavior:
  - Run the verifier for the state described by `$STATE_JSON`.
  - Exit non-zero on error.
- Example (Ligetron):

https://github.com/privacy-ethereum/csp-benchmarks/blob/3ee2706d3dba930669fd813697576db1901649f8/ligetron/sha256_verify.sh#L9-L10

#### API: `[target]_measure.sh`

- Required environment variables:
  - `STATE_JSON`: same JSON used for proving (you may need to run a quiet proof once to materialize the artifacts)
  - `SIZES_JSON`: output path for sizes JSON
- Behavior:
  - Output a JSON object containing `proof_size` and `preprocessing_size` (in bytes). Write it to `$SIZES_JSON`.
  - Dynamically update/create `circuit_sizes.json` in your system folder by recording the number of constraints/gates for the current target and input size.
  - Exit non-zero on error.
- Example output:

```json
{ "proof_size": 475590, "preprocessing_size": 329524 }
```

- Example (Ligetron): finds `proof.data` and measures the WASM size as preprocessing:

https://github.com/privacy-ethereum/csp-benchmarks/blob/3ee2706d3dba930669fd813697576db1901649f8/ligetron/sha256_measure.sh#L14-L39

### 6) What the orchestrator and CI do for you

- The root `benchmark.sh` will, for each target and for each input size (driven by the `utils` crate):
  - Run `hyperfine` on your `[target]_prove.sh` and `[target]_verify.sh` to collect timing metrics.
  - Call our `measure_mem_avg.sh` to capture peak memory during proving.
  - Call your `[target]_measure.sh` to capture proof and preprocessing sizes.
  - Post-process `hyperfine` outputs into a `[target]_[size]_[system]_..._metrics.json` file.
  - Require `circuit_sizes.json` (generated by your measure scripts) and read it to embed the constraints/gates counts into the Metrics JSONs.
  - Read optional `bench_flags.json` and embed `feat` and `acceleration` into the Metrics JSONs.
- Ensure your `[target]_prove.sh` script performs a "lean" proof so memory is measured accurately.
- Ensure all four scripts are executable (`chmod +x`).

### Reporting circuit size (constraints/gates) for non-Rust systems

Non-Rust systems typically do not expose the number of constraints/gates as a dedicated public API. We therefore generate these numbers dynamically during measurement.

- Your `[target]_measure.sh` should compute the circuit size for each input and update a `circuit_sizes.json` in your system folder. The orchestrator reads this file (`--num-constraints-file`) at the end of all benchmark runs and writes the values into the Metrics JSONs.

Example (`circuit_sizes.json`):

```json
{
  "sha256": {
    "128": 67890,
    ...
  },
  "ecdsa": {
    "32": 12345,
    ...
  },
  ...
}
```

- How to obtain the numbers is system‑specific. For example: Barretenberg/Noir can run `noir-profiler gates` and parse `Circuit size: N`; Ligetron can run a quiet proof and sum Stage 1 linear + quadratic constraints.

- Tip: use a single‑iteration run to quickly emit sizes without full benchmarking:

```bash
BENCH_INPUT_PROFILE=full sh ./benchmark.sh --system-dir ./barretenberg --logging --quick --no-ram
```

### 7) File naming recap for non-Rust systems

- Metrics: `[target]_[size]_[proving_system]_[optional_feature]_metrics.json`
- Memory report (created by our wrapper): `[target]_[size]_mem_report.json` — transient; its `peak_memory` is folded into the metrics JSON and the file is then removed.
- Sizes (produced by your `[target]_measure.sh`): contains `proof_size` and `preprocessing_size` as shown above
- Benchmark flags (optional): `bench_flags.json`

Use `ligetron` and `barretenberg` as a reference implementation.

## Useful Commands For Non-Rust Systems

Use `--logging` to enable logging, `--quick` to run only a single `hyperfine` iteration, and `--no-ram` to skip RAM measurement.

```bash
# For example, for Noir/Barretenberg
BENCH_INPUT_PROFILE=full sh ./benchmark.sh --system-dir ./barretenberg --logging --quick --no-ram
```
