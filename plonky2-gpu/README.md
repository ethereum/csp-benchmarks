# Plonky2 GPU and compiled witness benchmarks

This adapter measures the GPU fork with a compiled witness executor. SHA-256,
Keccak-256 and Poseidon reuse the stock adapter's circuit sources, preparation,
public digest checks and `standard_recursion_zk_config` directly via Rust path
modules. ECDSA is not included in this variant.

The stock `plonky2/` adapter retains its original dependencies and behavior.
This crate is a normal workspace member. Cargo keeps its pinned Git Plonky2
and u32 packages separate from the registry packages used by stock Plonky2.
Fork revisions are pinned in `Cargo.toml` and the root `Cargo.lock`; no local
source overrides are required.

## Run

Use the repository's canonical Rust toolchain and an available hardware GPU
(Metal on macOS, or a supported Vulkan/DX12 adapter). Run from this directory so
the harness finds its memory script:

```sh
cd plonky2-gpu
BENCH_INPUT_PROFILE=reduced cargo bench --locked --bench sha256
BENCH_INPUT_PROFILE=reduced cargo bench --locked --bench keccak
BENCH_INPUT_PROFILE=reduced cargo bench --locked --bench poseidon
```

Use `BENCH_INPUT_PROFILE=full` for all canonical input sizes. Results use the
`plonky2-gpu` system identifier and the `gpu_executor` feature tag,
e.g. `sha256_128_plonky2-gpu_gpu_executor_metrics.json`. This feature tag does not
use the `acceleration` field: Poseidon retains stock's `precompile` classification;
SHA-256 and Keccak retain `None`.

The separate system identifier lets the shared collector retain the fork's
`not_audited` metadata alongside the stock implementation's audit status; feature
tags alone do not separate system properties.

GPU support is an unconditional dependency feature. The harness's plain
`cargo build --release --bin ...` therefore builds the same GPU/executor memory
variant. Each uniquely named memory binary prepares and proves, including
executor compilation and witness generation, without verification. The shared
harness locates the binary using Cargo's effective target directory, including
when `CARGO_TARGET_DIR` is set.

The adapter requires a hardware GPU and fails if GPU initialization is disabled
or unavailable. It preserves the fork's automatic GPU/hybrid routing and witness
placement; `PLONKY2_GPU_*` settings can select the supported backend, adapter and
routing. The new u32 witness operations execute on the CPU and feed GPU proving.
Some phases are intentionally on the CPU. Executor compilation/installation is
mandatory and `WitnessFallback::Error` is set explicitly, regardless of the
process's fallback preference. Use identical runtime settings for the benchmark
and its inherited memory subprocess.

## Setup and measurements

Preparation initializes the GPU, builds the unchanged circuit, and compiles and
installs its executor. These operations run outside the harness's proving timer.
Every Criterion iteration prepares a fresh circuit, following the stock adapter's
harness behavior. Witness generation remains inside the timed proof.

`preprocessing_size` includes serialized common data, prover data and the
compiled witness program. The program must be counted separately because normal
Plonky2 circuit serialization omits it. Cache sizes depend on the circuit and
build. The memory subprocess includes preparation and proving in its peak RSS;
RSS is not a complete measure of discrete GPU VRAM.

No external shader artifact or prebuilt witness cache is supplied. The first
proof creates shader/pipeline and circuit-dependent GPU caches as needed; the
harness performs an initial proof before Criterion, whose normal warm-up follows.
Process/driver caches may therefore be warm for headline timings. A separate
cold-start measurement is needed to quantify setup latency: the shared metrics
format has no setup-duration field. Reusable-circuit probe results are not
substitutes for measurements from this fresh-circuit harness.

Protocol metadata follows the stock hash adapter (including the 97-bit estimate
and enabled zero-knowledge blinding). The GPU fork's implementation changes have
not been audited, so this variant reports `not_audited`.

## Adapter checks

```sh
cargo test --locked --test adapter
cargo test --release --locked --test adapter -- --include-ignored --test-threads=1
```

The second command needs GPU access. It prepares all three hashes, accounts for
preprocessing, reloads each executor and verifies two proofs against the public
digest. Core/u32 witness differential and malformed-program tests live in the
respective fork repositories.
