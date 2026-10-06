# CSP Benchmarks (agent instructions)

See `README.MD` for project overview and `CONTRIBUTING.md` for the full contributor guide.

## Golden rules

- **YOU MUST** read `CONTRIBUTING.md` before changing benchmarks.
- **Prefer existing patterns**: copy from an existing system folder closest to what you’re adding.
- **Don’t commit generated artifacts** (e.g. `target/`, downloaded toolchains, large generated outputs) unless explicitly requested.
- **When running git in automation**, use `git --no-pager` (avoid interactive pagers).
- **Avoid changing `utils/` APIs** unless necessary (it affects all benchmarks).
- When validating a Codex skill with `skill-creator/scripts/quick_validate.py`, use `/usr/local/bin/python3`, which has PyYAML installed. A missing `yaml` module in the default `python3` does not require a system-wide installation.

## Communication

- Use established industry or professional terminology. Use coined terms only when agreed with the user, and avoid inventing terms, especially hyphenated phrases.
- Explain mechanisms directly. Do not introduce an explanation by denying another interpretation unless the user raised it.
- State observed results, supporting measurements, and remaining uncertainty directly. Do not invent reader interpretations or expectations to argue against.

## Rust benchmarks

- **Workspace**: new system = new top-level crate + add it to `[workspace].members` in `Cargo.toml`.
- **Harness**: register benches via `utils::define_benchmark_harness!` (don’t write bespoke timing/output code).
- **Proving RAM measurement binary**: the `mem_binary_name` must exist; it reads `INPUT_SIZE`, runs preprocessing + proving (incl. witness), then exits 0.
- **Input sizes**: controlled by `BENCH_INPUT_PROFILE` (`reduced` for iteration, `full` for final runs).

### Quick commands

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features
BENCH_INPUT_PROFILE=reduced cargo bench -p <crate>
```

### Gotcha: excluded crates

`binius64/`, `cairo-m/`, `rookie-numbers/`, and `stark-v/` are excluded from the workspace. If you touch them, build/lint from inside each directory.

## Non-Rust benchmarks

- **Folder**: top-level `<system>/` with a required `bench_props.json`.
- **CI**: add `<system>` to `.github/workflows/sh_benchmarks_parallel.yml` (`FOLDERS`) so CI runs it.
- **Scripts per target** (example target `sha256`):
  - `sha256_prepare.sh`: uses `$UTILS_BIN` + `$INPUT_SIZE`, writes `$STATE_JSON`
  - `sha256_prove.sh`: reads `$STATE_JSON`, produces proof artifacts
  - `sha256_verify.sh`: reads `$STATE_JSON`, exits 0 on success
  - `sha256_measure.sh`: writes `$SIZES_JSON` (`proof_size`, `preprocessing_size`) and updates `circuit_sizes.json`
  - optional `sha256_prove_for_verify.sh`
- **Scripts MUST be executable**: `chmod +x <system>/*.sh`

### Quick commands

```bash
cargo build --release -p utils
BENCH_INPUT_PROFILE=reduced bash ./benchmark.sh --system-dir ./<system> --logging --quick --no-ram
```

## Output naming (don’t hardcode)

- **Rust**: the harness emits `{target}_{input}_{system}_[feature]_{metrics|mem_report}.json`
- **Non-Rust**: the orchestrator emits `{target}_{input}_{system}_metrics.json`, `{target}_{input}_{system}_mem_report.json`, and expects `circuit_sizes.json`

## Common Gotchas

- Follow existing examples (plonky2, circom, risc0, barretenberg, ligetron) for patterns
- Record circuit sizes accurately in your measure scripts
- Ensure memory binaries perform only preprocessing + proving (no verify)
- Don't break existing benchmarks while adding new ones

See `CONTRIBUTING.md` for comprehensive guidelines on adding benchmarks.

## Final Validation

Before reporting completion:

1. Run `cargo build --workspace` successfully
   - **Note**: Some crates (`binius64`, `cairo-m`, `rookie-numbers`, `stark-v`) are excluded from the workspace. Build them separately:
     ```bash
     cd binius64 && cargo build && cd ..
     cd cairo-m && cargo build && cd ..
     cd rookie-numbers && cargo build && cd ..
     cd stark-v && cargo build && cd ..
     ```
2. Run `cargo clippy --workspace --all-targets --all-features` with no errors
   - For excluded crates: `cd binius64 && cargo clippy --all-targets --all-features && cd ..` (and same for `cairo-m`, `rookie-numbers`, and `stark-v`)
3. Run `cargo fmt --all -- --check`
4. Test benchmark with `BENCH_INPUT_PROFILE=reduced`
