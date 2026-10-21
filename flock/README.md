# Flock benchmarks

The SHA-256 and BLAKE3 benchmarks use [Flock revision b684b125](https://github.com/succinctlabs/flock/tree/b684b1258e4b1f202bec24afd660ace851b09e5e). Both reuse upstream compression circuits. Repository wrappers assemble the SHA-256 padding and compression chain, and BLAKE3 chunks and parent compression.

Flock builds in a separate Cargo workspace because ProveKit's `blake3/traits-preview` feature breaks compilation of Flock's transcript crate. Its Cargo configuration writes binaries and Criterion reports to the repository's shared target directory.

Proofs use Flock's circuit wiring argument and Ligerito PCS with the `Fast` profile. The benchmark records the upstream profile's 128-bit security target and `is_zk: false`. ARM64 uses the upstream AG zerocheck; other architectures use its RS implementation. Proving includes witness generation; verification uses the complete circuit verifier.

Release builds use ThinLTO and one codegen unit; the benchmark profile inherits these settings, so timing and memory measurements use the same compiler configuration. Builds enable native CPU instructions, and Flock chooses thread counts from the host's core topology.

`preprocessing_size` measures the serialized public setup: sparse R1CS matrices, IO schemas, gate counts, fixed constants, circuit wiring, statement digests and PCS parameters. `num_constraints` counts the Boolean R1CS rows for the actual compressions. Unused capacity is filled with zeros to fit the supported PCS configurations.

Run both targets with the reduced input profile:

```bash
cd flock
BENCH_INPUT_PROFILE=reduced cargo bench
```
