# Flock benchmarks

The SHA-256 and BLAKE3 benchmarks use the [Client-Side Proving Flock fork at revision fd83f87b](https://github.com/Client-Side-Proving/flock/tree/fd83f87b2a02878352ffa19023c36c108cbb97f2). Both reuse upstream compression circuits. Repository wrappers assemble the SHA-256 padding and compression chain, and BLAKE3 chunks and parent compression.

Proofs use Flock's circuit wiring argument and Ligerito PCS with the `Fast` profile. The benchmark records the upstream profile's 128-bit security target and `is_zk: false`. ARM64 uses the upstream AG zerocheck; other architectures use its RS implementation. Proving includes witness generation; verification uses the complete circuit verifier.

The [Cargo configuration](.cargo/config.toml) enables native CPU instructions, ThinLTO and one codegen unit. Flock chooses thread counts from the host's core topology.

`preprocessing_size` measures the serialized public setup: sparse R1CS matrices, IO schemas, gate counts, fixed constants, circuit wiring, statement digests and PCS parameters. `num_constraints` counts the Boolean R1CS rows for the actual compressions. Unused capacity is filled with zeros to fit the supported PCS configurations.

Run both targets with reduced inputs from the repository root:

```bash
cd flock
BENCH_INPUT_PROFILE=reduced cargo bench --bench sha256 --bench blake3
```
