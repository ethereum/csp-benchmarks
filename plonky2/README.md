# Plonky2 benchmarks

The SHA-256 circuit is derived from
[polymerdao/plonky2-sha256](https://github.com/polymerdao/plonky2-sha256).
The ECDSA circuit uses the pinned
[`AnInsaneJimJam/plonky2-ecdsa@0bf1a54`](https://github.com/AnInsaneJimJam/plonky2-ecdsa/commit/0bf1a54c5d97a64917861596c08fd4fc0d4366b6)
fork.

> [!NOTE]
> SHA-256 and Keccak use the pinned
> [`alxkzmn/plonky2-u32`](https://github.com/alxkzmn/plonky2-u32) revision
> `fcabb02`. Its serializers are required to measure the serialized circuit
> and prover data. The ECDSA fork aligns with Plonky2 1.1 and serializes its
> custom gates and witness generators.

## Prerequisites

Install Rust with rustup. Rustup automatically selects the repository's
canonical toolchain from [`../rust-toolchain.toml`](../rust-toolchain.toml).
The first build may need network access to fetch the pinned Git dependencies.

## Benchmarking

Run all targets with the reduced profile while iterating:

```bash
BENCH_INPUT_PROFILE=reduced cargo bench -p plonky2_circuits
```

Run one target:

```bash
BENCH_INPUT_PROFILE=reduced cargo bench -p plonky2_circuits --bench sha256
BENCH_INPUT_PROFILE=reduced cargo bench -p plonky2_circuits --bench keccak
BENCH_INPUT_PROFILE=reduced cargo bench -p plonky2_circuits --bench poseidon
BENCH_INPUT_PROFILE=reduced cargo bench -p plonky2_circuits --bench ecdsa
```

Use `BENCH_INPUT_PROFILE=full` for the complete variable-size sweep.

## Circuit details

The Poseidon benchmark uses Plonky2's built-in Poseidon operation and records
`precompile` acceleration rather than treating it as an explicit circuit.

- **secp256k1 ECDSA** — verifies the generated fixed fixture for a 32-byte
  prehash. The public inputs are ordered `digest`, `public_key_x`,
  `public_key_y`; each 32-byte value is represented by eight little-endian
  32-bit limbs. The signature values `r` and `s` are private witness inputs and
  remain fully constrained by the ECDSA gadget. The circuit enables Plonky2's
  zero-knowledge blinding, so the proof mode is marked ZK.

The ECDSA gadget uses incomplete affine addition and compares `r` directly
with the computed x-coordinate instead of reducing that coordinate modulo the
secp256k1 scalar order. Treat its result as a measurement of the deterministic
fixture, not as evidence of a complete production ECDSA verifier.

The in-tree Keccak implementation includes its upstream MIT license at
[`src/keccak256/MIT-LICENSE.txt`](src/keccak256/MIT-LICENSE.txt).
