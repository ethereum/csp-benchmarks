# ProveKit benchmarks

The Spartan + WHIR benchmark uses ProveKit's v1 implementation at [`c87957a0`](https://github.com/worldfnd/provekit/tree/c87957a02a2618a0932abd85726040139e49091c) and Arkworks 0.6.

## Prerequisites

Install the Noir compiler for this backend with `noirup --version 1.0.0-beta.26`. The wrapper checks the compiler version before compiling a circuit.

Set `PROVEKIT_NARGO` to the beta.26 `nargo` executable when keeping several Noir versions installed. The wrapper also accepts `NARGO_BIN`, then falls back to `nargo` on `PATH`.

## Benchmarking and validation

Run commands from the repository root:

```bash
cargo bench -p provekit
cargo test -p provekit --lib -- --test-threads=1
```

The test checks the compiled ECDSA ABI. Generated circuit artifacts and witness inputs are written beneath `provekit/circuits/target/`.

## Proof mode

The backend uses [WhirZkConfig](https://github.com/worldfnd/provekit/blob/c87957a02a2618a0932abd85726040139e49091c/provekit/r1cs-compiler/src/whir_r1cs.rs) at 128-bit security and [blinds both witness layers](https://github.com/worldfnd/provekit/blob/c87957a02a2618a0932abd85726040139e49091c/provekit/prover/src/whir_r1cs.rs).
