# Vega SHA-256 benchmark

This benchmark uses Microsoft's [`VegaZkSNARK` at revision c0ee259](https://github.com/microsoft/vega-prover/blob/c0ee259053cd12eaf43ed71b5cde375452b3ee4d/src/vega_sc_zkp.rs) with `T256HyraxEngine` and Hyrax commitments.

## Proof and circuit

The circuit uses Bellpepper's SHA-256 gadget. Digest bits are allocated in `synthesize`, after Vega resets the public assignments.

## Measurement boundaries

Proving includes a fresh `prep_prove` for each invocation, followed by `prove`. Reported constraint counts are padded; key and proof sizes use Bincode serialization.

## Running

```bash
cd vega

BENCH_INPUT_PROFILE=reduced cargo bench --locked -p vega-bench --bench sha256
cargo test --locked -p vega-bench --lib
```

Unit tests cover the Vega phase allocation and the wrapper's digest comparison.
