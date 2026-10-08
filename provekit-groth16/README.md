# ProveKit-Groth16 benchmarks

Groth16+BSB22 sibling of [`provekit/`](../provekit), pinned to [`worldfnd/ProveKit@b910fe8`](https://github.com/worldfnd/ProveKit/commit/b910fe8da2b909bb84f0c48a5078101369bfb435).

## Prerequisites

Use Noir 1.0.0-beta.19. This crate has a separate Cargo workspace because its Noir dependencies conflict with the WHIR v1 backend.

## Benchmarking

```bash
cd provekit-groth16
cargo bench --locked
```

## Trusted setup

A fresh trusted setup is sampled per `prepare` call from the OS RNG; the
toxic-waste struct is wiped via `ZeroizeOnDrop`. Suitable for benchmarking
only — production deployments need a proper MPC ceremony.
