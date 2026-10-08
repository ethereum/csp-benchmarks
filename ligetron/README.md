# Ligetron Benchmarks

These benchmarks use [Ligetron v1.7.0, revision 4b1cdef](https://github.com/ligeroinc/ligero-prover/tree/4b1cdef1bfdf4497fb3e38170db4541fba3f6c12). The P-256 ECDSA guest calls the SDK's `verify_digest` operation.

The native benchmark flow is labeled `is_zk: false`. Its [verifier](https://github.com/ligeroinc/ligero-prover/blob/4b1cdef1bfdf4497fb3e38170db4541fba3f6c12/src/webgpu_verifier.cpp) reads declared private arguments and reruns the program with them. The interpreter also converts witness values to native values for shift counts and memory addresses through [`make_numeric`](https://github.com/ligeroinc/ligero-prover/blob/4b1cdef1bfdf4497fb3e38170db4541fba3f6c12/include/zkp/nonbatch_context.hpp).

## Installation

### On OSX

From the root directory:

```bash
cd ligetron
./osx_local_setup.sh
```

With Emscripten and native dependencies installed, `./build_programs.sh` builds the three benchmark programs. Configure and build `ligero-prover` with CMake for the native prover and verifier. Native dependencies include Protocol Buffers, GMP, Boost, Dawn and WABT. Shaders are generated into `ligero-prover/build/shader`; proofs use the native Protocol Buffers serialization in `proof_data.gz`.

`UTILS_BIN=../target/debug/utils ./test_proofs.sh` checks the P-256 argument configuration and the ECDSA guest's validity and length assertions.

## Benchmarking

From the root directory:

```bash
cargo build --release -p utils
./benchmark.sh
```
