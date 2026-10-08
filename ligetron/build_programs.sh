#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SDK_DIR="${SCRIPT_DIR}/ligero-prover/sdk/cpp"
BUILD_DIR="${SDK_DIR}/build"
BUILD_JOBS="${BUILD_JOBS:-2}"

emcmake cmake -S "$SDK_DIR" -B "$BUILD_DIR"
cmake --build "$BUILD_DIR" --target sha256 poseidon2 --parallel "$BUILD_JOBS"
em++ -O2 -std=c++20 -sSTACK_SIZE=100000000 -sERROR_ON_UNDEFINED_SYMBOLS=0 \
  -I "${SDK_DIR}/include" "${SCRIPT_DIR}/programs/ecdsa_p256_verify_digest.cpp" \
  "${BUILD_DIR}/libligetron.a" \
  -o "${BUILD_DIR}/examples/ecdsa_p256_verify_digest.wasm"
