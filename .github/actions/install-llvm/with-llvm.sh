#!/usr/bin/env bash
set -euo pipefail

llvm_prefix="$(brew --prefix llvm)"
sdkroot="$(xcrun --sdk macosx --show-sdk-path)"
export CC="$llvm_prefix/bin/clang"
export CXX="$llvm_prefix/bin/clang++"
export AR="$llvm_prefix/bin/llvm-ar"
export RANLIB="$llvm_prefix/bin/llvm-ranlib"
export SDKROOT="$sdkroot"

exec "$@"
