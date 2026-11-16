#!/usr/bin/env bash
set -euo pipefail
: "${UTILS_BIN:?UTILS_BIN is required}"
: "${INPUT_SIZE:?INPUT_SIZE is required}"
: "${STATE_JSON:?STATE_JSON is required}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGET="${1:?target is required}"
case "$TARGET" in
  ecdsa) "$UTILS_BIN" ecdsa ;;
  poseidon2) "$UTILS_BIN" poseidon --size "$INPUT_SIZE" ;;
  sha256|keccak) "$UTILS_BIN" "$TARGET" --size "$INPUT_SIZE" ;;
  *) echo "Unsupported target: $TARGET" >&2; exit 2 ;;
esac | "$SCRIPT_DIR/gnark-bench" prepare "$TARGET"
