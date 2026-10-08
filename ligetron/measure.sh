#!/usr/bin/env bash
set -euo pipefail

# Required env vars:
# - STATE_JSON: path to JSON arguments for proving
# - SIZES_JSON: output JSON path (defaults to <dir>/${TARGET}_<INPUT_SIZE>_sizes.json when run via benchmark.sh)

: "${STATE_JSON:?STATE_JSON is required}"
: "${SIZES_JSON:?SIZES_JSON is required}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT_JSON="$SIZES_JSON"
BASENAME="$(basename "$SIZES_JSON")"
TARGET_NAME="${BASENAME%%_[0-9]*}"

# Generate a fresh proof and capture its constraint counts in the same run.
if ! DUMMY_OUTPUT="$("$SCRIPT_DIR/prove.sh" 2>&1)"; then
  printf '%s\n' "$DUMMY_OUTPUT" >&2
  exit 1
fi

# In Ligetron, the prover writes a proof file named proof_data.gz in the current working directory.
proof_path="${PWD}/proof_data.gz"

if [[ ! -f "$proof_path" ]]; then
  echo "proof_data.gz not found for Ligero size measurement" >&2
  exit 1
fi

proof_size_bytes=$(stat -f %z "$proof_path" 2>/dev/null || stat -c %s "$proof_path")

# Preprocessing artifacts: WASM used by the prover (prefer path from STATE_JSON)
WASM_PATH=$(jq -r '.program // empty' "$STATE_JSON")
WASM_PATH="${WASM_PATH:-${SCRIPT_DIR}/ligero-prover/sdk/cpp/build/examples/${TARGET_NAME}.wasm}"
wasm_size=$(stat -f %z "$WASM_PATH" 2>/dev/null || stat -c %s "$WASM_PATH")
preprocessing_size_bytes=$(( wasm_size ))

json_output=$(jq -n \
  --argjson proof_size "$proof_size_bytes" \
  --argjson preprocessing_size "$preprocessing_size_bytes" \
  '{proof_size: $proof_size, preprocessing_size: $preprocessing_size}'
)

echo "$json_output" > "$OUT_JSON"
jq . "$OUT_JSON" || true

# === Compute and update circuit_sizes.json (Ligetron) ===
# Parse the constraint counts from the successful proving run.
PROVER_BIN="${SCRIPT_DIR}/ligero-prover/build/webgpu_prover"
if [[ -x "$PROVER_BIN" ]]; then
  # Extract first-stage linear and quadratic counts and sum them
  CONSTRAINTS_SUM=$(printf "%s\n" "$DUMMY_OUTPUT" | awk '
    /^Start Stage 1/ { in_s1=1; next }
    in_s1 && /Num Linear constraints:/ { if (match($0, /[0-9]+/)) lin=substr($0, RSTART, RLENGTH); next }
    in_s1 && /Num quadratic constraints:/ { if (match($0, /[0-9]+/)) quad=substr($0, RSTART, RLENGTH); print lin+quad; exit }
  ')

  if [[ -n "$CONSTRAINTS_SUM" ]]; then
    SIZE_LABEL=$(basename "$OUT_JSON" | sed -E "s/^${TARGET_NAME}_([^_]+)_sizes\\.json\$/\\1/")
    if [[ -n "$SIZE_LABEL" ]]; then
      CONSTRAINTS_JSON_PATH="${SCRIPT_DIR}/circuit_sizes.json"

      if [[ -f "$CONSTRAINTS_JSON_PATH" ]]; then
        UPDATED_JSON=$(jq \
          --arg target "$TARGET_NAME" \
          --arg size_key "$SIZE_LABEL" \
          --argjson size_val "$CONSTRAINTS_SUM" \
          '.[$target][$size_key] = $size_val | . // {($target): {($size_key): $size_val}}' \
          "$CONSTRAINTS_JSON_PATH")
      else
        UPDATED_JSON=$(jq -n \
          --arg target "$TARGET_NAME" \
          --arg size_key "$SIZE_LABEL" \
          --argjson size_val "$CONSTRAINTS_SUM" \
          '{($target): {($size_key): $size_val}}')
      fi

      printf "%s\n" "$UPDATED_JSON" > "$CONSTRAINTS_JSON_PATH"
    fi
  else
    echo "Ligetron Stage 1 constraint counts missing from prover output" >&2
    exit 1
  fi
else
  echo "Ligetron prover binary not found" >&2
  exit 1
fi
