#!/usr/bin/env bash
set -euo pipefail

# Required env vars:
# - STATE_JSON: path to JSON arguments containing:
#   - workspace-root-path: path to the workspace
#   - circuit-path: path to the compiled circuit
#   - toml-path: path to the prover TOML file
#   - benchmark-name
#   - input-size (optional)

: "${STATE_JSON:?STATE_JSON is required}"

# One `jq` for all five fields: this script is the timed region, so each
# subprocess it spawns is charged to the proving time. `input-size` falls back
# to the empty string rather than `empty` so that the field always occupies a
# line and the reads stay aligned.
{
  read -r WORKSPACE_ROOT_PATH
  read -r CIRCUIT_PATH
  read -r TOML_PATH
  read -r BENCHMARK_NAME
  read -r INPUT_SIZE
} < <(jq -r '."workspace-root-path", ."circuit-path", ."toml-path",
             ."benchmark-name", (."input-size" // "")' "$STATE_JSON")

cd "$WORKSPACE_ROOT_PATH"

# Determine witness file name
if [[ -n "$INPUT_SIZE" ]]; then
  WITNESS_FILE="${BENCHMARK_NAME}_${INPUT_SIZE}.gz"
else
  WITNESS_FILE="${BENCHMARK_NAME}.gz"
fi

# Extract prover name from TOML path (filename without .toml extension)
PROVER_NAME="$(basename "$TOML_PATH" .toml)"

# Step 1: Witness generation
nargo execute --prover-name "$PROVER_NAME" --package "$BENCHMARK_NAME" "$WITNESS_FILE"

# Step 2: bb prove (set WRITE_VK=1 to also write verification key)
bb prove -b "$CIRCUIT_PATH" -w "$WORKSPACE_ROOT_PATH/target/$WITNESS_FILE" ${WRITE_VK:+--write_vk} -o "$WORKSPACE_ROOT_PATH/target/"

cd ../..
