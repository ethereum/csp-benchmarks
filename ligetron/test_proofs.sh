#!/usr/bin/env bash
set -euo pipefail

: "${UTILS_BIN:?UTILS_BIN is required}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
UTILS_BIN="$(cd "$(dirname "$UTILS_BIN")" && pwd)/$(basename "$UTILS_BIN")"
export UTILS_BIN
TEST_DIR="$(mktemp -d)"
trap 'rm -rf "$TEST_DIR"' EXIT
cd "$TEST_DIR"

expect_failure() {
  if { "$@" > negative.log 2>&1; } 2>> negative.log; then
    echo "Expected failure: $*" >&2
    exit 1
  fi
}

export INPUT_SIZE=32
export STATE_JSON="${TEST_DIR}/ecdsa.json"
bash "${SCRIPT_DIR}/ecdsa_prepare.sh"
jq -e '."private-indices" == [2] and (.args | length) == 3' "$STATE_JSON" > /dev/null
if ! bash "${SCRIPT_DIR}/prove.sh" > ecdsa_prove.log 2>&1; then
  cat ecdsa_prove.log >&2
  exit 1
fi

# Check the guest's validity and signature-length assertions.
jq '.args[1].hex = ("0x" + ("00" * 64))' "$STATE_JSON" > wrong_signature.json
jq '.args[1].hex = "0x00"' "$STATE_JSON" > short_signature.json
STATE_JSON="${TEST_DIR}/wrong_signature.json" expect_failure bash "${SCRIPT_DIR}/prove.sh"
STATE_JSON="${TEST_DIR}/short_signature.json" expect_failure bash "${SCRIPT_DIR}/prove.sh"
printf 'ecdsa: benchmark arguments and guest assertions passed\n'
