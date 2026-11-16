#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
exec "$SCRIPT_DIR/gnark-bench" measure "$SCRIPT_DIR/circuit_sizes.json"
