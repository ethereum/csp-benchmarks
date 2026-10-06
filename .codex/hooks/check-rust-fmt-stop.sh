#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel 2>/dev/null || true)"
if [[ -z "$repo_root" || ! -f "$repo_root/.codex/hooks.json" ]]; then
  exit 0
fi

cd "$repo_root"

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

{
  echo "cargo fmt --all -- --check"
  cargo fmt --all -- --check

  for crate in cairo-m rookie-numbers stark-v; do
    if [[ -d "$crate" ]]; then
      echo
      echo "(cd $crate && cargo fmt --all -- --check)"
      (cd "$crate" && cargo fmt --all -- --check)
    fi
  done
} >"$tmp" 2>&1 || {
  python3 - "$tmp" <<'PY'
import json
import pathlib
import sys

output = pathlib.Path(sys.argv[1]).read_text(errors="replace").strip()
if len(output) > 12000:
    output = output[-12000:]

reason = (
    "Rust formatting failed in csp-benchmarks. "
    "Run the failing cargo fmt command(s), inspect the diff, and do not stop until fmt passes.\n\n"
    + output
)

print(json.dumps({"decision": "block", "reason": reason}))
PY
  exit 0
}

printf '{"continue":true}\n'
