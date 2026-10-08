#!/usr/bin/env bash
set -euo pipefail

# Generic benchmark orchestrator for non-Rust systems.
# Usage: benchmark.sh --system-dir <path> [--targets "sha256,poseidon,..."]

SYSTEM_DIR=""
TARGETS=("sha256" "blake3" "ecdsa" "keccak" "poseidon" "poseidon2")

while [[ $# -gt 0 ]]; do
  case "$1" in
    --system-dir)
      SYSTEM_DIR="$2"; shift 2 ;;
    --targets)
      IFS=',' read -r -a TARGETS <<< "$2"; shift 2 ;;
    --logging)
      LOGGING_RUN=true; shift ;;
    --quick)
      QUICK_RUN=true; shift ;;
    --no-ram)
      NO_RAM=true; shift ;;
    *)
      echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [[ -z "${QUICK_RUN:-}" ]]; then
  RUNS=10
else
  RUNS=1
fi

if [[ -z "${SYSTEM_DIR:-}" ]]; then
  echo "--system-dir is required (path containing prepare.sh, prove.sh, verify.sh)" >&2
  exit 2
fi

if [[ ! -d "$SYSTEM_DIR" ]]; then
  echo "system dir does not exist: $SYSTEM_DIR" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HYPERFINE_VERSION="$(cat "$SCRIPT_DIR/.hyperfine-version")"
HYPERFINE_ACTUAL="$(hyperfine --version 2>/dev/null || true)"
if [[ "$HYPERFINE_ACTUAL" != "hyperfine $HYPERFINE_VERSION" ]]; then
  echo "Hyperfine $HYPERFINE_VERSION is required (found ${HYPERFINE_ACTUAL:-not installed}); see README.MD for setup." >&2
  exit 1
fi

UTILS_BIN="${SCRIPT_DIR}/target/release/utils"
MEASURE_RAM_SCRIPT="${SCRIPT_DIR}/measure_mem_avg.sh"
BENCH_PROPS_JSON="${SYSTEM_DIR}/bench_props.json"
BENCH_FLAGS_JSON="${SYSTEM_DIR}/bench_flags.json"
NUM_CONSTRAINTS="${SYSTEM_DIR}/circuit_sizes.json"

if [[ ! -f "$BENCH_PROPS_JSON" ]]; then
  echo "bench_props.json not found: $BENCH_PROPS_JSON" >&2
  exit 1
fi

step() { printf "\n\033[1;34m==> %s\033[0m\n" "$*"; }
ok()   { printf "\033[1;32m✓ %s\033[0m\n" "$*"; }
warn() { printf "\033[1;33m! %s\033[0m\n" "$*"; }

resolve_script() {
  local name="$1" target="$2" dir="$3"
  local specific="${dir}/${target}_${name}.sh" generic="${dir}/${name}.sh"
  if [[ -x "$specific" ]]; then echo "$specific"
  elif [[ -x "$generic" ]]; then echo "$generic"
  fi
}

if [[ ! -x "$UTILS_BIN" ]]; then
  echo "utils binary not found or not executable: $UTILS_BIN" >&2
  exit 1
fi

step "Running benchmarks for system: $SYSTEM_DIR"

STATE_DIR="$SYSTEM_DIR/.bench_state"
mkdir -p "$STATE_DIR"

for target in "${TARGETS[@]}"; do
  TARGET="$target"

  sizes_len="$($UTILS_BIN sizes len --target "$TARGET")"
  [[ -n "$sizes_len" ]] || { echo "Failed to obtain sizes length from utils" >&2; exit 1; }

  PREPARE_SH="${SYSTEM_DIR}/${TARGET}_prepare.sh"
  PROVE_SH="$(resolve_script prove "$TARGET" "$SYSTEM_DIR")"
  VERIFY_SH="$(resolve_script verify "$TARGET" "$SYSTEM_DIR")"
  MEASURE_SH="$(resolve_script measure "$TARGET" "$SYSTEM_DIR")"
  PREPARE_VERIFY_SH="$(resolve_script prepare_verify "$TARGET" "$SYSTEM_DIR")"

  if [[ ! -x "$PREPARE_SH" ]]; then
    warn "Skipping target $TARGET: prepare script not found/executable"
    continue
  fi

  for (( i=0; i<sizes_len; i++ )); do
    INPUT_SIZE="$($UTILS_BIN sizes get --target "$TARGET" --index "$i")"

    PROVER_JSON_FILE="$STATE_DIR/prover_${TARGET}_${INPUT_SIZE}.json"
    VERIFIER_JSON_FILE="$STATE_DIR/verifier_${TARGET}_${INPUT_SIZE}.json"

    step "[$TARGET] Size measurement (size ${INPUT_SIZE})"
    SIZES_JSON="$SYSTEM_DIR/${TARGET}_${INPUT_SIZE}_sizes.json"
    if SIZES_JSON="$SIZES_JSON" UTILS_BIN="$UTILS_BIN" INPUT_SIZE="$INPUT_SIZE" STATE_JSON="$PROVER_JSON_FILE" bash "$PREPARE_SH"; then
      :
    else
      PREPARE_STATUS=$?
      if (( PREPARE_STATUS == 77 )); then
        warn "Skipping target $TARGET at size $INPUT_SIZE: unsupported by system"
        continue
      fi
      exit "$PREPARE_STATUS"
    fi
    SIZES_JSON="$SIZES_JSON" STATE_JSON="$PROVER_JSON_FILE" bash "$MEASURE_SH" || warn "Size measurement failed"
    ok "Sizes report: $SIZES_JSON"

    step "[$TARGET] Prover (size ${INPUT_SIZE}):"
    if [[ -z "${LOGGING_RUN:-}" ]]; then
    SHOW_OUTPUT=""
    else
    SHOW_OUTPUT="--show-output"
    fi

    hyperfine $SHOW_OUTPUT --runs "$RUNS" \
      --prepare "UTILS_BIN=$UTILS_BIN INPUT_SIZE=$INPUT_SIZE STATE_JSON=$PROVER_JSON_FILE bash $PREPARE_SH" \
      "STATE_JSON=$PROVER_JSON_FILE bash $PROVE_SH" \
      --export-json "$SYSTEM_DIR/hyperfine_${TARGET}_${INPUT_SIZE}_prover_metrics.json"

    step "[$TARGET] Verifier (size ${INPUT_SIZE}):"
    if [[ -n "$PREPARE_VERIFY_SH" ]]; then
      VERIFY_PREP_CMD="STATE_JSON=$VERIFIER_JSON_FILE bash $PREPARE_VERIFY_SH"
    else
      VERIFY_PREP_CMD="STATE_JSON=$VERIFIER_JSON_FILE bash $PROVE_SH"
    fi
    hyperfine --runs "$RUNS" \
      --prepare "UTILS_BIN=$UTILS_BIN INPUT_SIZE=$INPUT_SIZE STATE_JSON=$VERIFIER_JSON_FILE bash $PREPARE_SH && $VERIFY_PREP_CMD > /dev/null 2>&1" \
      "STATE_JSON=$VERIFIER_JSON_FILE bash $VERIFY_SH" \
      --export-json "$SYSTEM_DIR/hyperfine_${TARGET}_${INPUT_SIZE}_verifier_metrics.json"

    if [[ -z "${NO_RAM:-}" ]]; then
      step "[$TARGET] RAM measurement (size ${INPUT_SIZE})"
      MEM_JSON="$SYSTEM_DIR/${TARGET}_${INPUT_SIZE}_mem_report.json"
      bash "$MEASURE_RAM_SCRIPT" -o "$MEM_JSON" -- bash -lc "STATE_JSON=\"$PROVER_JSON_FILE\" bash \"$PROVE_SH\"" || warn "Memory measurement failed"
      ok "Memory report: $MEM_JSON"
    fi
  done
done

step "Benchmark complete"
step "Post-processing hyperfine outputs into Metrics JSONs"

FORMATTER_BIN="${SCRIPT_DIR}/target/release/format_hyperfine"
if [[ ! -x "$FORMATTER_BIN" ]]; then
  step "Building format_hyperfine binary"
  (cd "$SCRIPT_DIR" && cargo build --release -p utils --bin format_hyperfine >/dev/null 2>&1) || warn "Failed to build format_hyperfine"
fi

if [[ ! -f "$NUM_CONSTRAINTS" ]]; then
  echo "circuit_sizes.json not found: $NUM_CONSTRAINTS" >&2
  exit 1
fi

if [[ -x "$FORMATTER_BIN" ]]; then
  step "Formatting hyperfine outputs into Metrics JSON"
  FORMATTER_ARGS=(--system-dir "$SYSTEM_DIR" --properties "$BENCH_PROPS_JSON" --num-constraints-file "$NUM_CONSTRAINTS")
  if [[ -f "$BENCH_FLAGS_JSON" ]]; then
    FORMATTER_ARGS+=(--flags "$BENCH_FLAGS_JSON")
  fi
  "$FORMATTER_BIN" "${FORMATTER_ARGS[@]}" || {
    echo "format_hyperfine failed" >&2
    exit 1
  }
else
  warn "format_hyperfine binary not found; skipping formatting"
fi

ok "Benchmark complete"
