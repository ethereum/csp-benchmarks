#!/usr/bin/env bash
set -euo pipefail

# ================================
# Noir macOS end-to-end setup
# ================================
# - Installs Nargo
# - Installs Barretenberg(bbup)
# - Runs benchmarks
#

### Helpers
step() { printf "\n\033[1;34m==> %s\033[0m\n" "$*"; }
ok()   { printf "\033[1;32m✓ %s\033[0m\n" "$*"; }

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "This script is for macOS (Darwin) only."; exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# -----------------------
# Install Nargo
# -----------------------

export PATH="$HOME/.nargo/bin:$PATH"
if command -v noirup >/dev/null 2>&1; then
    echo "Nargo is already installed."
else
    step "Installing Nargo"
    curl -fL https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash
fi

step "Installing Noir v1.0.0-beta.25"
noirup --version 1.0.0-beta.25

# -----------------------
# Install Barretenberg(bbup)
# -----------------------

step "Installing Barretenberg"
export PATH="$HOME/.bb:$PATH"
if command -v bbup >/dev/null 2>&1; then
    echo "Barretenberg is already installed."
else
    curl -fL https://raw.githubusercontent.com/AztecProtocol/aztec-packages/refs/heads/next/barretenberg/bbup/install | bash
fi

step "Installing Barretenberg v5.2.1"
bbup -v 5.2.1

# -----------------------
# Run benchmarks
# -----------------------
cd "$SCRIPT_DIR"
cargo bench

ok "All done!"
