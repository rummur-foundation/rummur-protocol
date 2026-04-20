#!/usr/bin/env bash
# setup-dev-env.sh — Rummur Protocol development environment setup (macOS)
#
# Run once before building libxmrmsg or starting stagenet testing.
# Safe to re-run; steps that are already done are skipped.
#
# What this does:
#   1. Installs missing Homebrew dependencies
#   2. Clones the Monero source at the pinned version
#   3. Vendors the required crypto files into third_party/monero-crypto/
#   4. Starts a local monerod on stagenet (detached)
#   5. Creates a stagenet test wallet
#
# Usage:
#   chmod +x scripts/setup-dev-env.sh
#   ./scripts/setup-dev-env.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MONERO_VERSION="v0.18.3.4"          # update to latest stable v0.18.x
MONERO_DIR="$HOME/.rummur-dev/monero-source"
VENDOR_DIR="$REPO_ROOT/third_party/monero-crypto"
STAGENET_DIR="$HOME/.rummur-dev/stagenet"

echo "==> Rummur dev environment setup"
echo "    Repo:        $REPO_ROOT"
echo "    Monero src:  $MONERO_DIR ($MONERO_VERSION)"
echo "    Stagenet:    $STAGENET_DIR"
echo ""

# ── 1. Homebrew dependencies ────────────────────────────────────────────────

echo "==> Installing Homebrew dependencies..."
BREW_DEPS=(openssl pkg-config ninja ccache)
for dep in "${BREW_DEPS[@]}"; do
    if brew list --formula "$dep" &>/dev/null; then
        echo "    [ok] $dep"
    else
        echo "    [installing] $dep"
        brew install "$dep"
    fi
done
# boost and cmake are checked separately (already present per project setup)
for dep in boost cmake; do
    brew list --formula "$dep" &>/dev/null \
        && echo "    [ok] $dep" \
        || { echo "ERROR: $dep not found — run: brew install $dep"; exit 1; }
done

# ── 2. Clone Monero source ───────────────────────────────────────────────────

if [[ -d "$MONERO_DIR/.git" ]]; then
    echo "==> Monero source already present at $MONERO_DIR"
    CURRENT_TAG=$(git -C "$MONERO_DIR" describe --tags --exact-match 2>/dev/null || echo "(detached)")
    echo "    Current: $CURRENT_TAG"
    if [[ "$CURRENT_TAG" != "$MONERO_VERSION" ]]; then
        echo "    WARNING: expected $MONERO_VERSION — run: git -C $MONERO_DIR checkout $MONERO_VERSION"
    fi
else
    echo "==> Cloning Monero at $MONERO_VERSION (shallow)..."
    mkdir -p "$(dirname "$MONERO_DIR")"
    git clone --branch "$MONERO_VERSION" --depth 1 \
        https://github.com/monero-project/monero.git \
        "$MONERO_DIR"
    git -C "$MONERO_DIR" submodule update --init --depth 1
fi

MONERO_COMMIT=$(git -C "$MONERO_DIR" rev-parse HEAD)
echo "    Commit: $MONERO_COMMIT"

# ── 3. Vendor crypto files ───────────────────────────────────────────────────

echo "==> Vendoring Monero crypto files into third_party/monero-crypto/..."

# Only the pure-C, platform-independent primitives are vendored.
# Monero's crypto.cpp (Boost-dependent) and base58.cpp (Linux-only headers)
# are NOT vendored — libxmrmsg provides portable replacements in src/.
VENDOR_FILES=(
    "src/crypto/crypto-ops.h"
    "src/crypto/crypto-ops.c"
    "src/crypto/crypto-ops-data.c"
    "src/crypto/keccak.h"
    "src/crypto/keccak.c"
    "contrib/epee/include/memwipe.h"   # lives in epee, not src/crypto
    "contrib/epee/src/memwipe.c"       # lives in epee, not src/crypto
)

MISSING=0
for f in "${VENDOR_FILES[@]}"; do
    SRC="$MONERO_DIR/$f"
    DEST="$VENDOR_DIR/$(basename "$f")"
    if [[ ! -f "$SRC" ]]; then
        echo "    MISSING in Monero source: $f"
        MISSING=$((MISSING + 1))
        continue
    fi
    cp "$SRC" "$DEST"
    echo "    [copied] $(basename "$f")"
done

if [[ $MISSING -gt 0 ]]; then
    echo "ERROR: $MISSING files not found in Monero source tree."
    echo "       The Monero source structure may have changed in $MONERO_VERSION."
    echo "       Update VENDOR_FILES in this script and VENDOR.md accordingly."
    exit 1
fi

echo "$MONERO_COMMIT" > "$VENDOR_DIR/VENDOR_COMMIT"
echo "    Recorded commit hash → third_party/monero-crypto/VENDOR_COMMIT"

# ── 4. Start stagenet monerod ────────────────────────────────────────────────

echo ""
echo "==> Stagenet monerod setup"

# Build Monero binaries if not already present
MONEROD="$MONERO_DIR/build/release/bin/monerod"
if [[ ! -f "$MONEROD" ]]; then
    echo "    Building monerod (this takes 20-40 minutes)..."
    cd "$MONERO_DIR"
    mkdir -p build/release && cd build/release
    cmake -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_TESTS=OFF \
        -DBUILD_GUI_DEPS=OFF \
        ../..
    ninja monerod monero-wallet-cli
    cd "$REPO_ROOT"
    echo "    Build complete."
else
    echo "    monerod binary already present."
fi

mkdir -p "$STAGENET_DIR"

# Check if monerod is already running
if pgrep -f "monerod.*stagenet" > /dev/null 2>&1; then
    echo "    stagenet monerod already running."
else
    echo "    Starting stagenet monerod (detached, RPC on port 38081)..."
    "$MONEROD" \
        --stagenet \
        --detach \
        --data-dir "$STAGENET_DIR/node" \
        --log-file "$STAGENET_DIR/monerod.log" \
        --rpc-bind-port 38081 \
        --no-igd \
        --hide-my-port \
        --p2p-external-port 0
    echo "    monerod started. Log: $STAGENET_DIR/monerod.log"
    echo "    Sync will take several minutes on first run."
fi

# ── 5. Test wallet ───────────────────────────────────────────────────────────

WALLET_CLI="$MONERO_DIR/build/release/bin/monero-wallet-cli"
WALLET_PATH="$STAGENET_DIR/test-wallet"

echo ""
echo "==> Test wallet"
if [[ -f "${WALLET_PATH}.keys" ]]; then
    echo "    Wallet already exists at $WALLET_PATH"
    echo "    To open: $WALLET_CLI --stagenet --wallet-file $WALLET_PATH --daemon-address 127.0.0.1:38081"
else
    echo ""
    echo "    No test wallet found. To create one, run:"
    echo ""
    echo "    $WALLET_CLI \\"
    echo "      --stagenet \\"
    echo "      --generate-new-wallet $WALLET_PATH \\"
    echo "      --daemon-address 127.0.0.1:38081 \\"
    echo "      --password \"\" \\"
    echo "      --mnemonic-language English"
    echo ""
    echo "    For stagenet XMR, use the stagenet faucet at:"
    echo "    https://community.getmonero.org/faucet/stagenet/"
    echo ""
    echo "    Or mine blocks locally (fast on stagenet with --offline):"
    echo "    In the wallet CLI: start_mining 1"
fi

# ── Done ─────────────────────────────────────────────────────────────────────

echo ""
echo "==> Setup complete."
echo ""
echo "    Next steps:"
echo "    1. Wait for stagenet sync  — tail -f $STAGENET_DIR/monerod.log"
echo "    2. Create test wallet      — see wallet instructions above"
echo "    3. Vendor files are ready  — cd $REPO_ROOT && cmake -B build && cmake --build build"
echo ""
echo "    Useful commands:"
echo "    Stop monerod:   pkill -f 'monerod.*stagenet'"
echo "    Check sync:     $MONEROD --stagenet print_height  # (if running)"
