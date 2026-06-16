#!/usr/bin/env bash
# Build and sign the wasm harness (issue #8).
#
# Compiles harness/ to wasm32-unknown-unknown, copies the module to the
# launcher test/dev fixture, and signs it with the demo company key. CI runs
# this before `cargo test` so the committed fixture can never drift from the
# harness source (a stale fixture fails the build, not a test in production).
#
# Usage: scripts/build-harness.sh
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

fixture_dir="launcher/tests/fixtures/harness"
wasm_out="$fixture_dir/harness.wasm"

echo "[1/3] cargo build --target wasm32-unknown-unknown --release"
rustup target add wasm32-unknown-unknown >/dev/null 2>&1 || true
cargo build --manifest-path harness/Cargo.toml \
    --target wasm32-unknown-unknown --release

echo "[2/3] copy module -> $wasm_out"
mkdir -p "$fixture_dir"
cp harness/target/wasm32-unknown-unknown/release/harness.wasm "$wasm_out"

echo "[3/3] sign with the demo company key"
scripts/sign-harness.py "$wasm_out"

echo "done: $wasm_out (+ .sig)"
