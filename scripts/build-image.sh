#!/usr/bin/env bash
# Canonical, deterministic launcher image build (spike 001, issue 012).
#
# This script IS the release recipe and the verify-it-yourself instructions:
# run it from the tagged source and the resulting manifest digest must equal
# the published release digest D. It needs docker, python3, and curl; the
# crane binary is downloaded (pinned version, checksum-verified) into
# dist/tools/. Network is used only for crates.io (content-addressed via the
# committed Cargo.lock), the pinned apk package, and the tool downloads —
# none of it is trusted: every input is pinned below, and the output digest
# is the proof.
#
# Steps:
#   1. Build launcher as a static x86_64-unknown-linux-musl binary inside a
#      digest-pinned Rust container at a fixed in-container path (/build).
#   2. Pack it as a metadata-stripped USTAR tar (scripts/make-layer-tar.py).
#   3. crane append onto an empty OCI base + crane mutate (entrypoint,
#      Confidential Space log_redirect label, platform) -> manifest digest D.
#      crane is version-pinned: it gzips the layer, so its output is a
#      digest input. The ephemeral local registry is transport only and
#      does not influence D.
#
# Outputs (in dist/):
#   image-digest.txt   D, the value pinned everywhere
#   oci-layout/        the image as an OCI layout (push with `make push`)
#   release-pins.txt   every pinned input, for the release notes
set -euo pipefail

cd "$(dirname "$0")/.."
REPO_ROOT="$PWD"
DIST="$REPO_ROOT/dist"

# ---- pinned inputs (recipe version 1) --------------------------------------
RECIPE_VERSION=1
# rust:1.88.0-alpine3.22, linux/amd64 platform image (not the multi-arch index)
RUST_IMAGE="rust@sha256:64eba3726734dcfe89e0a62a0485007a3ab7c7372ce5b38c621d8812f70215f0"
RUST_IMAGE_HUMAN="rust:1.88.0-alpine3.22 (linux/amd64)"
# ring (via rcgen) compiles C against musl headers; the exact-version pin
# fails loudly if Alpine 3.22 rolls the package, instead of silently
# changing the digest. (Alpine keeps only the latest version per branch, so
# a roll breaks rebuilds of older releases — loudly. Long-term fix: a
# committed, digest-pinned builder image with the toolchain baked in.)
MUSL_DEV_PKG="musl-dev=1.2.5-r12"
# crane gzips the layer tar -> its version is a digest input.
CRANE_VERSION="v0.21.6"
CRANE_SHA256_Linux_x86_64="7ebbdcd05b652345c1f5105f8475e518534b90d66f3bdb50017be63f426ea435"
CRANE_SHA256_Linux_arm64="6f61571ca0c2a5da27c2927fcb143255ccb2b74b8977dfcb44645b372ab0f951"
CRANE_SHA256_Darwin_x86_64="f1e653737a1d6e8a412734d0ac25009e04eccec98853be2eb59b8c744dede834"
CRANE_SHA256_Darwin_arm64="a124f297d1e63e8b6c63c2463e43565290d2fd074c1dadb5ca73d737bc7b2484"
# -----------------------------------------------------------------------------

log() { echo "==> $*" >&2; }

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

# ---- fetch the pinned crane --------------------------------------------------
fetch_crane() {
  local os arch asset want crane_bin tools="$DIST/tools"
  os="$(uname -s)" arch="$(uname -m)"
  case "$arch" in aarch64) arch=arm64 ;; esac
  asset="go-containerregistry_${os}_${arch}.tar.gz"
  want="$(eval echo "\${CRANE_SHA256_${os}_${arch}:-}")"
  [ -n "$want" ] || { echo "no pinned crane checksum for ${os}/${arch}" >&2; exit 1; }

  crane_bin="$tools/crane-$CRANE_VERSION"
  if [ ! -x "$crane_bin" ]; then
    log "downloading crane $CRANE_VERSION ($os/$arch)"
    mkdir -p "$tools"
    curl -fsSL -o "$tools/$asset" \
      "https://github.com/google/go-containerregistry/releases/download/$CRANE_VERSION/$asset"
    local got; got="$(sha256_of "$tools/$asset")"
    [ "$got" = "$want" ] || { echo "crane checksum mismatch: got $got want $want" >&2; exit 1; }
    tar -xzf "$tools/$asset" -C "$tools" crane
    mv "$tools/crane" "$crane_bin"
    rm -f "$tools/$asset"
  fi
  CRANE="$crane_bin"
}

mkdir -p "$DIST"
fetch_crane

# ---- 1. reproducible static binary ------------------------------------------
log "building static musl binary in pinned container ($RUST_IMAGE_HUMAN)"
docker run --rm --platform linux/amd64 \
  -v "$REPO_ROOT/launcher":/src:ro \
  -v "$DIST":/out \
  "$RUST_IMAGE" \
  sh -euc "
    apk add --no-cache '$MUSL_DEV_PKG' >/dev/null
    mkdir /build
    cp /src/Cargo.toml /src/Cargo.lock /build/
    cp -R /src/src /build/src
    cd /build
    # CARGO_JOBS limits build parallelism only (helps memory-constrained or
    # emulated hosts); it has no effect on the produced bytes.
    cargo build --locked --release --target x86_64-unknown-linux-musl \
      ${CARGO_JOBS:+--jobs $CARGO_JOBS}
    cp target/x86_64-unknown-linux-musl/release/launcher /out/launcher
  "
BINARY_SHA256="$(sha256_of "$DIST/launcher")"
log "binary sha256: $BINARY_SHA256"

# ---- 2. reproducible layer tar -----------------------------------------------
python3 "$REPO_ROOT/scripts/make-layer-tar.py" "$DIST/launcher" "$DIST/layer.tar"
LAYER_SHA256="$(sha256_of "$DIST/layer.tar")"
log "layer tar sha256: $LAYER_SHA256"

# ---- 3. assemble with pinned crane (ephemeral registry = transport only) -----
log "assembling image with crane $CRANE_VERSION"
REG_ID="$(docker run -d --rm -p 127.0.0.1:0:5000 registry:2)"
trap 'docker stop "$REG_ID" >/dev/null 2>&1 || true' EXIT
REG="$(docker port "$REG_ID" 5000/tcp | head -n1 | sed 's/^.*:/localhost:/')"
# wait for the registry to accept connections
for _ in $(seq 1 50); do curl -fsS "http://$REG/v2/" >/dev/null 2>&1 && break; sleep 0.2; done

"$CRANE" append --oci-empty-base -f "$DIST/layer.tar" -t "$REG/launcher:rc" >/dev/null
# Keep the Confidential Space launch-policy label: without
# tee.launch_policy.log_redirect=always the production image gives the
# container no stdout and the VM self-terminates right after launch.
"$CRANE" mutate "$REG/launcher:rc" \
  --set-platform linux/amd64 \
  --entrypoint /launcher \
  --label tee.launch_policy.log_redirect=always \
  -t "$REG/launcher:release" >/dev/null
DIGEST="$("$CRANE" digest "$REG/launcher:release")"

rm -rf "$DIST/oci-layout"
"$CRANE" pull --format=oci "$REG/launcher:release" "$DIST/oci-layout" >/dev/null

# ---- outputs ------------------------------------------------------------------
printf '%s\n' "$DIGEST" > "$DIST/image-digest.txt"
cat > "$DIST/release-pins.txt" <<EOF
recipe_version=$RECIPE_VERSION
rust_image=$RUST_IMAGE
rust_image_human=$RUST_IMAGE_HUMAN
musl_dev_pkg=$MUSL_DEV_PKG
crane_version=$CRANE_VERSION
binary_sha256=$BINARY_SHA256
layer_tar_sha256=$LAYER_SHA256
image_digest=$DIGEST
EOF

log "image digest D: $DIGEST"
log "outputs in dist/: image-digest.txt, oci-layout/, release-pins.txt"
echo "$DIGEST"
