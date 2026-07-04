#!/usr/bin/env bash
#
# fresh_clone_test.sh — "Simulated Fresh User" reproducibility test
#
# Creates a temp directory, copies the repository into it, strips all local
# environment variables, then runs the full verification suite.
# Exits with 0 only if ALL steps pass.
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# FUSE/noexec workaround: use /tmp for build artifacts
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/opencode/cargo-target}"
mkdir -p "${CARGO_TARGET_DIR}"

echo "============================================"
echo "  Axiom Protocol — Fresh Clone Test"
echo "============================================"
echo "Project root: ${PROJECT_ROOT}"
echo ""

# Step 0: Verify required tooling
echo "[STEP 0] Checking required tooling..."
for cmd in rustc cargo go make; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "FATAL: Required tool '$cmd' not found. Hidden step detected."
        exit 1
    fi
done
echo "  rustc:  $(rustc --version)"
echo "  cargo:  $(cargo --version)"
echo "  go:     $(go version)"
echo "  make:   $(make --version 2>&1 | head -1)"
echo ""

# Step 1: Create temp directory and copy project
echo "[STEP 1] Creating fresh clone environment..."
TMPDIR=$(mktemp -d)
trap 'rm -rf "${TMPDIR}"' EXIT

echo "  Temp dir: ${TMPDIR}"

# Copy the repository (excluding target, .git, and large artifacts)
mkdir -p "${TMPDIR}/repo"
cp -a "${PROJECT_ROOT}/." "${TMPDIR}/repo/"
rm -rf "${TMPDIR}/repo/target" "${TMPDIR}/repo/.git" 2>/dev/null || true

cd "${TMPDIR}/repo"
echo "  Copied repository to ${TMPDIR}/repo"
echo ""

# Step 2: Build FFI (no env vars needed)
echo "[STEP 2] Building Rust FFI (libaxiom_core_ffi)..."
env -i PATH="${PATH}" HOME="${HOME}" CARGO_TARGET_DIR="${CARGO_TARGET_DIR}" \
    cargo build --release -p axiom-core-ffi
echo "  FFI build complete."
echo ""

# Step 3: Run Rust tests
echo "[STEP 3] Running Rust test suite..."
env -i PATH="${PATH}" HOME="${HOME}" CARGO_TARGET_DIR="${CARGO_TARGET_DIR}" \
    cargo test --quiet
echo "  Rust tests PASS."
echo ""

# Step 4: Run Go FFI tests
echo "[STEP 4] Running Go FFI test suite..."
# Copy .so and headers for Go (needs them in same dir due to FUSE/noexec)
GO_TEST_DIR="${TMPDIR}/repo/crates/axiom-core-go"
cp "${CARGO_TARGET_DIR}/release/libaxiom_core_ffi.so" "${GO_TEST_DIR}/"
cp "${TMPDIR}/repo/crates/axiom-core-ffi/include/axiom_core.h" "${GO_TEST_DIR}/"
cp "${TMPDIR}/repo/test-vectors/vectors/conformance_suite.json" "${GO_TEST_DIR}/"

# Go tests must run from /tmp copy due to FUSE file locking issues
GO_TMP_DIR="/tmp/axiom-go-fresh"
mkdir -p "${GO_TMP_DIR}"
cp "${GO_TEST_DIR}"/*.go "${GO_TMP_DIR}/"
cp "${GO_TEST_DIR}/libaxiom_core_ffi.so" "${GO_TMP_DIR}/"
cp "${GO_TEST_DIR}/axiom_core.h" "${GO_TMP_DIR}/"
cp "${GO_TEST_DIR}/conformance_suite.json" "${GO_TMP_DIR}/"

export LD_LIBRARY_PATH="${GO_TMP_DIR}:${LD_LIBRARY_PATH:-}"
export CGO_LDFLAGS="-L${GO_TMP_DIR} -laxiom_core_ffi -lm -ldl"
export CGO_CFLAGS="-I${GO_TMP_DIR}"

env -i \
    PATH="${PATH}" \
    HOME="${HOME}" \
    LD_LIBRARY_PATH="${LD_LIBRARY_PATH}" \
    CGO_LDFLAGS="${CGO_LDFLAGS}" \
    CGO_CFLAGS="${CGO_CFLAGS}" \
    go test -C "${GO_TMP_DIR}" -v
echo "  Go tests PASS."
echo ""

# Step 5: Run Python CBOR conformance test
echo "[STEP 5] Running Python CBOR conformance test..."
if command -v python3 &>/dev/null; then
    python3 "${TMPDIR}/repo/scripts/differential_cbor_test.py"
    echo "  Python conformance test PASS."
else
    echo "  SKIP (python3 not available)"
fi
echo ""

# Step 6: Generate conformance vectors
echo "[STEP 6] Generating conformance vectors..."
python3 "${TMPDIR}/repo/scripts/gen_conformance.py"
echo "  Vectors generated."
echo ""

# Step 7: Build CLI
echo "[STEP 7] Building axiom-cli..."
env -i PATH="${PATH}" HOME="${HOME}" CARGO_TARGET_DIR="${CARGO_TARGET_DIR}" \
    cargo build --release -p axiom-cli
echo "  CLI build complete."
echo ""

# Step 8: Generate demo.axm
echo "[STEP 8] Generating demo.axm..."
env -i PATH="${PATH}" HOME="${HOME}" \
    "${CARGO_TARGET_DIR}/release/axiom-cli" generate demo.axm
echo "  demo.axm generated."
echo ""

# Step 9: Verify demo.axm
echo "[STEP 9] Verifying demo.axm..."
VERIFY_OUTPUT=$(env -i PATH="${PATH}" HOME="${HOME}" \
    "${CARGO_TARGET_DIR}/release/axiom-cli" verify demo.axm 2>&1)
echo "${VERIFY_OUTPUT}"

if echo "${VERIFY_OUTPUT}" | grep -q "PASS"; then
    echo ""
    echo "============================================"
    echo "  ALL VERIFICATION SUITES PASS"
    echo "  Repository is reproducible."
    echo "============================================"
    exit 0
else
    echo ""
    echo "FATAL: Hidden step detected. The repository is not reproducible."
    exit 1
fi
