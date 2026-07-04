#!/usr/bin/env bash
#
# check_ffi_abi.sh — Verify C FFI exported symbols match header declarations
#
# Usage: bash scripts/check_ffi_abi.sh [path-to-libaxiom_core_ffi.so]
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
HEADER="${PROJECT_ROOT}/crates/axiom-core-ffi/include/axiom_core.h"

if [ $# -ge 1 ]; then
    SO_FILE="$1"
else
    SO_FILE="${CARGO_TARGET_DIR:-${PROJECT_ROOT}/target/release}/libaxiom_core_ffi.so"
fi

if [ ! -f "$SO_FILE" ]; then
    echo "FATAL: shared library not found at $SO_FILE"
    echo "Build first: cargo build --release -p axiom-core-ffi"
    exit 1
fi

if [ ! -f "$HEADER" ]; then
    echo "FATAL: header not found at $HEADER"
    exit 1
fi

echo "=== Axiom Protocol — C FFI ABI Check ==="
echo "Shared lib: $(ls -lh "$SO_FILE" | awk '{print $5}') $SO_FILE"
echo "Header:     $HEADER"
echo ""

# Extract exported axiom_* symbols from .so
nm -D --defined-only "$SO_FILE" \
    | grep -oP 'axiom_\w+' \
    | sort -u > /tmp/exported_symbols.txt

echo "Exported symbols ($(wc -l < /tmp/exported_symbols.txt)):"
cat /tmp/exported_symbols.txt
echo ""

# Extract function names from header
grep -oP '(^int |^const char\* |^void )axiom_\w+' "$HEADER" \
    | grep -oP 'axiom_\w+' \
    | sort -u > /tmp/header_symbols.txt

echo "Header-declared symbols ($(wc -l < /tmp/header_symbols.txt)):"
cat /tmp/header_symbols.txt
echo ""

# Check all header symbols are exported
MISSING=0
while IFS= read -r sym; do
    if ! grep -q "^${sym}$" /tmp/exported_symbols.txt; then
        echo "  MISSING: $sym declared in header but NOT exported"
        MISSING=1
    fi
done < /tmp/header_symbols.txt

if [ "$MISSING" -eq 1 ]; then
    echo ""
    echo "FAIL: ABI mismatch — see above"
    exit 1
fi

# Check all exported symbols are in header (extra symbols are fine but warn)
EXTRA=0
while IFS= read -r sym; do
    if ! grep -q "^${sym}$" /tmp/header_symbols.txt; then
        echo "  EXTRA: $sym exported but NOT in header (non-public internal symbol)"
        EXTRA=1
    fi
done < /tmp/exported_symbols.txt

echo ""
echo "✅ ALL header symbols match exported symbols — ABI OK"
[ "$EXTRA" -eq 1 ] && echo "  (some non-public symbols also exported — expected for internal helpers)"
exit 0
