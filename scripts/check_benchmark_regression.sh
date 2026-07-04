#!/usr/bin/env bash
#
# check_benchmark_regression.sh — Benchmark regression guard
#
# Runs `axiom benchmark` and compares metrics against stored baseline.
# Fails if any metric exceeds baseline * threshold.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASELINE="${SCRIPT_DIR}/benchmark_baseline.json"

CLI="${1:-${CARGO_TARGET_DIR:-target/release}/axiom}"

if [ ! -f "$CLI" ]; then echo "FATAL: CLI not found at $CLI"; exit 1; fi
if [ ! -f "$BASELINE" ]; then echo "FATAL: baseline not found at $BASELINE"; exit 1; fi

echo "=== Axiom Protocol — Benchmark Regression Check ==="

OUTPUT=$("$CLI" benchmark 2>&1)
echo "$OUTPUT"

# Parse lines like: "  ✓ BLAKE3 Hash  0.5 µs/op"
THRESHOLD=$(python3 -c "import json; print(json.load(open('$BASELINE'))['threshold_multiplier'])")
FAILED=0

while IFS= read -r line; do
    line=$(echo "$line" | sed 's/^[[:space:]]*[✓✗]//' | xargs)
    [ -z "$line" ] && continue
    [[ "$line" != *"µs/op"* ]] && continue
    label=$(echo "$line" | sed 's/\(.*\)[[:space:]]*[0-9.]*[[:space:]]*µs\/op/\1/' | xargs)
    value=$(echo "$line" | grep -oP '[\d.]+(?=\s*µs/op)' || true)
    [ -z "$value" ] && continue

    baseline_key=$(echo "$label" | tr 'A-Z' 'a-z' | tr ' ' '_')
    BL=$(python3 -c "
import json
b = json.load(open('$BASELINE'))
for k in b:
    if k != 'threshold_multiplier' and '$baseline_key'.startswith(k.replace('_','')) or k.replace('_','').startswith('$baseline_key'.replace('_','')):
        print(b[k])
        break
" 2>/dev/null || echo "")

    if [ -n "$BL" ]; then
        LIMIT=$(python3 -c "print($BL * $THRESHOLD)")
        if python3 -c "import sys; sys.exit(0 if $value > $LIMIT else 1)" 2>/dev/null; then
            echo "  FAIL: $label = ${value}µs > ${LIMIT}µs (${BL}µs × ${THRESHOLD})"
            FAILED=1
        else
            echo "  PASS: $label = ${value}µs ≤ ${LIMIT}µs"
        fi
    else
        echo "  INFO: $label = ${value}µs (no baseline)"
    fi
done <<< "$OUTPUT"

if [ "$FAILED" -eq 1 ]; then
    echo "FAIL: benchmark regression detected"; exit 1
fi
echo "PASS: all benchmarks within ${THRESHOLD}x of baseline"
exit 0
