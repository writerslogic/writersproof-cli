#!/usr/bin/env bash
# Pipe each bundled sample through the transcription_check example and print
# the result. Intended as a quick sanity check that the engine pipeline still
# discriminates between composition / transcription / focus-correlated input.
#
# Usage:
#   ./run_all.sh
#
# Run from any working directory; the script resolves paths relative to its
# own location.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Crate root is two levels up from samples/ (examples/transcription_check_samples).
CRATE_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

SAMPLES=(
    "composition.json"
    "linear_typing.json"
    "with_focus_switches.json"
)

# Build once so each invocation below is fast.
echo "[run_all] building example transcription_check ..."
( cd "$CRATE_ROOT" && cargo build -p cpoe --example transcription_check --quiet )

for sample in "${SAMPLES[@]}"; do
    echo
    echo "============================================================"
    echo "[run_all] sample: $sample"
    echo "============================================================"
    ( cd "$CRATE_ROOT" && cargo run -p cpoe --example transcription_check --quiet -- \
        "$SCRIPT_DIR/$sample" )
done
