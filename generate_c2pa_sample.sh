#!/bin/bash
# Generate a C2PA conformance sample and run c2patool inspection.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SAMPLE_DIR="$SCRIPT_DIR/c2pa-conformance-sample"
mkdir -p "$SAMPLE_DIR"

echo "=== Step 1: Create sample document ==="
cat > "$SAMPLE_DIR/sample-essay.txt" << 'EOF'
The Role of Cryptographic Attestation in Modern Publishing

In an era where AI-generated text is indistinguishable from human writing,
publishers face a fundamental challenge: how do you verify that a submitted
manuscript was actually written by the claimed author?

Traditional approaches rely on AI detection tools, which suffer from
documented false positive rates of 9-20% (Liang et al., 2023) and
disproportionately flag non-native English speakers. These tools analyze
the finished product, attempting to distinguish human from machine
based on statistical patterns that break with every new model release.

WritersProof takes the opposite approach: instead of analyzing the
finished text, it records the act of creation. Every keystroke interval,
every revision cycle, every pause pattern is captured and sealed into
a cryptographic evidence chain during the writing process itself.

The result is a C2PA-conformant manifest that proves not just who
signed the document, but how it was created — turning authorship
from a claim into verifiable evidence.
EOF

echo "=== Step 2: Build C2PA manifest via engine ==="
cd "$SCRIPT_DIR"

# Use cargo test to generate the sample (faster than a full binary)
cargo test --test c2pa_conformance -- --nocapture 2>&1 | tail -5

# Generate via the CLI if available
if [ -f "/Volumes/C/rust-target/release/writersproof-cli" ] || [ -f "/Volumes/C/rust-target/debug/writersproof-cli" ]; then
    echo "CLI binary found"
fi

echo "=== Step 3: Generate standalone C2PA JUMBF via Rust ==="
# Write a small Rust program to generate the sample
cat > "$SAMPLE_DIR/gen.rs" << 'RUSTEOF'
// This would be compiled as a test — see c2pa_conformance.rs
RUSTEOF

# Run the conformance test which generates sample output
cargo test -p authorproof-protocol --lib -- c2pa --nocapture 2>&1 | tail -20

echo ""
echo "=== Step 4: Check for .c2pa output files ==="
find /tmp -name "*.c2pa" -newer "$SAMPLE_DIR/sample-essay.txt" 2>/dev/null | head -5
find "$SAMPLE_DIR" -name "*.c2pa" 2>/dev/null | head -5

echo ""
echo "=== Done ==="
echo "Sample document: $SAMPLE_DIR/sample-essay.txt"
echo "Next: Run c2patool on the generated .c2pa file"
