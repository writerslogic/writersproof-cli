#!/bin/bash
# Build and package WritersProof browser extensions for Chrome, Firefox, and Edge.
# Produces ready-to-submit ZIP files in dist/
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

VERSION=$(python3 -c "import json; print(json.load(open('manifest.json'))['version'])")
VERSION_FF=$(python3 -c "import json; print(json.load(open('manifest-firefox.json'))['version'])")
DIST_DIR="$SCRIPT_DIR/dist"
rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR"

# Shared files across all browsers
SHARED_FILES=(
    background.js
    content.js
    standalone.js
    secure-channel.js
    popup.html
    popup.js
    popup.css
    options.html
    options.js
    options.css
)

# Validate all shared files exist before building
for f in "${SHARED_FILES[@]}"; do
    if [ ! -f "$f" ]; then
        echo "ERROR: Missing required file: $f" >&2
        exit 1
    fi
done
for icon in icons/icon-16.png icons/icon-32.png icons/icon-48.png icons/icon-128.png; do
    if [ ! -f "$icon" ]; then
        echo "ERROR: Missing icon: $icon" >&2
        exit 1
    fi
done

echo "=== Building WritersProof Browser Extensions v${VERSION} ==="

# --- Chrome Web Store ---
echo ""
echo "--- Chrome Web Store ---"
CHROME_DIR="$DIST_DIR/chrome"
mkdir -p "$CHROME_DIR/icons"
cp manifest.json "$CHROME_DIR/"
for f in "${SHARED_FILES[@]}"; do cp "$f" "$CHROME_DIR/"; done
cp icons/icon-16.png icons/icon-32.png icons/icon-48.png icons/icon-128.png "$CHROME_DIR/icons/"
cd "$CHROME_DIR"
zip -r -q "$DIST_DIR/writersproof-chrome-v${VERSION}.zip" .
echo "  Created: dist/writersproof-chrome-v${VERSION}.zip ($(du -h "$DIST_DIR/writersproof-chrome-v${VERSION}.zip" | cut -f1))"
cd "$SCRIPT_DIR"

# --- Microsoft Edge Add-ons ---
echo ""
echo "--- Microsoft Edge Add-ons ---"
EDGE_DIR="$DIST_DIR/edge"
mkdir -p "$EDGE_DIR/icons"
# Edge uses the same Manifest V3 as Chrome
cp manifest.json "$EDGE_DIR/"
for f in "${SHARED_FILES[@]}"; do cp "$f" "$EDGE_DIR/"; done
cp icons/icon-16.png icons/icon-32.png icons/icon-48.png icons/icon-128.png "$EDGE_DIR/icons/"
cd "$EDGE_DIR"
zip -r -q "$DIST_DIR/writersproof-edge-v${VERSION}.zip" .
echo "  Created: dist/writersproof-edge-v${VERSION}.zip ($(du -h "$DIST_DIR/writersproof-edge-v${VERSION}.zip" | cut -f1))"
cd "$SCRIPT_DIR"

# --- Firefox Add-ons (AMO) ---
echo ""
echo "--- Firefox Add-ons (AMO) ---"
FIREFOX_DIR="$DIST_DIR/firefox"
mkdir -p "$FIREFOX_DIR/icons"
cp manifest-firefox.json "$FIREFOX_DIR/manifest.json"
for f in "${SHARED_FILES[@]}"; do cp "$f" "$FIREFOX_DIR/"; done
cp icons/icon-16.png icons/icon-32.png icons/icon-48.png icons/icon-128.png "$FIREFOX_DIR/icons/"
cd "$FIREFOX_DIR"
zip -r -q "$DIST_DIR/writersproof-firefox-v${VERSION_FF}.zip" .
echo "  Created: dist/writersproof-firefox-v${VERSION_FF}.zip ($(du -h "$DIST_DIR/writersproof-firefox-v${VERSION_FF}.zip" | cut -f1))"
cd "$SCRIPT_DIR"

echo ""
echo "=== Build Complete ==="
echo ""
echo "Packages ready for submission:"
ls -lh "$DIST_DIR"/*.zip
echo ""
echo "Next steps:"
echo "  Chrome:  https://chrome.google.com/webstore/devconsole"
echo "  Edge:    https://partner.microsoft.com/en-us/dashboard/microsoftedge"
echo "  Firefox: https://addons.mozilla.org/en-US/developers/"
