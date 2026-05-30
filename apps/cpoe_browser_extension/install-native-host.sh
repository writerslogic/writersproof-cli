#!/bin/bash
# Install CPoE Native Messaging Host on macOS/Linux
#
# This script:
# 1. Copies the native messaging host binary to /usr/local/bin/
# 2. Registers the native messaging manifest for Chrome, Firefox, and/or Edge
#
# Usage: ./install-native-host.sh [--chrome] [--firefox] [--edge] [--all] [--extension-id ID]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HOST_BINARY="writerslogic-native-messaging-host"
HOST_NAME="com.writerslogic.witnessd"

# Detect OS
case "$(uname -s)" in
  Darwin) OS="macos" ;;
  Linux)  OS="linux" ;;
  *)      echo "Unsupported OS: $(uname -s)"; exit 1 ;;
esac

# Find binary — check WritersProof.app bundle first, then build dirs, then PATH
BINARY_PATH=""
APP_BUNDLE="/Applications/WritersProof.app/Contents/MacOS/${HOST_BINARY}"
if [ -f "${APP_BUNDLE}" ]; then
  BINARY_PATH="${APP_BUNDLE}"
elif [ -f "${SCRIPT_DIR}/../target/release/${HOST_BINARY}" ]; then
  BINARY_PATH="${SCRIPT_DIR}/../target/release/${HOST_BINARY}"
elif [ -f "${SCRIPT_DIR}/../target/debug/${HOST_BINARY}" ]; then
  BINARY_PATH="${SCRIPT_DIR}/../target/debug/${HOST_BINARY}"
elif command -v "${HOST_BINARY}" &>/dev/null; then
  BINARY_PATH="$(command -v "${HOST_BINARY}")"
else
  echo "Error: Cannot find ${HOST_BINARY} binary."
  echo "Install WritersProof.app first, or build: cargo build --release --bin ${HOST_BINARY}"
  exit 1
fi

INSTALL_DIR="/usr/local/bin"
INSTALLED_BINARY="${INSTALL_DIR}/${HOST_BINARY}"

install_binary() {
  echo "Installing ${HOST_BINARY} to ${INSTALL_DIR}..."
  sudo install -m 755 "${BINARY_PATH}" "${INSTALLED_BINARY}"
  echo "  Installed: ${INSTALLED_BINARY}"
}

install_chrome() {
  if [ "$OS" = "macos" ]; then
    MANIFEST_DIR="$HOME/Library/Application Support/Google/Chrome/NativeMessagingHosts"
  else
    MANIFEST_DIR="$HOME/.config/google-chrome/NativeMessagingHosts"
  fi

  mkdir -p "${MANIFEST_DIR}"

  # Generate manifest with correct binary path
  cat > "${MANIFEST_DIR}/${HOST_NAME}.json" <<EOF
{
  "name": "${HOST_NAME}",
  "description": "CPoE Native Messaging Host",
  "path": "${INSTALLED_BINARY}",
  "type": "stdio",
  "allowed_origins": [
    "chrome-extension://${EXTENSION_ID}/"
  ]
}
EOF

  echo "  Chrome manifest: ${MANIFEST_DIR}/${HOST_NAME}.json"
  if [ "${EXTENSION_ID}" = "EXTENSION_ID_HERE" ]; then
    echo "  NOTE: Replace EXTENSION_ID_HERE with your actual extension ID after loading it"
  fi
}

install_firefox() {
  if [ "$OS" = "macos" ]; then
    MANIFEST_DIR="$HOME/Library/Application Support/Mozilla/NativeMessagingHosts"
  else
    MANIFEST_DIR="$HOME/.mozilla/native-messaging-hosts"
  fi

  mkdir -p "${MANIFEST_DIR}"

  cat > "${MANIFEST_DIR}/${HOST_NAME}.json" <<EOF
{
  "name": "${HOST_NAME}",
  "description": "CPoE Native Messaging Host",
  "path": "${INSTALLED_BINARY}",
  "type": "stdio",
  "allowed_extensions": [
    "cpoe@writerslogic.com"
  ]
}
EOF

  echo "  Firefox manifest: ${MANIFEST_DIR}/${HOST_NAME}.json"
}

install_edge() {
  if [ "$OS" = "macos" ]; then
    MANIFEST_DIR="$HOME/Library/Application Support/Microsoft Edge/NativeMessagingHosts"
  else
    MANIFEST_DIR="$HOME/.config/microsoft-edge/NativeMessagingHosts"
  fi

  mkdir -p "${MANIFEST_DIR}"

  # Edge uses the same manifest format as Chrome (Chromium-based)
  cat > "${MANIFEST_DIR}/${HOST_NAME}.json" <<EOF
{
  "name": "${HOST_NAME}",
  "description": "CPoE Native Messaging Host",
  "path": "${INSTALLED_BINARY}",
  "type": "stdio",
  "allowed_origins": [
    "chrome-extension://${EXTENSION_ID}/"
  ]
}
EOF

  echo "  Edge manifest: ${MANIFEST_DIR}/${HOST_NAME}.json"
  if [ "${EXTENSION_ID}" = "EXTENSION_ID_HERE" ]; then
    echo "  NOTE: Replace EXTENSION_ID_HERE with your actual extension ID after loading it"
  fi
}

# Parse arguments
INSTALL_CHROME=false
INSTALL_FIREFOX=false
INSTALL_EDGE=false
EXTENSION_ID="imkcofingfnmckconahhemohhnpmbfdp"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --chrome) INSTALL_CHROME=true; shift ;;
    --firefox) INSTALL_FIREFOX=true; shift ;;
    --edge) INSTALL_EDGE=true; shift ;;
    --all|--both) INSTALL_CHROME=true; INSTALL_FIREFOX=true; INSTALL_EDGE=true; shift ;;
    --extension-id) EXTENSION_ID="$2"; shift 2 ;;
    *) INSTALL_CHROME=true; INSTALL_FIREFOX=true; INSTALL_EDGE=true; shift ;;
  esac
done

if ! $INSTALL_CHROME && ! $INSTALL_FIREFOX && ! $INSTALL_EDGE; then
  INSTALL_CHROME=true; INSTALL_FIREFOX=true; INSTALL_EDGE=true
fi

echo "=== CPoE Native Messaging Host Installer ==="
echo ""

install_binary

if $INSTALL_CHROME; then
  echo ""
  echo "Registering Chrome native messaging host..."
  install_chrome
fi

if $INSTALL_FIREFOX; then
  echo ""
  echo "Registering Firefox native messaging host..."
  install_firefox
fi

if $INSTALL_EDGE; then
  echo ""
  echo "Registering Edge native messaging host..."
  install_edge
fi

echo ""
echo "Installation complete!"
echo ""
if [ "${EXTENSION_ID}" = "EXTENSION_ID_HERE" ]; then
  echo "Next steps:"
  echo "  1. Load the browser extension in developer mode"
  echo "  2. Copy the extension ID from chrome://extensions or edge://extensions"
  echo "  3. Re-run with --extension-id YOUR_ID to update manifests"
else
  echo "Extension ID configured: ${EXTENSION_ID}"
fi
