#!/bin/bash
# CPoE installer
# Usage: curl -sSf https://raw.githubusercontent.com/writerslogic/writersproof-cli/main/apps/cpoe_cli/install.sh | sh
#        CPoE_VERSION=v1.0.0 curl -sSf ... | sh

set -e

REPO="writerslogic/writersproof-cli"
BINARY_NAME="writersproof-cli"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

# Detect OS and architecture
detect_platform() {
    local os arch

    os=$(uname -s | tr '[:upper:]' '[:lower:]')
    arch=$(uname -m)

    case "$os" in
        linux)
            os="unknown-linux-gnu"
            ;;
        darwin)
            os="apple-darwin"
            ;;
        mingw* | msys* | cygwin* | windows*)
            error "Windows detected. Please use the PowerShell installer or download from GitHub releases."
            ;;
        *)
            error "Unsupported operating system: $os"
            ;;
    esac

    case "$arch" in
        x86_64 | amd64)
            arch="x86_64"
            ;;
        aarch64 | arm64)
            arch="aarch64"
            ;;
        *)
            error "Unsupported architecture: $arch"
            ;;
    esac

    echo "${arch}-${os}"
}

# Get the latest release version
get_latest_version() {
    curl -sSf "https://api.github.com/repos/${REPO}/releases/latest" | \
        grep '"tag_name":' | \
        sed -E 's/.*"([^"]+)".*/\1/'
}

# Verify SHA-256 checksum
verify_checksum() {
    local archive="$1"
    local checksum_file="$2"

    if [ ! -f "$checksum_file" ]; then
        warn "Checksum file not found — skipping verification"
        return 0
    fi

    local expected
    expected=$(awk '{print $1}' "$checksum_file")

    local actual
    if command -v sha256sum &> /dev/null; then
        actual=$(sha256sum "$archive" | awk '{print $1}')
    elif command -v shasum &> /dev/null; then
        actual=$(shasum -a 256 "$archive" | awk '{print $1}')
    else
        warn "No sha256sum or shasum found — skipping checksum verification"
        return 0
    fi

    if [ "$actual" != "$expected" ]; then
        error "Checksum mismatch!\n  Expected: $expected\n  Got:      $actual\n\nThe download may be corrupted or tampered with."
    fi

    info "Checksum verified: $actual"
}

# Download and install
install_cpoe() {
    local platform version url archive_name checksum_url tmp_dir

    info "Detecting platform..."
    platform=$(detect_platform)
    info "Platform: $platform"

    if [ -n "${CPoE_VERSION:-}" ]; then
        version="$CPoE_VERSION"
        info "Using pinned version: $version"
    else
        info "Fetching latest version..."
        version=$(get_latest_version)
        if [ -z "$version" ]; then
            error "Could not determine latest version. Check your internet connection."
        fi
        info "Latest version: $version"
    fi

    archive_name="writerslogic-${version}-${platform}.tar.gz"
    url="https://github.com/${REPO}/releases/download/${version}/${archive_name}"
    checksum_url="${url}.sha256"

    info "Downloading $archive_name..."
    tmp_dir=$(mktemp -d)
    trap 'rm -rf "$tmp_dir"' EXIT

    if ! curl -sSfL -o "${tmp_dir}/${archive_name}" "$url"; then
        error "Failed to download $url"
    fi

    # Download and verify checksum
    if curl -sSfL -o "${tmp_dir}/${archive_name}.sha256" "$checksum_url" 2>/dev/null; then
        verify_checksum "${tmp_dir}/${archive_name}" "${tmp_dir}/${archive_name}.sha256"
    else
        warn "Checksum file not available — skipping verification"
    fi

    info "Extracting archive..."
    tar -xzf "${tmp_dir}/${archive_name}" -C "$tmp_dir"

    # Check if we need sudo
    if [ -w "$INSTALL_DIR" ]; then
        info "Installing to $INSTALL_DIR..."
        mv "${tmp_dir}/${BINARY_NAME}" "${INSTALL_DIR}/writersproof-cli"
        chmod +x "${INSTALL_DIR}/writersproof-cli"
        if [ -f "${tmp_dir}/writerslogic-native-messaging-host" ]; then
            mv "${tmp_dir}/writerslogic-native-messaging-host" "${INSTALL_DIR}/writerslogic-native-messaging-host"
            chmod +x "${INSTALL_DIR}/writerslogic-native-messaging-host"
        fi
    else
        info "Installing to $INSTALL_DIR (requires sudo)..."
        sudo mv "${tmp_dir}/${BINARY_NAME}" "${INSTALL_DIR}/writersproof-cli"
        sudo chmod +x "${INSTALL_DIR}/writersproof-cli"
        if [ -f "${tmp_dir}/writerslogic-native-messaging-host" ]; then
            sudo mv "${tmp_dir}/writerslogic-native-messaging-host" "${INSTALL_DIR}/writerslogic-native-messaging-host"
            sudo chmod +x "${INSTALL_DIR}/writerslogic-native-messaging-host"
        fi
    fi

    info "CPoE installed successfully!"
    echo ""

    if command -v writersproof-cli &> /dev/null; then
        info "Installed version: $(writersproof-cli --version)"
        echo ""
        echo "Get started:"
        echo "  writersproof-cli --help      # Show all commands"
        echo "  writersproof-cli essay.md    # Start tracking a document"
    else
        warn "writersproof-cli installed but not in PATH. Add $INSTALL_DIR to your PATH."
        echo ""
        echo "After adding to PATH, run:"
        echo "  writersproof-cli --help      # Show all commands"
        echo "  writersproof-cli essay.md    # Start tracking a document"
    fi
}

# Main
main() {
    echo ""
    echo "  ╦ ╦╦═╗╦╔╦╗╔═╗╦═╗╔═╗╦  ╔═╗╔═╗╦╔═╗"
    echo "  ║║║╠╦╝║ ║ ║╣ ╠╦╝╚═╗║  ║ ║║ ╦║║  "
    echo "  ╚╩╝╩╚═╩ ╩ ╚═╝╩╚═╚═╝╩═╝╚═╝╚═╝╩╚═╝"
    echo "  Cryptographic Authorship Witnessing"
    echo ""

    install_cpoe
}

main "$@"
