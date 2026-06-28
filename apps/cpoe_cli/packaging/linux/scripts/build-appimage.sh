#!/bin/bash
# Build AppImage for writerslogic
# Usage: ./build-appimage.sh [version] [arch]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../../../../.." && pwd)"
PACKAGING_DIR="${PROJECT_ROOT}/apps/cpoe_cli/packaging/linux"
BUILD_DIR="${PROJECT_ROOT}/build/appimage"
VERSION="${1:-$(git describe --tags --abbrev=0 2>/dev/null | sed 's/^v//' || echo "1.0.0")}"
ARCH="${2:-x86_64}"

echo "=== Building AppImage for writerslogic v${VERSION} (${ARCH}) ==="

# Check dependencies
for cmd in cargo git; do
    if ! command -v "${cmd}" &>/dev/null; then
        echo "Error: ${cmd} is required but not installed."
        exit 1
    fi
done

# Clean and create build directory
rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}"

# Download linuxdeploy if not present
LINUXDEPLOY="${BUILD_DIR}/linuxdeploy-${ARCH}.AppImage"
if [[ ! -f "${LINUXDEPLOY}" ]]; then
    echo "Downloading linuxdeploy..."
    curl -L -o "${LINUXDEPLOY}" \
        "https://github.com/linuxdeploy/linuxdeploy/releases/download/continuous/linuxdeploy-${ARCH}.AppImage"
    chmod +x "${LINUXDEPLOY}"
fi

# Create AppDir structure
APPDIR="${BUILD_DIR}/AppDir"
mkdir -p "${APPDIR}/usr/bin"
mkdir -p "${APPDIR}/usr/share/applications"
mkdir -p "${APPDIR}/usr/share/icons/hicolor/256x256/apps"
mkdir -p "${APPDIR}/usr/share/icons/hicolor/scalable/apps"
mkdir -p "${APPDIR}/usr/share/metainfo"
mkdir -p "${APPDIR}/usr/share/man/man1"
mkdir -p "${APPDIR}/usr/share/doc/writerslogic"

# Build binaries
echo "Building binaries..."
cd "${PROJECT_ROOT}"

# Set Rust target based on architecture
case "${ARCH}" in
    x86_64)
        RUST_TARGET="x86_64-unknown-linux-gnu"
        ;;
    aarch64|arm64)
        RUST_TARGET="aarch64-unknown-linux-gnu"
        ;;
    *)
        echo "Unsupported architecture: ${ARCH}"
        exit 1
        ;;
esac

cargo build --release --package cpoe_cli --target "${RUST_TARGET}"

# Install binaries into AppDir
cp "${PROJECT_ROOT}/target/${RUST_TARGET}/release/writersproof-cli" "${APPDIR}/usr/bin/writersproof-cli"
cp "${PROJECT_ROOT}/target/${RUST_TARGET}/release/writerslogic-native-messaging-host" "${APPDIR}/usr/bin/writerslogic-native-messaging-host"

# Copy resources
echo "Copying resources..."

# Desktop file
cp "${PACKAGING_DIR}/appimage/writersproof-cli.desktop" "${APPDIR}/usr/share/applications/"
cp "${PACKAGING_DIR}/appimage/writersproof-cli.desktop" "${APPDIR}/"

# AppData/MetaInfo
cp "${PACKAGING_DIR}/appimage/writersproof-cli.appdata.xml" "${APPDIR}/usr/share/metainfo/"

# Icons
cp "${PACKAGING_DIR}/appimage/icons/writersproof-cli.svg" "${APPDIR}/usr/share/icons/hicolor/scalable/apps/"

# Convert SVG to PNG for icon (if ImageMagick is available)
if command -v convert &>/dev/null; then
    convert -background none -resize 256x256 \
        "${PACKAGING_DIR}/appimage/icons/writersproof-cli.svg" \
        "${APPDIR}/usr/share/icons/hicolor/256x256/apps/writersproof-cli.png"
else
    echo "Warning: ImageMagick not found, skipping PNG icon generation"
fi

# Copy main icon for AppImage
cp "${PACKAGING_DIR}/appimage/icons/writersproof-cli.svg" "${APPDIR}/writersproof-cli.svg"

# Man pages
if [[ -d "${PROJECT_ROOT}/docs/man" ]]; then
    cp "${PROJECT_ROOT}/docs/man/"*.1 "${APPDIR}/usr/share/man/man1/" 2>/dev/null || true
fi

# Documentation
cp "${PROJECT_ROOT}/LICENSE" "${APPDIR}/usr/share/doc/writerslogic/"
cp "${PROJECT_ROOT}/README.md" "${APPDIR}/usr/share/doc/writerslogic/"

# AppRun script
cp "${PACKAGING_DIR}/appimage/AppRun" "${APPDIR}/"
chmod +x "${APPDIR}/AppRun"

# Create the AppImage
echo "Creating AppImage..."
cd "${BUILD_DIR}"

export OUTPUT="writersproof-cli-${VERSION}-${ARCH}.AppImage"
export VERSION="${VERSION}"

# AppStream metadata is optional for a CLI AppImage; skip its (overly strict)
# validation so the build does not fail on a cid-contains-hyphen hint.
export NO_APPSTREAM=1
"${LINUXDEPLOY}" --appdir "${APPDIR}" --output appimage

# Move to final location
mkdir -p "${PROJECT_ROOT}/build"
mv "${OUTPUT}" "${PROJECT_ROOT}/build/"

# Create update information file (for AppImageUpdate)
echo "gh-releases-zsync|writerslogic|writersproof-cli|latest|writersproof-cli-*${ARCH}.AppImage.zsync" \
    > "${PROJECT_ROOT}/build/${OUTPUT%.AppImage}.zsync"

echo ""
echo "=== Build complete ==="
echo "AppImage created: ${PROJECT_ROOT}/build/${OUTPUT}"
ls -la "${PROJECT_ROOT}/build/"*AppImage* 2>/dev/null || echo "No AppImage files found"
