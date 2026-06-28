#!/bin/bash
# Build Debian package for writersproof-cli
# Usage: ./build-deb.sh [version]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../../../../.." && pwd)"
PACKAGING_DIR="${PROJECT_ROOT}/apps/cpoe_cli/packaging/linux"
BUILD_DIR="${PROJECT_ROOT}/build/deb"
VERSION="${1:-$(git describe --tags --abbrev=0 2>/dev/null | sed 's/^v//' || echo "1.0.0")}"

echo "=== Building Debian package for writersproof-cli v${VERSION} ==="

# Check dependencies
for cmd in dpkg-buildpackage dh cargo git; do
    if ! command -v "${cmd%% *}" &>/dev/null; then
        echo "Error: ${cmd} is required but not installed."
        exit 1
    fi
done

# Clean and create build directory
rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}"

# Create source directory structure
SOURCE_DIR="${BUILD_DIR}/writersproof-cli-${VERSION}"
mkdir -p "${SOURCE_DIR}"

# Copy source files
echo "Copying source files..."
rsync -a --exclude='build' --exclude='.git' --exclude='target' --exclude='*.AppImage' \
    --exclude='*.deb' --exclude='*.rpm' --exclude='/bin/' \
    "${PROJECT_ROOT}/" "${SOURCE_DIR}/"

# Copy debian directory
cp -r "${PACKAGING_DIR}/debian" "${SOURCE_DIR}/"

# Update changelog with current version
sed -i "s/^writersproof-cli (.*)/writersproof-cli (${VERSION}-1)/" "${SOURCE_DIR}/debian/changelog"

# Make rules executable
chmod +x "${SOURCE_DIR}/debian/rules"
chmod +x "${SOURCE_DIR}/debian/postinst"
chmod +x "${SOURCE_DIR}/debian/prerm"
chmod +x "${SOURCE_DIR}/debian/postrm"

# Build the package
echo "Building package..."
cd "${SOURCE_DIR}"

# Generate source tarball
tar czf "../writersproof-cli_${VERSION}.orig.tar.gz" -C "${BUILD_DIR}" "writersproof-cli-${VERSION}"

# Build binary package
dpkg-buildpackage -us -uc -b -d  # -d: toolchain via rustup, not dpkg

# Move artifacts
echo "Moving artifacts..."
mv "${BUILD_DIR}"/*.deb "${PROJECT_ROOT}/build/" 2>/dev/null || true
mv "${BUILD_DIR}"/*.buildinfo "${PROJECT_ROOT}/build/" 2>/dev/null || true
mv "${BUILD_DIR}"/*.changes "${PROJECT_ROOT}/build/" 2>/dev/null || true

echo ""
echo "=== Build complete ==="
echo "Packages created in: ${PROJECT_ROOT}/build/"
ls -la "${PROJECT_ROOT}/build/"*.deb 2>/dev/null || echo "No .deb files found"
