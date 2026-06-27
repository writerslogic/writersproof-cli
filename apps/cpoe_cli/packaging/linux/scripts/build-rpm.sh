#!/bin/bash
# Build RPM package for writerslogic
# Usage: ./build-rpm.sh [version]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../../../../.." && pwd)"
PACKAGING_DIR="${PROJECT_ROOT}/apps/cpoe_cli/packaging/linux"
BUILD_DIR="${PROJECT_ROOT}/build/rpm"
VERSION="${1:-$(git describe --tags --abbrev=0 2>/dev/null | sed 's/^v//' || echo "1.0.0")}"

echo "=== Building RPM package for writerslogic v${VERSION} ==="

# Check dependencies
for cmd in rpmbuild cargo git; do
    if ! command -v "${cmd}" &>/dev/null; then
        echo "Error: ${cmd} is required but not installed."
        exit 1
    fi
done

# Clean and create build directory structure
rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

# Create source tarball
echo "Creating source tarball..."
SOURCE_DIR="${BUILD_DIR}/writerslogic-${VERSION}"
mkdir -p "${SOURCE_DIR}"

rsync -a --exclude='build' --exclude='.git' --exclude='*.AppImage' \
    --exclude='*.deb' --exclude='*.rpm' --exclude='bin/' \
    "${PROJECT_ROOT}/" "${SOURCE_DIR}/"

cd "${BUILD_DIR}"
tar czf "SOURCES/writerslogic-${VERSION}.tar.gz" "writerslogic-${VERSION}"
rm -rf "${SOURCE_DIR}"

# Copy spec file
cp "${PACKAGING_DIR}/rpm/cpoe.spec" "${BUILD_DIR}/SPECS/"

# Update version in spec file
sed -i "s/^Version:.*/Version:        ${VERSION}/" "${BUILD_DIR}/SPECS/cpoe.spec"

# Build the RPM
echo "Building RPM..."
rpmbuild --define "_topdir ${BUILD_DIR}" \
    --define "_version ${VERSION}" \
    -ba "${BUILD_DIR}/SPECS/cpoe.spec"

# Move artifacts
echo "Moving artifacts..."
mkdir -p "${PROJECT_ROOT}/build"
find "${BUILD_DIR}/RPMS" -name "*.rpm" -exec mv {} "${PROJECT_ROOT}/build/" \;
find "${BUILD_DIR}/SRPMS" -name "*.rpm" -exec mv {} "${PROJECT_ROOT}/build/" \;

echo ""
echo "=== Build complete ==="
echo "Packages created in: ${PROJECT_ROOT}/build/"
ls -la "${PROJECT_ROOT}/build/"*.rpm 2>/dev/null || echo "No .rpm files found"
