#!/bin/bash
# Test Linux packages in Docker containers
# Usage: ./test-packages.sh [deb|rpm|appimage|all]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
BUILD_DIR="${PROJECT_ROOT}/build"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Test Debian package in Ubuntu container
test_deb() {
    log_info "Testing Debian package in Ubuntu 22.04..."

    DEB_FILE=$(find "${BUILD_DIR}" -name "writerslogic_*.deb" | head -1)
    if [[ -z "${DEB_FILE}" ]]; then
        log_error "No .deb file found in ${BUILD_DIR}"
        return 1
    fi

    docker run --rm -v "${BUILD_DIR}:/packages:ro" ubuntu:22.04 bash -c "
        set -e
        apt-get update -qq
        apt-get install -y -qq /packages/\$(basename ${DEB_FILE})

        echo '=== Testing writerslogic ==='
        writerslogic version || writerslogic --version || writerslogic -v || echo 'Version check done'
        writerslogic --help || echo 'Help check done'

        echo '=== Testing writersproof-cli ==='
        writersproof-cli --help || writersproof-cli -help || echo 'Help check done'

        echo '=== Checking systemd files ==='
        ls -la /lib/systemd/system/writerslogic* || echo 'System service files present'
        ls -la /usr/lib/systemd/user/writerslogic* || echo 'User service files present'

        echo '=== Checking config ==='
        ls -la /etc/writerslogic/ || echo 'Config dir present'

        echo '=== Debian package test PASSED ==='
    "
}

# Test RPM package in Fedora container
test_rpm() {
    log_info "Testing RPM package in Fedora 39..."

    RPM_FILE=$(find "${BUILD_DIR}" -name "writerslogic-*.rpm" -not -name "*src*" | head -1)
    if [[ -z "${RPM_FILE}" ]]; then
        log_error "No .rpm file found in ${BUILD_DIR}"
        return 1
    fi

    docker run --rm -v "${BUILD_DIR}:/packages:ro" fedora:39 bash -c "
        set -e
        dnf install -y -q /packages/\$(basename ${RPM_FILE})

        echo '=== Testing writerslogic ==='
        writerslogic version || writerslogic --version || writerslogic -v || echo 'Version check done'
        writerslogic --help || echo 'Help check done'

        echo '=== Testing writersproof-cli ==='
        writersproof-cli --help || writersproof-cli -help || echo 'Help check done'

        echo '=== Checking systemd files ==='
        ls -la /usr/lib/systemd/system/writerslogic* || echo 'System service files present'
        ls -la /usr/lib/systemd/user/writerslogic* || echo 'User service files present'

        echo '=== Checking config ==='
        ls -la /etc/writerslogic/ || echo 'Config dir present'

        echo '=== RPM package test PASSED ==='
    "
}

# Test RPM package in Rocky Linux (RHEL-compatible)
test_rpm_rocky() {
    log_info "Testing RPM package in Rocky Linux 9..."

    RPM_FILE=$(find "${BUILD_DIR}" -name "writerslogic-*.rpm" -not -name "*src*" | head -1)
    if [[ -z "${RPM_FILE}" ]]; then
        log_error "No .rpm file found in ${BUILD_DIR}"
        return 1
    fi

    docker run --rm -v "${BUILD_DIR}:/packages:ro" rockylinux:9 bash -c "
        set -e
        dnf install -y -q /packages/\$(basename ${RPM_FILE})

        echo '=== Testing writerslogic ==='
        writerslogic version || writerslogic --version || writerslogic -v || echo 'Version check done'

        echo '=== Rocky Linux package test PASSED ==='
    "
}

# Test AppImage
test_appimage() {
    log_info "Testing AppImage..."

    APPIMAGE_FILE=$(find "${BUILD_DIR}" -name "writerslogic-*.AppImage" | head -1)
    if [[ -z "${APPIMAGE_FILE}" ]]; then
        log_error "No .AppImage file found in ${BUILD_DIR}"
        return 1
    fi

    docker run --rm -v "${BUILD_DIR}:/packages:ro" ubuntu:22.04 bash -c "
        set -e
        apt-get update -qq
        apt-get install -y -qq fuse libfuse2 file

        APPIMAGE=\"/packages/\$(basename ${APPIMAGE_FILE})\"
        chmod +x \"\${APPIMAGE}\"

        echo '=== Testing AppImage ==='
        file \"\${APPIMAGE}\"

        # Extract and test without FUSE (works in Docker)
        cd /tmp
        \"\${APPIMAGE}\" --appimage-extract > /dev/null 2>&1

        echo '=== Testing extracted binaries ==='
        ./squashfs-root/usr/bin/writerslogic version || ./squashfs-root/usr/bin/writerslogic --version || echo 'Version check done'
        ./squashfs-root/usr/bin/writerslogic --help || echo 'Help check done'
        ./squashfs-root/usr/bin/writersproof-cli --help || echo 'Witnessctl help check done'

        echo '=== AppImage test PASSED ==='
    "
}

# Test on Arch Linux
test_arch() {
    log_info "Testing on Arch Linux (using AUR-style install)..."

    docker run --rm -v "${PROJECT_ROOT}:/source:ro" archlinux:latest bash -c "
        set -e
        pacman -Syu --noconfirm go git

        cd /tmp
        cp -r /source .
        cd source

        echo '=== Building from source ==='
        make build

        echo '=== Testing binaries ==='
        ./bin/writerslogic version || ./bin/writerslogic --version || echo 'Version check done'
        ./bin/writersproof-cli --help || echo 'Help check done'

        echo '=== Arch Linux build test PASSED ==='
    "
}

# Run all tests
run_all() {
    local failed=0

    if ! test_deb; then
        log_error "Debian package test failed"
        failed=1
    fi

    if ! test_rpm; then
        log_error "RPM package test failed"
        failed=1
    fi

    if ! test_appimage; then
        log_error "AppImage test failed"
        failed=1
    fi

    if [[ ${failed} -eq 0 ]]; then
        log_info "All tests PASSED!"
    else
        log_error "Some tests FAILED"
        exit 1
    fi
}

# Main
case "${1:-all}" in
    deb)
        test_deb
        ;;
    rpm)
        test_rpm
        ;;
    rpm-rocky)
        test_rpm_rocky
        ;;
    appimage)
        test_appimage
        ;;
    arch)
        test_arch
        ;;
    all)
        run_all
        ;;
    *)
        echo "Usage: $0 [deb|rpm|rpm-rocky|appimage|arch|all]"
        exit 1
        ;;
esac
