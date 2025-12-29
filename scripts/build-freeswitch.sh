#!/bin/bash
#
# Build FreeSWITCH 1.10.12 as static libraries for embedding in pyswitch
#
# Produces:
#   - libfreeswitch.a (core)
#   - libsofia-sip-ua.a (SIP stack)
#   - mod_sofia.a, mod_g711.a, mod_dptools.a
#
# Usage:
#   ./scripts/build-freeswitch.sh [--clean]
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
VENDOR_DIR="$PROJECT_ROOT/vendor"
FS_VERSION="1.10.12"
FS_DIR="$VENDOR_DIR/freeswitch-$FS_VERSION"
FS_REPO="https://github.com/signalwire/freeswitch.git"
BUILD_DIR="$FS_DIR/build-static"
INSTALL_DIR="$PROJECT_ROOT/vendor/freeswitch-static"

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

# Handle --clean flag
if [ "$1" == "--clean" ]; then
    log_info "Cleaning FreeSWITCH build..."
    rm -rf "$BUILD_DIR" "$INSTALL_DIR"
    log_info "Clean complete"
    exit 0
fi

# Check dependencies
check_deps() {
    log_info "Checking build dependencies..."

    local missing=()

    for cmd in git autoconf automake libtool pkg-config gcc g++ make; do
        if ! command -v $cmd &> /dev/null; then
            missing+=($cmd)
        fi
    done

    if [ ${#missing[@]} -ne 0 ]; then
        log_error "Missing dependencies: ${missing[*]}"
        echo ""
        echo "On Ubuntu/Debian:"
        echo "  sudo apt-get install git build-essential autoconf automake libtool pkg-config"
        echo ""
        echo "On macOS:"
        echo "  brew install autoconf automake libtool pkg-config"
        exit 1
    fi

    log_info "All dependencies found"
}

# Clone FreeSWITCH if not present
clone_freeswitch() {
    if [ -d "$FS_DIR" ]; then
        log_info "FreeSWITCH $FS_VERSION already cloned"
        return
    fi

    log_info "Cloning FreeSWITCH $FS_VERSION from SignalWire..."
    mkdir -p "$VENDOR_DIR"

    git clone --depth 1 --branch "v$FS_VERSION" "$FS_REPO" "$FS_DIR"

    log_info "Clone complete"
}

# Create minimal modules.conf
create_modules_conf() {
    log_info "Creating minimal modules.conf..."

    cat > "$FS_DIR/modules.conf" << 'EOF'
# Minimal FreeSWITCH modules for pyswitch
# Only what's needed for SIP/RTP telephony

# Applications - minimal dialplan tools
applications/mod_dptools

# Codecs - G.711 only (PCMU/PCMA)
codecs/mod_g711

# Endpoints - SIP only
endpoints/mod_sofia

# Dialplan - minimal XML dialplan
dialplans/mod_dialplan_xml

# Loggers - console only for debugging
loggers/mod_console
EOF

    log_info "modules.conf created with minimal modules"
}

# Bootstrap and configure
configure_freeswitch() {
    log_info "Configuring FreeSWITCH for static build..."

    cd "$FS_DIR"

    # Bootstrap if needed
    if [ ! -f "configure" ]; then
        log_info "Running bootstrap..."
        ./bootstrap.sh -j
    fi

    # Create build directory
    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"

    # Configure for static libraries
    ../configure \
        --prefix="$INSTALL_DIR" \
        --disable-shared \
        --enable-static \
        --disable-debug \
        --disable-libyuv \
        --disable-libvpx \
        --without-python \
        --without-java \
        --without-lua \
        --without-perl \
        --without-erlang \
        --without-odbc \
        --without-pgsql \
        --without-mysql \
        --without-sqlite \
        --disable-core-odbc-support \
        --disable-core-pgsql-support \
        CFLAGS="-fPIC -O2" \
        CXXFLAGS="-fPIC -O2"

    log_info "Configuration complete"
}

# Build FreeSWITCH
build_freeswitch() {
    log_info "Building FreeSWITCH (this may take a while)..."

    cd "$BUILD_DIR"

    # Determine number of parallel jobs
    if [ "$(uname)" == "Darwin" ]; then
        JOBS=$(sysctl -n hw.ncpu)
    else
        JOBS=$(nproc)
    fi

    make -j$JOBS

    log_info "Build complete"
}

# Install to vendor directory
install_freeswitch() {
    log_info "Installing to $INSTALL_DIR..."

    cd "$BUILD_DIR"
    make install

    log_info "Installation complete"
}

# Print summary
print_summary() {
    echo ""
    log_info "=========================================="
    log_info "FreeSWITCH $FS_VERSION static build complete!"
    log_info "=========================================="
    echo ""
    echo "Static libraries installed to:"
    echo "  $INSTALL_DIR/lib/"
    echo ""
    echo "Headers installed to:"
    echo "  $INSTALL_DIR/include/"
    echo ""

    # List the key static libraries
    if [ -d "$INSTALL_DIR/lib" ]; then
        echo "Key static libraries:"
        ls -lh "$INSTALL_DIR/lib/"*.a 2>/dev/null | head -10 || echo "  (none found yet)"
    fi

    echo ""
    echo "To use in freeswitch-sys/build.rs:"
    echo "  cargo:rustc-link-search=native=$INSTALL_DIR/lib"
    echo "  cargo:rustc-link-lib=static=freeswitch"
    echo ""
}

# Main
main() {
    log_info "Building FreeSWITCH $FS_VERSION for pyswitch..."
    echo ""

    check_deps
    clone_freeswitch
    create_modules_conf
    configure_freeswitch
    build_freeswitch
    install_freeswitch
    print_summary
}

main "$@"
