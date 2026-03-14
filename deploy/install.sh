#!/usr/bin/env bash
# install.sh — rootkit-radar installation script
#
# Steps:
#   1. Checks prerequisites (kernel headers, Rust toolchain, DKMS)
#   2. Registers the kernel module with DKMS and builds it
#   3. Builds the Rust daemon and TUI binaries
#   4. Installs binaries to /usr/local/bin
#   5. Installs and enables the systemd service
#
# Must be run as root.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="1.0.0"
MODULE_NAME="rootkit-radar"
DKMS_SRC="/usr/src/${MODULE_NAME}-${VERSION}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
die()     { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

# ── 0. Root check ──────────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || die "This script must be run as root (sudo $0)"

# ── 1. Prerequisites ───────────────────────────────────────────────────────
info "Checking prerequisites..."

# Kernel headers
KVER="$(uname -r)"
KDIR="/lib/modules/${KVER}/build"
if [[ ! -d "${KDIR}" ]]; then
    warn "Kernel headers not found at ${KDIR}"
    info "Attempting to install linux-headers-${KVER}..."
    if command -v apt-get &>/dev/null; then
        apt-get install -y "linux-headers-${KVER}" || \
            die "Failed to install kernel headers. Install manually: apt-get install linux-headers-$(uname -r)"
    elif command -v dnf &>/dev/null; then
        dnf install -y "kernel-devel-${KVER}" || \
            die "Failed to install kernel headers."
    else
        die "Cannot auto-install kernel headers. Install linux-headers-$(uname -r) manually."
    fi
fi
success "Kernel headers found at ${KDIR}"

# DKMS
if ! command -v dkms &>/dev/null; then
    info "Installing DKMS..."
    if command -v apt-get &>/dev/null; then
        apt-get install -y dkms
    elif command -v dnf &>/dev/null; then
        dnf install -y dkms
    else
        die "DKMS not found. Install it manually."
    fi
fi
success "DKMS available: $(dkms --version)"

# Rust toolchain
if ! command -v cargo &>/dev/null; then
    info "Rust toolchain not found. Installing via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
        sh -s -- -y --default-toolchain stable --profile minimal
    # shellcheck disable=SC1090
    source "${HOME}/.cargo/env"
fi
success "Rust: $(rustc --version)"

# clang (for eBPF detectors, if still used)
if ! command -v clang &>/dev/null; then
    warn "clang not found — eBPF detectors will not compile"
else
    success "clang: $(clang --version | head -1)"
fi

# ── 2. DKMS — register and build the kernel module ────────────────────────
info "Setting up DKMS for ${MODULE_NAME} v${VERSION}..."

# Copy source to DKMS tree
rm -rf "${DKMS_SRC}"
mkdir -p "${DKMS_SRC}/kernel_module"
cp "${REPO_ROOT}/kernel_module/rootkit_radar.c" "${DKMS_SRC}/kernel_module/"
cp "${REPO_ROOT}/kernel_module/Makefile"        "${DKMS_SRC}/kernel_module/"
cp "${REPO_ROOT}/deploy/dkms.conf"              "${DKMS_SRC}/"

# Remove previous DKMS registration if present
if dkms status "${MODULE_NAME}/${VERSION}" 2>/dev/null | grep -q installed; then
    info "Removing previous DKMS registration..."
    dkms remove "${MODULE_NAME}/${VERSION}" --all || true
fi

dkms add     "${MODULE_NAME}/${VERSION}"
dkms build   "${MODULE_NAME}/${VERSION}" -k "${KVER}"
dkms install "${MODULE_NAME}/${VERSION}" -k "${KVER}"
success "Kernel module installed via DKMS"

# Load the module now
if ! lsmod | grep -q rootkit_radar; then
    modprobe rootkit_radar && success "rootkit_radar module loaded" \
        || warn "modprobe failed — reboot may be required"
fi

# ── 3. Build Rust binaries ─────────────────────────────────────────────────
info "Building Rust daemon..."
(cd "${REPO_ROOT}/daemon" && cargo build --release)
success "Daemon built: ${REPO_ROOT}/daemon/target/release/rr-daemon"

info "Building Rust TUI..."
(cd "${REPO_ROOT}/tui" && cargo build --release)
success "TUI built: ${REPO_ROOT}/tui/target/release/rr-tui"

# ── 4. Install binaries ────────────────────────────────────────────────────
info "Installing binaries to /usr/local/bin..."
install -m 0755 "${REPO_ROOT}/daemon/target/release/rr-daemon" /usr/local/bin/rr-daemon
install -m 0755 "${REPO_ROOT}/tui/target/release/rr-tui"       /usr/local/bin/rr-tui
success "Binaries installed"

# ── 5. Systemd service ────────────────────────────────────────────────────
info "Installing systemd service..."
install -m 0644 "${REPO_ROOT}/deploy/rootkit-radar.service" \
    /etc/systemd/system/rootkit-radar.service

systemctl daemon-reload
systemctl enable  rootkit-radar.service
systemctl restart rootkit-radar.service

success "rootkit-radar service enabled and started"
systemctl status rootkit-radar.service --no-pager || true

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║   rootkit-radar installation complete!       ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║  Daemon:  systemctl status rootkit-radar     ║${NC}"
echo -e "${GREEN}║  Logs:    journalctl -u rootkit-radar -f     ║${NC}"
echo -e "${GREEN}║  TUI:     sudo rr-tui                        ║${NC}"
echo -e "${GREEN}║  JSON:    tail -f /var/log/rootkit_radar.log ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════╝${NC}"
