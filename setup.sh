#!/usr/bin/env bash
# =============================================================================
# DNS Attack Lab Suite – Automated Setup
# =============================================================================
# Sets up the complete environment for all 8 DNS attack modules.
#
# Usage:
#   sudo ./setup.sh
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${SCRIPT_DIR}/.venv"
LOG="${SCRIPT_DIR}/logs/setup.log"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${GREEN}[+]${NC} $*" | tee -a "${LOG}"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*" | tee -a "${LOG}"; }
error()   { echo -e "${RED}[-]${NC} $*" | tee -a "${LOG}"; }
step()    { echo -e "\n${BLUE}[>]${NC} ${BOLD}$*${NC}" | tee -a "${LOG}"; }
success() { echo -e "${GREEN}[✓]${NC} $*" | tee -a "${LOG}"; }

banner() {
echo -e "${CYAN}"
cat << 'EOF'
  ██████╗ ███╗   ██╗███████╗     █████╗ ████████╗████████╗ █████╗  ██████╗██╗  ██╗
  ██╔══██╗████╗  ██║██╔════╝    ██╔══██╗╚══██╔══╝╚══██╔══╝██╔══██╗██╔════╝██║ ██╔╝
  ██║  ██║██╔██╗ ██║███████╗    ███████║   ██║      ██║   ███████║██║     █████╔╝
  ██████╔╝██║ ╚████║███████║    ██║  ██║   ██║      ██║   ██║  ██║╚██████╗██║  ██╗
  ╚═════╝ ╚═╝  ╚═══╝╚══════╝    ╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
                              S E T U P
EOF
echo -e "${NC}"
}

check_root() {
    [[ $EUID -eq 0 ]] || { error "Run as root: sudo ./setup.sh"; exit 1; }
}

# =============================================================================
install_system_deps() {
    step "Installing system dependencies..."
    apt-get update -qq 2>>"${LOG}" || warn "apt-get update failed (continuing)"

    PACKAGES=(
        python3 python3-pip python3-venv python3-dev
        tcpdump tshark wireshark-common
        dnsmasq dsniff iptables iproute2
        netcat-openbsd curl wget
        build-essential libnetfilter-queue-dev
        libpcap-dev libssl-dev
    )

    for pkg in "${PACKAGES[@]}"; do
        if dpkg -l "${pkg}" &>/dev/null; then
            info "  ${pkg} — already installed"
        else
            if apt-get install -y -q "${pkg}" >>"${LOG}" 2>&1; then
                info "  ${pkg} — installed"
            else
                warn "  ${pkg} — could not install (may not be needed)"
            fi
        fi
    done

    # dnschef via pip (not in all apt repos)
    if ! command -v dnschef &>/dev/null; then
        pip3 install dnschef --break-system-packages -q 2>>"${LOG}" || \
            warn "dnschef install failed"
    fi
}

# =============================================================================
setup_python_venv() {
    step "Setting up Python virtual environment..."
    if [[ ! -d "${VENV_DIR}" ]]; then
        python3 -m venv "${VENV_DIR}"
        info "Created venv at ${VENV_DIR}"
    fi
    source "${VENV_DIR}/bin/activate"

    pip install --quiet --upgrade pip 2>>"${LOG}"

    PYTHON_PKGS=(
        "scapy>=2.5"
        "dnslib"
        "flask"
        "requests"
        "dnspython"
        "impacket"
    )

    for pkg in "${PYTHON_PKGS[@]}"; do
        name="${pkg%%[>=]*}"
        if python3 -c "import ${name//-/_}" 2>/dev/null; then
            info "  ${name} — already installed"
        else
            if pip install --quiet --break-system-packages "${pkg}" 2>>"${LOG}"; then
                info "  ${name} — installed"
            else
                warn "  ${name} — could not install"
            fi
        fi
    done

    # NetfilterQueue (optional, for ARP module inline mode)
    pip install --quiet --break-system-packages NetfilterQueue 2>>"${LOG}" || \
        warn "NetfilterQueue not installed (ARP module may use simulation fallback)"
}

# =============================================================================
create_directories() {
    step "Creating lab directories..."
    mkdir -p \
        "${SCRIPT_DIR}/logs" \
        "${SCRIPT_DIR}/captures" \
        "${SCRIPT_DIR}/artifacts" \
        "${SCRIPT_DIR}/modules" \
        "${SCRIPT_DIR}/shared"
    success "Directories created"
}

# =============================================================================
create_init_files() {
    touch "${SCRIPT_DIR}/shared/__init__.py" 2>/dev/null || true
    touch "${SCRIPT_DIR}/modules/__init__.py" 2>/dev/null || true
}

# =============================================================================
create_launcher() {
    step "Creating launcher scripts..."

    # Main launcher
    cat > "${SCRIPT_DIR}/run_lab.sh" << 'EOF'
#!/usr/bin/env bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/.venv/bin/activate" 2>/dev/null || true
cd "${SCRIPT_DIR}"
exec python3 dns_lab.py "$@"
EOF
    chmod +x "${SCRIPT_DIR}/run_lab.sh"

    # Sudo launcher
    cat > "${SCRIPT_DIR}/sudo_run_lab.sh" << 'EOF'
#!/usr/bin/env bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec sudo bash "${SCRIPT_DIR}/run_lab.sh" "$@"
EOF
    chmod +x "${SCRIPT_DIR}/sudo_run_lab.sh"

    # Quick module launchers
    for i in $(seq 1 8); do
        cat > "${SCRIPT_DIR}/run_module_${i}.sh" << MODEOF
#!/usr/bin/env bash
SCRIPT_DIR="\$(cd "\$(dirname "\${BASH_SOURCE[0]}")" && pwd)"
source "\${SCRIPT_DIR}/.venv/bin/activate" 2>/dev/null || true
cd "\${SCRIPT_DIR}"
python3 -c "
import sys
sys.path.insert(0, '.')
from dns_lab import MODULES, run_module
run_module(MODULES[${i}-1])
"
MODEOF
        chmod +x "${SCRIPT_DIR}/run_module_${i}.sh"
    done
    success "Launcher scripts created"
}

# =============================================================================
link_tunnel_lab() {
    step "Linking dns_tunnel_lab..."
    TUNNEL_LAB=""
    for candidate in \
        "${HOME}/dns_tunnel_lab" \
        "/home/ocelot/dns_tunnel_lab" \
        "$(dirname "${SCRIPT_DIR}")/dns_tunnel_lab"
    do
        if [[ -d "${candidate}" ]]; then
            TUNNEL_LAB="${candidate}"
            break
        fi
    done

    if [[ -n "${TUNNEL_LAB}" ]]; then
        success "Found dns_tunnel_lab at: ${TUNNEL_LAB}"
        # Create symlink if not already there
        if [[ ! -e "${SCRIPT_DIR}/../dns_tunnel_lab" ]]; then
            ln -sf "${TUNNEL_LAB}" "${SCRIPT_DIR}/../dns_tunnel_lab" 2>/dev/null || true
        fi
    else
        warn "dns_tunnel_lab not found. Modules 06, 07, 08 will use simulation mode."
        warn "To enable full tunnel demos, set up dns_tunnel_lab in ~/dns_tunnel_lab"
    fi
}

# =============================================================================
run_preflight() {
    step "Running preflight checks..."
    source "${VENV_DIR}/bin/activate"

    python3 - << 'PYEOF'
import sys
sys.path.insert(0, '.')
results = []

checks = [
    ("Python 3.10+",    lambda: sys.version_info >= (3, 10)),
    ("scapy",          lambda: __import__("scapy")),
    ("dnslib",         lambda: __import__("dnslib")),
    ("flask",          lambda: __import__("flask")),
    ("shared.ui",      lambda: __import__("shared.ui")),
    ("shared.dns_core",lambda: __import__("shared.dns_core")),
    ("Module 01 load", lambda: __import__("modules.m01_cache_poison")),
    ("Module 03 load", lambda: __import__("modules.m03_rogue_dns")),
    ("Module 06 load", lambda: __import__("modules.m06_tunnel")),
]

for name, fn in checks:
    try:
        fn()
        print(f"  \033[1;32m[✓]\033[0m {name}")
    except Exception as e:
        print(f"  \033[0;31m[✗]\033[0m {name}: {e}")
PYEOF
}

# =============================================================================
print_usage() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║         DNS Attack Lab Suite — Ready                        ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BOLD}Start the interactive lab:${NC}"
    echo "  sudo ./run_lab.sh"
    echo ""
    echo -e "${BOLD}Jump directly to a module:${NC}"
    echo "  sudo ./run_module_1.sh    # Cache Poisoning"
    echo "  sudo ./run_module_3.sh    # Rogue DNS Server"
    echo "  sudo ./run_module_6.sh    # DNS Tunneling"
    echo "  sudo ./run_module_8.sh    # Full Kill Chain"
    echo ""
    echo -e "${BOLD}8 Modules Available:${NC}"
    echo "  01  DNS Cache Poisoning (Kaminsky)"
    echo "  02  ARP + DNS Spoofing (LAN MITM)"
    echo "  03  Rogue DNS Server (wildcard/selective/sinkhole)"
    echo "  04  DNS Rebinding (same-origin bypass)"
    echo "  05  NXDOMAIN Hijacking"
    echo "  06  DNS Tunneling (C2 & Exfiltration)"
    echo "  07  Firewall Bypass via DNS Tunnel"
    echo "  08  Full Attack Kill Chain"
    echo ""
    echo -e "${RED}Isolated lab environments only.${NC}"
    echo ""
}

# =============================================================================
main() {
    mkdir -p "$(dirname "${LOG}")"
    banner
    check_root
    create_directories
    create_init_files
    install_system_deps
    setup_python_venv
    link_tunnel_lab
    create_launcher
    run_preflight
    print_usage
}

main
