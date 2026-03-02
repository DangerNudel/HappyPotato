#!/usr/bin/env bash
# ============================================================
# DNS Attack Lab — Module 07: Firewall Bypass via DNS Tunnel
# ============================================================
# Usage:
#   sudo ./run_module_07.sh              (setup + demo)
#   sudo ./run_module_07.sh --guide-only (show guide only)
#   sudo ./run_module_07.sh --demo-only  (skip setup)
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="${SCRIPT_DIR}/.venv/bin/activate"
ARG="${1:-}"

# Activate virtual environment if present
if [ -f "${VENV}" ]; then
    # shellcheck disable=SC1090
    source "${VENV}"
fi

# Escalate to root if not already (most modules need raw socket access)
if [ "${EUID}" -ne 0 ]; then
    echo -e "\033[1;33m[!]\033[0m Root required — re-running with sudo..."
    exec sudo bash "${BASH_SOURCE[0]}" "$@"
fi

cd "${SCRIPT_DIR}"

python3 - "${ARG}" << 'PYEOF'
import sys
import os

script_dir = os.path.dirname(os.path.abspath(sys.argv[0])) if sys.argv[0] != "-" else os.getcwd()
sys.path.insert(0, script_dir)
os.chdir(script_dir)

arg = sys.argv[1] if len(sys.argv) > 1 else ""

try:
    from modules.m07_firewall_bypass import FirewallBypassModule
except ImportError as e:
    print(f"\033[0;31m[-]\033[0m Import error: {e}")
    print(f"\033[1;33m[!]\033[0m Run setup first:  sudo ./setup.sh")
    sys.exit(1)

try:
    from shared.ui import C, confirm
except ImportError:
    def confirm(msg, default=False):
        r = input(f"{msg} [y/N]: ").strip().lower()
        return r in ("y", "yes")

obj = FirewallBypassModule()

if arg == "--guide-only":
    obj.show_overview()
    sys.exit(0)

obj.show_overview()
print()

if arg == "--demo-only":
    obj.prompt_run()
else:
    ok = obj.prompt_setup()
    if ok:
        obj.prompt_run()
    else:
        print()
        if confirm("Setup failed or cancelled. Run demo anyway?", default=False):
            obj.prompt_run()
PYEOF
