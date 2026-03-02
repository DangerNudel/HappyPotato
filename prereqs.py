"""
Prerequisite checker and automated installer.
Each module calls check_module_deps() with its requirements.
"""

import os
import shutil
import subprocess
import sys
from shared.ui import *


# ---------------------------------------------------------------------------
# Dependency definitions
# ---------------------------------------------------------------------------
PYTHON_PKGS = {
    "scapy":      "scapy>=2.5",
    "netfilterqueue": "NetfilterQueue",
    "dnslib":     "dnslib",
    "flask":      "flask",
    "requests":   "requests",
}

SYSTEM_TOOLS = {
    "tcpdump":    "tcpdump",
    "arpspoof":   "dsniff",
    "ettercap":   "ettercap-text-only",
    "dnschef":    "dnschef",
    "tshark":     "tshark",
    "iptables":   "iptables",
    "ip":         "iproute2",
    "nft":        "nftables",
    "nc":         "netcat-openbsd",
    "iodine":     "iodine",
    "ping":       "iputils-ping",
}


# ---------------------------------------------------------------------------
# Checkers
# ---------------------------------------------------------------------------
def _has_tool(name: str) -> bool:
    return shutil.which(name) is not None


def _has_python_pkg(name: str) -> bool:
    try:
        __import__(name.replace("-", "_"))
        return True
    except ImportError:
        return False


def _is_root() -> bool:
    return os.geteuid() == 0


def _install_system(pkg: str) -> bool:
    try:
        result = subprocess.run(
            ["apt-get", "install", "-y", "-q", pkg],
            capture_output=True, timeout=120
        )
        return result.returncode == 0
    except Exception:
        return False


def _install_python(pkg_spec: str) -> bool:
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "-q",
             "--break-system-packages", pkg_spec],
            capture_output=True, timeout=120
        )
        return result.returncode == 0
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def check_root(require: bool = True) -> bool:
    """Check for root/sudo. Optionally abort if not root."""
    if _is_root():
        return True
    if require:
        error("This module requires root privileges.")
        warn("Re-run with: sudo python3 dns_lab.py")
        return False
    warn("Not running as root — some features may be limited.")
    return False


def check_deps(
    python_pkgs:  list[str] | None = None,
    system_tools: list[str] | None = None,
    auto_install: bool = True
) -> bool:
    """
    Check and optionally auto-install dependencies.
    Returns True if all requirements are satisfied after checking.
    """
    python_pkgs  = python_pkgs  or []
    system_tools = system_tools or []

    all_ok = True
    rows   = []

    # --- Python packages ---
    for pkg in python_pkgs:
        ok = _has_python_pkg(pkg)
        if not ok and auto_install:
            spec = PYTHON_PKGS.get(pkg, pkg)
            with Spinner(f"Installing Python package: {pkg}"):
                ok = _install_python(spec)
        rows.append((f"py:{pkg}", PYTHON_PKGS.get(pkg, pkg),
                     "✓ OK" if ok else "✗ MISSING"))
        if not ok:
            all_ok = False

    # --- System tools ---
    for tool in system_tools:
        ok = _has_tool(tool)
        if not ok and auto_install and _is_root():
            apt_pkg = SYSTEM_TOOLS.get(tool, tool)
            with Spinner(f"Installing system tool: {tool} ({apt_pkg})"):
                ok = _install_system(apt_pkg)
                if ok:
                    ok = _has_tool(tool)
        rows.append((f"tool:{tool}", SYSTEM_TOOLS.get(tool, tool),
                     "✓ OK" if ok else "✗ MISSING"))
        if not ok:
            all_ok = False

    if rows:
        status_table(rows)

    return all_ok


def check_interface(iface: str) -> bool:
    """Verify a network interface exists."""
    path = f"/sys/class/net/{iface}"
    if os.path.exists(path):
        return True
    error(f"Interface '{iface}' not found.")
    warn("Available interfaces:")
    try:
        result = subprocess.run(["ip", "-br", "link"], capture_output=True, text=True)
        for line in result.stdout.strip().split("\n"):
            print(f"    {line}")
    except Exception:
        pass
    return False


def get_interface_ip(iface: str) -> str | None:
    """Get the IPv4 address of an interface."""
    try:
        result = subprocess.run(
            ["ip", "-4", "addr", "show", iface],
            capture_output=True, text=True
        )
        import re
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", result.stdout)
        return m.group(1) if m else None
    except Exception:
        return None


def get_default_gateway() -> str | None:
    """Get the default gateway IP."""
    try:
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True
        )
        import re
        m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", result.stdout)
        return m.group(1) if m else None
    except Exception:
        return None


def get_default_interface() -> str:
    """Return the default outbound interface name."""
    try:
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True
        )
        import re
        m = re.search(r"dev (\S+)", result.stdout)
        return m.group(1) if m else "eth0"
    except Exception:
        return "eth0"


def enable_ip_forward():
    """Enable kernel IP forwarding."""
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1\n")
        return True
    except Exception:
        return False


def disable_ip_forward():
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("0\n")
    except Exception:
        pass
