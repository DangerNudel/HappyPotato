#!/usr/bin/env python3
"""
DNS Attack Lab – Master Launcher
==================================
Interactive menu for all DNS attack and defense demonstrations.
Run with: sudo python3 dns_lab.py
"""

import os
import sys
import time

# Ensure project root is on the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from shared.ui import *

# ---------------------------------------------------------------------------
# Module registry
# ---------------------------------------------------------------------------
MODULES = [
    {
        "key": "01",
        "label": "DNS Cache Poisoning (Kaminsky Attack)",
        "desc":  "Race spoofed UDP responses to poison a resolver's cache",
        "mitre": "T1584.002",
        "diff":  "Intermediate",
        "class": ("modules.m01_cache_poison", "CachePoisonModule"),
    },
    {
        "key": "02",
        "label": "ARP + DNS Spoofing (LAN MITM)",
        "desc":  "Poison ARP tables then intercept and rewrite DNS responses",
        "mitre": "T1557.002",
        "diff":  "Advanced",
        "class": ("modules.m02_arp_spoof", "ArpDnsSpoofModule"),
    },
    {
        "key": "03",
        "label": "Rogue DNS Server",
        "desc":  "Wildcard/selective DNS server with full query logging",
        "mitre": "T1584.002",
        "diff":  "Beginner",
        "class": ("modules.m03_rogue_dns", "RogueDNSModule"),
    },
    {
        "key": "04",
        "label": "DNS Rebinding Attack",
        "desc":  "Bypass same-origin policy via low-TTL domain rebinding",
        "mitre": "T1557",
        "diff":  "Advanced",
        "class": ("modules.m04_rebinding", "DnsRebindingModule"),
    },
    {
        "key": "05",
        "label": "NXDOMAIN Hijacking",
        "desc":  "Intercept failed lookups and redirect to attacker IP",
        "mitre": "T1584.002",
        "diff":  "Beginner",
        "class": ("modules.m05_nxdomain", "NxdomainHijackModule"),
    },
    {
        "key": "06",
        "label": "DNS Tunneling – C2 & Exfiltration",
        "desc":  "Covert data channel inside DNS queries (hex-encoded payloads)",
        "mitre": "T1071.004",
        "diff":  "Intermediate",
        "class": ("modules.m06_tunnel", "DnsTunnelModule"),
    },
    {
        "key": "07",
        "label": "Firewall Bypass via DNS Tunnel",
        "desc":  "Show egress filtering defeated by DNS-encapsulated traffic",
        "mitre": "T1572",
        "diff":  "Intermediate",
        "class": ("modules.m07_firewall_bypass", "FirewallBypassModule"),
    },
    {
        "key": "08",
        "label": "Full DNS Attack Kill Chain",
        "desc":  "End-to-end: Poison → Phishing → Tunnel C2 → Recon Exfil",
        "mitre": "T1071.004+T1572+T1041",
        "diff":  "Advanced",
        "class": ("modules.m08_kill_chain", "KillChainModule"),
    },
]

DIFF_COLOR = {
    "Beginner":     C.LGREEN,
    "Intermediate": C.YELLOW,
    "Advanced":     C.LRED,
}


# ---------------------------------------------------------------------------
# ASCII Banner
# ---------------------------------------------------------------------------
BANNER = r"""
  ██████╗ ███╗   ██╗███████╗     █████╗ ████████╗████████╗ █████╗  ██████╗██╗  ██╗
  ██╔══██╗████╗  ██║██╔════╝    ██╔══██╗╚══██╔══╝╚══██╔══╝██╔══██╗██╔════╝██║ ██╔╝
  ██║  ██║██╔██╗ ██║███████╗    ███████║   ██║      ██║   ███████║██║     █████╔╝
  ██║  ██║██║╚██╗██║╚════██║    ██╔══██║   ██║      ██║   ██╔══██║██║     ██╔═██╗
  ██████╔╝██║ ╚████║███████║    ██║  ██║   ██║      ██║   ██║  ██║╚██████╗██║  ██╗
  ╚═════╝ ╚═╝  ╚═══╝╚══════╝    ╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
                            L A B   S U I T E   v1.0
"""


def print_banner():
    os.system("clear" if os.name == "posix" else "cls")
    print(C.CYAN + BANNER + C.RESET)
    w = min(shutil.get_terminal_size((100, 40)).columns, 84)
    print(C.DIM + "─" * w + C.RESET)
    print(f"  {C.BOLD}DNS Poisoning & Tunneling Lab{C.RESET}  "
          f"{C.DIM}│{C.RESET}  "
          f"Cybersecurity Training — Isolated Lab Use Only")
    print(C.DIM + "─" * w + C.RESET)
    print()


def print_menu():
    print(f"  {'#':<4} {'MODULE':<42} {'MITRE':<12} {'DIFFICULTY'}")
    print(f"  {C.DIM}{'─'*4} {'─'*42} {'─'*12} {'─'*12}{C.RESET}")
    for i, mod in enumerate(MODULES):
        dc = DIFF_COLOR.get(mod["diff"], C.WHITE)
        print(f"  {C.CYAN}{i+1:<4}{C.RESET}"
              f"{C.BOLD}{mod['label']:<42}{C.RESET}"
              f"{C.DIM}{mod['mitre']:<12}{C.RESET}"
              f"{dc}{mod['diff']}{C.RESET}")
    print()
    print(f"  {C.CYAN}A{C.RESET}   Show all module guides")
    print(f"  {C.CYAN}Q{C.RESET}   Quit")
    print()


def load_module(mod_info: dict):
    """Dynamically import and instantiate a module."""
    module_path, class_name = mod_info["class"]
    try:
        import importlib
        module = importlib.import_module(module_path)
        cls    = getattr(module, class_name)
        return cls()
    except ImportError as e:
        error(f"Failed to import {module_path}: {e}")
        return None
    except Exception as e:
        error(f"Failed to load {class_name}: {e}")
        return None


def run_module(mod_info: dict):
    """Full module lifecycle: overview → setup → run."""
    obj = load_module(mod_info)
    if obj is None:
        return

    print_banner()
    obj.show_overview()
    print()

    choices = ["Run automated setup + demo", "Setup only", "Demo only (skip setup)", "Back to main menu"]
    idx = choose("What would you like to do?", choices)

    if idx == 3:
        return

    if idx in (0, 1):
        ok = obj.prompt_setup()
        if not ok:
            error("Setup failed or was cancelled.")
            if not confirm("Continue to demo anyway?", default=False):
                return

    if idx in (0, 2):
        print()
        obj.prompt_run()

    pause("Demo complete. Press ENTER to return to menu")


def show_all_guides():
    """Paginate through all module guides."""
    for i, mod_info in enumerate(MODULES):
        print_banner()
        obj = load_module(mod_info)
        if obj:
            obj.show_overview()
        if i < len(MODULES) - 1:
            if not confirm(f"\nShow next module guide? ({i+2}/{len(MODULES)})", default=True):
                break


def main():
    # Warn if not root
    if os.geteuid() != 0:
        print()
        warn("Not running as root. Some modules require root privileges.")
        warn("Run: sudo python3 dns_lab.py")
        print()

    while True:
        print_banner()
        print_menu()

        raw = ask("Select module number, A for all guides, or Q to quit", "").strip().upper()

        if raw in ("Q", "QUIT", "EXIT"):
            print()
            info("Lab exited. Remember to restore any network changes.")
            print()
            sys.exit(0)

        if raw == "A":
            show_all_guides()
            continue

        try:
            idx = int(raw) - 1
            if 0 <= idx < len(MODULES):
                run_module(MODULES[idx])
            else:
                warn(f"Enter a number between 1 and {len(MODULES)}")
                time.sleep(1)
        except ValueError:
            warn("Invalid input. Enter a number, A, or Q.")
            time.sleep(1)


if __name__ == "__main__":
    main()
