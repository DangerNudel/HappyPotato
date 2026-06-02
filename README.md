# HappyPotato

A modular DNS attack lab for hands-on instruction in DNS-based offensive techniques and corresponding defenses. Built for authorized, isolated lab and classroom use.

> ⚠️ **Authorized use only.** Every technique in this lab is destructive or disruptive by design. Run it exclusively against systems you own or are explicitly authorized to test, on an isolated network. Do not point any module at production infrastructure or third-party resolvers.

## Overview

HappyPotato packages eight self-contained DNS attack modules behind a common framework and a terminal UI. Each module demonstrates a distinct technique, maps the activity to observable behavior, and can be launched independently for guided exercises or chained for a full attack walkthrough.

## Modules

| # | Module | Technique |
|---|--------|-----------|
| 01 | `m01_cache_poison.py` | DNS cache poisoning |
| 02 | `m02_arp_spoof.py` | ARP spoofing / on-path positioning |
| 03 | `m03_rogue_dns.py` | Rogue DNS server |
| 04 | `m04_rebinding.py` | DNS rebinding |
| 05 | `m05_nxdomain.py` | NXDOMAIN abuse / flooding |
| 06 | `m06_tunnel.py` | DNS tunneling (covert channel / exfiltration) |
| 07 | `m07_firewall_bypass.py` | DNS-based firewall / egress bypass |
| 08 | `m08_kill_chain.py` | End-to-end kill chain combining prior modules |

## Repository Layout

```
base.py                 Shared base classes / common module scaffolding
dns_core.py             Core DNS packet handling and helpers
dns_lab.py              Lab orchestration / entry point
ui.py                   Terminal interface
prereqs.py              Dependency and environment checks
setup.sh                Environment setup
m01–m08_*.py            Attack modules
run_module_1–8.sh       Per-module launchers
DNS_Attack_Lab_Guide.docx   Instructor / student lab guide
LICENSE                 MIT
```

## Requirements

- Linux host (Kali or Ubuntu recommended) on an isolated lab network
- Python 3
- Root / `sudo` for modules that craft or inject packets
- See `prereqs.py` for the dependency check

## Setup

```bash
git clone https://github.com/jhenrysec/HappyPotato.git
cd HappyPotato
chmod +x setup.sh run_module_*.sh
sudo ./setup.sh
python3 prereqs.py    # verify environment
```

## Usage

Launch the lab UI:

```bash
sudo python3 dns_lab.py
```

Or run an individual module directly:

```bash
sudo ./run_module_1.sh    # cache poisoning
sudo ./run_module_6.sh    # DNS tunneling
```

Work through the modules in order, or jump to a specific technique. The full procedure, expected output, and defensive discussion are in `DNS_Attack_Lab_Guide.docx`.

## Educational Use

This project exists to teach how DNS attacks work and how to detect and defend against them. It is intended for cybersecurity training, CTF prep, and curriculum delivery in controlled environments. The author assumes no liability for misuse.

## License

MIT — see [LICENSE](LICENSE).
