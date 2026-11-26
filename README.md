# port-scanner

Lightweight, zero-dependency Python network diagnostics toolkit built for ISP NOC troubleshooting, service discovery, and locating custom management ports (such as moved MikroTik Winbox or SSH ports).

## Toolkit Overview

| Script | Use Case | Target Input | Key Capabilities |
| :--- | :--- | :--- | :--- |
| **`single_ip_port_scanner.py`** | Deep-dive troubleshooting on a single router | Single IP (`192.0.2.1`) | Fast `1–10,000` or `--full` (`1–65,535`) TCP sweep, passive banner grabbing, live `%` & ETA progress |
| **`subnet_port_scanner.py`** | Auditing an entire POP or management subnet | CIDR block (`192.0.2.0/24`) | Two-stage host discovery (`SYN-ACK`/`RST`/ICMP), numerical IP sorting, `--csv` export |
| **`multi_ip_port_scanner.py`** | Auditing scattered core, POP, or branch routers | Text file (`-f targets.txt`) or IP list | Comment-aware file parser (`#`), duplicate/typo filtering, reuses core scanner engine |

## Features

* **Zero External Dependencies:** Runs purely on the Python 3.8+ standard library (`socket`, `concurrent.futures`, `ipaddress`, `argparse`, `csv`)—ready to execute on restricted jump servers or NOC workstations without `pip install`.
* **Passive Banner Grabbing:** Inspects initial TCP greeting bytes (`s.recv(256)`) to identify `SSH` (`ROSSSH`) and MikroTik Bandwidth Test (`btest`) services even when moved to non-standard ports, while flagging silent open ports as Winbox candidates.
* **Two-Stage Host Discovery:** Automatically filters unreachable/unallocated IPs during `--top10k` and `--full` sweeps before launching heavy port checks, cutting subnet scan times by up to 85–90%.
* **In-Place Live Progress & ETA:** Displays real-time completion percentage, elapsed time, and estimated time remaining without console clutter.

## Quick Start

Clone the repository and run any tool directly with Python 3.8+:

```bash
git clone [https://github.com/eleven-it-lab/port-scanner.git](https://github.com/eleven-it-lab/port-scanner.git)
cd port-scanner
```

### 1. Single IP Port Scanner (`single_ip_port_scanner.py`)

```bash
# Fast scan (ports 1–10,000)
python single_ip_port_scanner.py 192.0.2.1

# Full sweep (all 65,535 TCP ports)
python single_ip_port_scanner.py 192.0.2.1 --full

# Custom worker threads and socket timeout
python single_ip_port_scanner.py 192.0.2.1 --full --workers 250 --timeout 0.3
```

### 2. Subnet Port Scanner (`subnet_port_scanner.py`)

```bash
# Audit default MikroTik management ports (22, 80, 443, 8291, 8728) across a /24
python subnet_port_scanner.py 192.0.2.0/24

# Check custom management ports and export results to CSV
python subnet_port_scanner.py 192.0.2.0/24 -p 22,3352,8291,9909 --csv subnet_audit.csv

# Discover active hosts first, then scan ports 1–10,000
python subnet_port_scanner.py 192.0.2.0/28 --top10k --csv pop_audit.csv
```

### 3. Multi-IP Port Scanner (`multi_ip_port_scanner.py`)

Create a `targets.txt` file with one IP per line (`#` inline comments are supported):

```text
# Core & POP Routers
192.0.2.10      # Core Router 01
192.0.2.14      # Distribution Switch
198.51.100.25   # Remote POP Gateway
```

Run the audit against your target list:

```bash
# Scan default management ports from targets.txt and export to CSV
python multi_ip_port_scanner.py -f targets.txt --csv router_audit.csv

# Hunt for non-standard Winbox ports (1–10,000) across listed routers
python multi_ip_port_scanner.py -f targets.txt --top10k --csv winbox_hunt.csv

# Scan inline IPs directly without a file
python multi_ip_port_scanner.py 192.0.2.10 198.51.100.25 -p 22,8291,8728
```

## Operational Notice

This toolkit is intended strictly for authorized network administration, NOC diagnostics, and isolated lab testing. Multi-port TCP sweeps generate firewall connection-tracking entries, Syslog events, and NetFlow records—always verify authorization and tune `--workers` and `--timeout` to respect device rate limits.