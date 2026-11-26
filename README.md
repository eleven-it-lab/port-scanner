# port-scanner

Unified, zero-dependency Python network diagnostics CLI tool built for ISP NOC troubleshooting, service discovery, and locating custom management ports (such as moved MikroTik Winbox or SSH ports) across single hosts, CIDR subnets, or custom router lists.

## Key Capabilities

* **Polymorphic Target Engine:** Automatically handles single IPv4 addresses (`192.0.2.1`), CIDR subnets (`192.0.2.0/24`), mixed inline lists, and comment-annotated text files (`-f targets.txt`) from one command-line interface.
* **Zero External Dependencies:** Built strictly on the Python 3.8+ standard library (`socket`, `concurrent.futures`, `ipaddress`, `argparse`, `csv`, `subprocess`)—ready to run on restricted jump hosts or NOC workstations without `pip install`.
* **Two-Stage Host Discovery:** Automatically filters unreachable/unallocated IPs (`SYN-ACK`, `RST`, and ICMP fallback) before executing heavy multi-host sweeps (`>50` ports, `--top10k`, or `--full`), cutting subnet audit times by 85–90%.
* **Passive Banner Grabbing & Service Mapping:** Inspects initial TCP greeting bytes (`s.recv(256)`) to identify `SSH` (`ROSSSH`) and MikroTik Bandwidth Test (`btest`) services even on non-standard ports, maps standard ISP/RouterOS ports (`21, 22, 23, 80, 179, 443, 888, 2000, 8291, 8728, 8729`), and flags silent open ports as Winbox candidates.
* **Live Progress & CSV Reporting:** Displays real-time completion percentage, elapsed seconds, and ETA in place without console clutter, prints a numerically sorted per-IP summary at completion, and optionally exports timestamped results via `--csv`.

## Requirements

* **Python 3.8+** (Windows, Linux, or macOS)
* No third-party packages required

## Installation

```bash
git clone [https://github.com/eleven-it-lab/port-scanner.git](https://github.com/eleven-it-lab/port-scanner.git)
cd port-scanner
```

## Usage

### Syntax

```bash
python port_scanner.py [target(s)...] [start_port end_port | single_port] [options]
```

### 1. Single-IP Diagnostics (Winbox / Custom Port Hunting)

```bash
# Default management ports (22, 80, 443, 8291, 8728)
python port_scanner.py 192.0.2.1

# Custom port range (e.g., ports 1 to 10,000)
python port_scanner.py 192.0.2.1 1 10000

# Shorthand for ports 1–10,000
python port_scanner.py 192.0.2.1 --top10k

# Full sweep across all 65,535 TCP ports
python port_scanner.py 192.0.2.1 --full

# Check a single specific port
python port_scanner.py 192.0.2.1 8291
```

### 2. Subnet CIDR Audits

```bash
# Audit default MikroTik management ports across a /24 block
python port_scanner.py 192.0.2.0/24

# Scan a custom port range across a /24 and export to CSV
python port_scanner.py 192.0.2.0/24 8000 9999 --csv subnet_audit.csv

# Auto-discover active hosts in a /28 first, then scan ports 1–10,000
python port_scanner.py 192.0.2.0/28 --top10k --csv pop_audit.csv
```

### 3. Multi-IP & File-Based Audits

Create a `targets.txt` file containing IPs and/or CIDR blocks (`#` inline comments and blank lines are ignored):

```text
# Core & POP Routers
192.0.2.10      # Core Router 01
192.0.2.14      # Distribution Switch
198.51.100.0/29 # Remote POP Block
```

Run against the file or mixed inline arguments:

```bash
# Audit targets from file and export timestamped CSV report
python port_scanner.py -f targets.txt --csv router_audit.csv

# Scan ports 1–10,000 across targets.txt with tuned thread count and timeout
python port_scanner.py -f targets.txt 1 10000 --workers 250 --timeout 0.3 --csv winbox_hunt.csv

# Combine inline IPs, CIDRs, and custom port lists
python port_scanner.py 192.0.2.10 198.51.100.25 -p 22,3352,8291,8728,9909
```

## CLI Reference

| Flag / Argument | Description | Default |
| :--- | :--- | :--- |
| `args` | Target IP(s) or CIDR(s), optionally followed by `<start_port> <end_port>` or `<port>` | Required (unless `-f` is used) |
| `-f`, `--file FILE` | Path to a text file listing target IPs and/or CIDRs | `None` |
| `-p`, `--ports PORTS` | Comma-separated ports or ranges (e.g., `22,8291,8000-8010`) | `22,80,443,8291,8728` |
| `--top10k` | Scan TCP ports `1–10,000` | `False` |
| `--full` | Scan all TCP ports `1–65,535` | `False` |
| `--workers N` | Maximum concurrent worker threads | `200` |
| `--timeout SEC` | TCP socket connection timeout in seconds | `0.4` |
| `--csv FILE` | Export sorted results (`IP Address, Port, Service, Scanned At`) to CSV | `None` |

## Performance Tuning Guidelines

* **LAN / Direct Core Fiber (`<5 ms` RTT):** `--workers 350 --timeout 0.25`
* **Nationwide ISP / POP Links (`10–30 ms` RTT):** `--workers 200 --timeout 0.4` (default)
* **High-Latency WAN / CPE Links:** `--workers 150 --timeout 0.6`

## Operational Notice

This toolkit is intended strictly for authorized network administration, NOC diagnostics, and isolated lab testing. Multi-port TCP sweeps generate firewall connection-tracking entries, Syslog events, and NetFlow/IPFIX records—always verify change authorization and tune `--workers` and `--timeout` to respect device rate limits.