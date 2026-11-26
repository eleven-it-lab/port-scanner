# port-scanner

Unified, zero-dependency Python network diagnostics CLI tool built for ISP NOC troubleshooting, service discovery, and locating custom management ports (such as moved MikroTik Winbox or SSH ports) across single hosts, CIDR subnets, or custom router lists.

## Requirements

* **Python 3.8+** (Windows, Linux, or macOS)
* No third-party packages required

## Installation

```bash
git clone https://github.com/eleven-it-lab/port-scanner
cd port-scanner
```

## Usage

### Syntax

```bash
python port_scanner.py [target(s)...] [start_port end_port | single_port] [options]
```

### 1. Single-IP Diagnostics (Custom Port Hunting)

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
python port_scanner.py -f targets.txt 1 10000 --workers 250 --timeout 0.3 --csv port_hunt.csv

# Combine inline IPs, CIDRs, and custom port lists
python port_scanner.py 192.0.2.10 198.51.100.25 -p 22,3352,8291,8728,9909
```