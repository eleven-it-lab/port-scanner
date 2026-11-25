# port-scanner

Lightweight, zero-dependency Python network diagnostics toolkit built for ISP NOC troubleshooting and service discovery.

## Tools Included

* **`single_ip_port_scanner.py`** — Multi-threaded TCP port scanner (`1–65,535`) with passive banner grabbing (`SSH`, MikroTik Bandwidth Test), standard ISP/RouterOS service mapping, and live progress/ETA tracking to locate moved management ports (such as custom Winbox ports).
* **`subnet_port_scanner.py`** *(Planned)* — Scan entire CIDR subnets for exposed management services.
* **`multi_ip_port_scanner.py`** *(Planned)* — Audit a custom list or file of target router IPs in bulk.

## Usage (`single_ip_port_scanner.py`)

Requires **Python 3.8+** (standard library only, no third-party packages).

```bash
# Fast scan (ports 1–10,000)
python3 single_ip_port_scanner.py 192.0.2.1

# Full sweep (all 65,535 TCP ports)
python3 single_ip_port_scanner.py 192.0.2.1 --full

# Custom thread count and socket timeout
python3 single_ip_port_scanner.py 192.0.2.1 --full --workers 250 --timeout 0.3