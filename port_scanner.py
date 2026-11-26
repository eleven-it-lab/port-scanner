import argparse
import csv
import ipaddress
import socket
import subprocess
import sys
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

KNOWN_PORTS = {
    # Core & Legacy Management
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP / WebFig",
    110: "POP3",
    143: "IMAP",
    179: "BGP",
    389: "LDAP",
    443: "HTTPS / WebFig-SSL",
    445: "SMB / Windows File Share",
    465: "SMTPS",
    514: "Syslog (TCP) / RSH",
    587: "SMTP Submission",
    636: "LDAPS",
    873: "rsync",
    888: "HTTP / WebFig (Alt)",
    993: "IMAPS",
    995: "POP3S",

    # VPN & Tunneling (TCP)
    1194: "OpenVPN",
    1723: "PPTP VPN",
    8443: "HTTPS (Alt) / Web Management",

    # MikroTik RouterOS & ISP Specific
    2000: "MikroTik Bandwidth Test",
    8080: "HTTP Proxy / Alt Web",
    8081: "HTTP (Alt) / OLT Web",
    8291: "Winbox (Default)",
    8728: "RouterOS API",
    8729: "RouterOS API-SSL",

    # OLT / TR-069 / CWMP & ISP Provisioning
    7547: "TR-069 / CWMP (ACS)",
    9090: "Web Console / Cockpit / Alt Web",
    9100: "Raw Print / JetDirect",

    # Linux, Databases & NMS / Monitoring
    3000: "Grafana / Dev Web",
    3306: "MySQL / MariaDB",
    3389: "RDP (Windows Remote Desktop)",
    5000: "UPnP / Flask / Dev Web",
    5432: "PostgreSQL",
    5900: "VNC Remote Desktop",
    6379: "Redis",
    8000: "Django / Dev HTTP",
    8086: "InfluxDB",
    9000: "Portainer / SonarQube / PHP-FPM",
    9200: "Elasticsearch",
    10050: "Zabbix Agent",
    10051: "Zabbix Server / Trapper",
}

CANARY_PORTS = [22, 23, 80, 443, 179, 2000, 8080, 8291, 8728]


def is_host_alive(ip_str, timeout=0.35):
    """Fast L3/L4 check: returns IP if any canary port responds (OPEN or RST) or ICMP replies."""
    for port in CANARY_PORTS:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            code = s.connect_ex((ip_str, port))
            if code in (0, 10061, 111):  # 0=OPEN, 10061/111=RST (host stack is alive)
                return ip_str

    param = "-n" if sys.platform.startswith("win") else "-c"
    wait_flag = "-w" if sys.platform.startswith("win") else "-W"
    wait_val = "300" if sys.platform.startswith("win") else "1"
    res = subprocess.run(
        ["ping", param, "1", wait_flag, wait_val, ip_str],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return ip_str if res.returncode == 0 else None


def check_target(ip_str, port, timeout=0.4):
    """Checks a single (IP, port) pair and grabs passive banner if open."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        if s.connect_ex((ip_str, port)) != 0:
            return None

        label = KNOWN_PORTS.get(port, "Custom Port")
        try:
            s.settimeout(0.3)
            banner = s.recv(256)
            if b"ROSSSH" in banner or banner.startswith(b"SSH-"):
                label = f"SSH ({banner.decode(errors='ignore').strip()})"
            elif banner == b"\x01\x00\x00\x00":
                label = "MikroTik Bandwidth Test"
        except Exception:
            pass

        return ip_str, port, label


def parse_ports(port_arg):
    """Converts '22,8291' or '1-10000' into a sorted list of unique integer ports."""
    ports = set()
    for part in port_arg.split(","):
        part = part.strip()
        if "-" in part:
            start, end = map(int, part.split("-", 1))
            ports.update(range(start, end + 1))
        elif part:
            ports.add(int(part))
    return sorted(ports)


def extract_positional_ports(positional_args):
    """Separates target IPs/CIDRs from optional trailing <start_port> <end_port> or <single_port>."""
    if len(positional_args) >= 3 and positional_args[-2].isdigit() and positional_args[-1].isdigit():
        start_p, end_p = int(positional_args[-2]), int(positional_args[-1])
        if 1 <= start_p <= end_p <= 65535:
            return positional_args[:-2], start_p, end_p

    if len(positional_args) >= 2 and positional_args[-1].isdigit():
        single_p = int(positional_args[-1])
        if 1 <= single_p <= 65535:
            return positional_args[:-1], single_p, single_p

    return positional_args, None, None


def expand_targets(target_tokens, file_path=None):
    """Expands single IPs, CIDR subnets, and target files into a deduplicated IP list."""
    raw_items = list(target_tokens)

    if file_path:
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                for line in f:
                    clean = line.split("#", 1)[0].strip()
                    if clean:
                        raw_items.extend(clean.replace(",", " ").split())
        except FileNotFoundError:
            print(f"[!] Target file not found: {file_path}")
            sys.exit(1)

    ips = []
    seen = set()

    for token in raw_items:
        try:
            if "/" in token:
                net = ipaddress.ip_network(token, strict=False)
                if net.num_addresses > 4096:
                    print(f"[!] Safety stop: {token} contains {net.num_addresses} IPs (/20 max).")
                    sys.exit(1)
                for host in net.hosts():
                    ip_str = str(host)
                    if ip_str not in seen:
                        seen.add(ip_str)
                        ips.append(ip_str)
            else:
                ip_str = str(ipaddress.ip_address(token))
                if ip_str not in seen:
                    seen.add(ip_str)
                    ips.append(ip_str)
        except ValueError:
            print(f"[!] Invalid IP or CIDR target: '{token}'")
            sys.exit(1)

    return ips


def run_scan(target_ips, ports, workers=200, timeout=0.4, csv_file=None):
    if not target_ips:
        print("[!] No valid targets provided. Pass IP(s), CIDR(s), or -f <file>.")
        return

    start_time = time.time()

    # Auto-enable Stage 1 host discovery only for multi-host sweeps > 50 ports
    if len(target_ips) > 1 and len(ports) > 50:
        print(f"[*] Stage 1: Checking liveness across {len(target_ips)} hosts...")
        with ThreadPoolExecutor(max_workers=min(100, len(target_ips))) as executor:
            alive_hosts = [h for h in executor.map(is_host_alive, target_ips) if h]
        print(f"[+] {len(alive_hosts)}/{len(target_ips)} hosts active in {time.time() - start_time:.2f}s.\n")
        if not alive_hosts:
            return
    else:
        alive_hosts = target_ips

    tasks = [(ip, port) for ip in alive_hosts for port in ports]
    total_tasks = len(tasks)
    print(f"[*] Scanning {len(alive_hosts)} host(s) x {len(ports)} port(s) = {total_tasks} checks...")

    scan_start = time.time()
    completed = 0
    grouped_results = defaultdict(list)

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(check_target, ip, port, timeout) for ip, port in tasks]

        for future in as_completed(futures):
            completed += 1
            hit = future.result()

            if hit:
                ip_str, port, label = hit
                grouped_results[ip_str].append((port, label))
                sys.stdout.write("\r" + " " * 80 + "\r")
                print(f"    [+] {ip_str:<15} | Port {port:<5} -> {label}")

            if completed % 100 == 0 or completed == total_tasks:
                elapsed = time.time() - scan_start
                percent = (completed / total_tasks) * 100
                rate = completed / elapsed if elapsed > 0 else 0
                eta = (total_tasks - completed) / rate if rate > 0 else 0
                sys.stdout.write(
                    f"\r    Progress: {percent:5.1f}% ({completed}/{total_tasks}) | Elapsed: {elapsed:4.1f}s | ETA: {eta:4.1f}s"
                )
                sys.stdout.flush()

    sys.stdout.write("\r" + " " * 80 + "\r")
    print(f"\n[*] Completed in {time.time() - start_time:.2f}s. Summary:")

    sorted_ips = sorted(grouped_results.keys(), key=lambda ip: tuple(int(o) for o in ip.split(".")))
    if not sorted_ips:
        print("    No open ports found.")
    for ip_str in sorted_ips:
        ports_str = ", ".join(f"{p} ({lbl})" for p, lbl in sorted(grouped_results[ip_str]))
        print(f"    {ip_str:<15} -> {ports_str}")

    if csv_file and grouped_results:
        scan_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(csv_file, mode="w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["IP Address", "Port", "Service", "Scanned At"])
            for ip_str in sorted_ips:
                for port, label in sorted(grouped_results[ip_str]):
                    writer.writerow([ip_str, port, label, scan_timestamp])
        print(f"\n[+] Results exported to {csv_file}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Unified TCP Port Scanner (Single IP, CIDR, or Multi-IP)")
    parser.add_argument("args", nargs="*", help="Target IP(s)/CIDR(s) optionally followed by <start_port> <end_port>")
    parser.add_argument("-f", "--file", metavar="FILE", help="Text file containing target IPs or CIDRs")
    parser.add_argument("-p", "--ports", default="22,80,443,8291,8728", help="Comma/range ports (default: 22,80,443,8291,8728)")
    parser.add_argument("--top10k", action="store_true", help="Scan ports 1-10000")
    parser.add_argument("--full", action="store_true", help="Scan all 65535 TCP ports")
    parser.add_argument("--workers", type=int, default=200, help="Concurrent threads (default: 200)")
    parser.add_argument("--timeout", type=float, default=0.4, help="Socket timeout in seconds (default: 0.4)")
    parser.add_argument("--csv", metavar="FILE", help="Export scan results to CSV")
    cli = parser.parse_args()

    target_tokens, start_port, end_port = extract_positional_ports(cli.args)
    targets = expand_targets(target_tokens, file_path=cli.file)

    if cli.full:
        ports_to_scan = list(range(1, 65536))
    elif cli.top10k:
        ports_to_scan = list(range(1, 10001))
    elif start_port is not None and end_port is not None:
        ports_to_scan = list(range(start_port, end_port + 1))
    else:
        ports_to_scan = parse_ports(cli.ports)

    run_scan(targets, ports_to_scan, workers=cli.workers, timeout=cli.timeout, csv_file=cli.csv)