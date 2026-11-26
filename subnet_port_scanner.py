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
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    80: "HTTP / WebFig",
    179: "BGP",
    443: "HTTPS / WebFig-SSL",
    888: "HTTP / WebFig (Alt)",
    2000: "MikroTik Bandwidth Test",
    8291: "Winbox (Default)",
    8728: "RouterOS API",
    8729: "RouterOS API-SSL",
}

CANARY_PORTS = [22, 80, 443, 2000, 8291, 8728]


def is_host_alive(ip_str, timeout=0.35):
    """Fast L3/L4 check: returns IP if any canary port responds (OPEN or RST) or ICMP replies."""
    for port in CANARY_PORTS:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            code = s.connect_ex((ip_str, port))
            # 0 = OPEN (SYN-ACK), 10061 (Win) / 111 (Linux) = CLOSED (RST -> host is UP!)
            if code in (0, 10061, 111):
                return ip_str

    # Fallback ICMP ping (1 packet, 300ms wait) in case firewall drops all canary ports
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

        label = KNOWN_PORTS.get(port, "Custom / Winbox Candidate")
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


def scan_subnet(cidr, ports, workers=200, timeout=0.4, discover_first=False, csv_file=None):
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        print(f"[!] Invalid CIDR subnet '{cidr}': {e}")
        return

    if network.num_addresses > 4096:
        print(f"[!] Safety stop: {cidr} contains {network.num_addresses} IPs (/20 max recommended).")
        return

    all_hosts = [str(ip) for ip in network.hosts()]
    start_time = time.time()

    # Stage 1: Filter out dead IPs before heavy port sweeps (10k / 65k)
    if discover_first:
        print(f"[*] Stage 1: Discovering live hosts in {cidr} ({len(all_hosts)} IPs)...")
        with ThreadPoolExecutor(max_workers=100) as executor:
            alive_hosts = [h for h in executor.map(is_host_alive, all_hosts) if h]
        alive_hosts.sort(key=lambda ip: tuple(int(o) for o in ip.split(".")))
        print(f"[+] Found {len(alive_hosts)} active hosts in {time.time() - start_time:.2f}s.\n")
        if not alive_hosts:
            return
    else:
        alive_hosts = all_hosts

    # Stage 2: Port scan across active hosts
    tasks = [(ip, port) for ip in alive_hosts for port in ports]
    total_tasks = len(tasks)
    print(f"[*] Scanning {len(alive_hosts)} hosts x {len(ports)} ports = {total_tasks} checks...")

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
    print(f"\n[*] Completed in {time.time() - start_time:.2f}s. Grouped Summary:")

    sorted_ips = sorted(grouped_results.keys(), key=lambda ip: tuple(int(o) for o in ip.split(".")))
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
    parser = argparse.ArgumentParser(description="Subnet TCP Port Scanner for MikroTik / ISP Management")
    parser.add_argument("cidr", help="Target subnet in CIDR notation (e.g., 192.0.2.0/24)")
    parser.add_argument("-p", "--ports", default="22,80,443,8291,8728", help="Ports or ranges (e.g., 22,8291 or 1-10000)")
    parser.add_argument("--top10k", action="store_true", help="Auto-discover live hosts first, then scan ports 1-10000")
    parser.add_argument("--full", action="store_true", help="Auto-discover live hosts first, then scan all 65535 ports")
    parser.add_argument("--workers", type=int, default=200, help="Concurrent threads (default: 200)")
    parser.add_argument("--timeout", type=float, default=0.4, help="Socket timeout in seconds (default: 0.4)")
    parser.add_argument("--csv", metavar="FILE", help="Export scan results to a CSV file (e.g., audit.csv)")
    args = parser.parse_args()

    if args.full:
        target_ports = list(range(1, 65536))
        discover = True
    elif args.top10k:
        target_ports = list(range(1, 10001))
        discover = True
    else:
        target_ports = parse_ports(args.ports)
        discover = len(target_ports) > 50

    scan_subnet(
        args.cidr,
        target_ports,
        workers=args.workers,
        timeout=args.timeout,
        discover_first=discover,
        csv_file=args.csv,
    )