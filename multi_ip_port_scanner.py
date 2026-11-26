import argparse
import csv
import ipaddress
import sys
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# Reuse the core socket engine, host discovery, and port parser from subnet_port_scanner.py
from subnet_port_scanner import check_target, is_host_alive, parse_ports


def load_targets(file_path=None, cli_ips=None):
    """Loads, validates, and deduplicates target IPs from a text file and/or CLI arguments."""
    raw_entries = []

    if file_path:
        try:
            with open(file_path, mode="r", encoding="utf-8") as f:
                for line_num, line in enumerate(f, start=1):
                    # Strip inline comments (# ...) and whitespace
                    clean = line.split("#", 1)[0].strip()
                    if not clean:
                        continue
                    # Support comma-separated or whitespace-separated IPs on a single line
                    for token in clean.replace(",", " ").split():
                        raw_entries.append((token, f"{file_path}:{line_num}"))
        except FileNotFoundError:
            print(f"[!] Target file not found: {file_path}")
            sys.exit(1)

    if cli_ips:
        for ip_item in cli_ips:
            raw_entries.append((ip_item.strip(), "CLI argument"))

    valid_ips = []
    seen = set()

    for candidate, source in raw_entries:
        try:
            ip_obj = ipaddress.ip_address(candidate)
            ip_str = str(ip_obj)
            if ip_str not in seen:
                seen.add(ip_str)
                valid_ips.append(ip_str)
        except ValueError:
            print(f"[!] Skipping invalid IP '{candidate}' ({source})")

    return valid_ips


def scan_multi_ips(target_ips, ports, workers=200, timeout=0.4, discover_first=False, csv_file=None):
    if not target_ips:
        print("[!] No valid target IPs provided. Use -f <file> or pass IPs directly.")
        return

    start_time = time.time()

    # Optional Stage 1: Filter unreachable IPs before heavy port sweeps (--top10k / --full)
    if discover_first:
        print(f"[*] Stage 1: Checking liveness across {len(target_ips)} target IPs...")
        with ThreadPoolExecutor(max_workers=min(100, len(target_ips))) as executor:
            alive_hosts = [h for h in executor.map(is_host_alive, target_ips) if h]
        print(f"[+] {len(alive_hosts)}/{len(target_ips)} targets responded in {time.time() - start_time:.2f}s.\n")
        if not alive_hosts:
            return
    else:
        alive_hosts = target_ips

    tasks = [(ip, port) for ip in alive_hosts for port in ports]
    total_tasks = len(tasks)
    print(f"[*] Scanning {len(alive_hosts)} targets x {len(ports)} ports = {total_tasks} checks...")

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
    parser = argparse.ArgumentParser(description="Multi-IP TCP Port Scanner from File or CLI List")
    parser.add_argument("ips", nargs="*", help="Optional target IPs passed directly on the command line")
    parser.add_argument("-f", "--file", metavar="FILE", help="Path to text file containing target IPs (one per line)")
    parser.add_argument("-p", "--ports", default="22,80,443,8291,8728", help="Ports or ranges (default: 22,80,443,8291,8728)")
    parser.add_argument("--top10k", action="store_true", help="Filter live hosts first, then scan ports 1-10000")
    parser.add_argument("--full", action="store_true", help="Filter live hosts first, then scan all 65535 ports")
    parser.add_argument("--workers", type=int, default=200, help="Concurrent threads (default: 200)")
    parser.add_argument("--timeout", type=float, default=0.4, help="Socket timeout in seconds (default: 0.4)")
    parser.add_argument("--csv", metavar="FILE", help="Export scan results to a CSV file (e.g., audit.csv)")
    args = parser.parse_args()

    targets = load_targets(file_path=args.file, cli_ips=args.ips)

    if args.full:
        target_ports = list(range(1, 65536))
        discover = True
    elif args.top10k:
        target_ports = list(range(1, 10001))
        discover = True
    else:
        target_ports = parse_ports(args.ports)
        discover = len(target_ports) > 50

    scan_multi_ips(
        targets,
        target_ports,
        workers=args.workers,
        timeout=args.timeout,
        discover_first=discover,
        csv_file=args.csv,
    )