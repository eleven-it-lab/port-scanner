import argparse
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

KNOWN_PORTS = {
    21: "FTP",
    22: "SSH",
    80: "HTTP / WebFig",
    179: "BGP",
    443: "HTTPS / WebFig-SSL",
    888: "HTTP / WebFig (Alt)",
    2000: "MikroTik Bandwidth Test",
    8291: "Winbox (Default)",
    8728: "RouterOS API",
    8729: "RouterOS API-SSL",
}


def check_single_port(ip, port, timeout=0.4):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        if s.connect_ex((ip, port)) != 0:
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

        return port, label


def scan_range(target_ip, start_port=1, end_port=10000, workers=200, timeout=0.4):
    total_ports = end_port - start_port + 1
    print(f"[*] Scanning {target_ip} ({start_port}-{end_port}) with {workers} threads...")
    start_time = time.time()
    completed = 0
    found = 0

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [
            executor.submit(check_single_port, target_ip, p, timeout)
            for p in range(start_port, end_port + 1)
        ]

        for future in as_completed(futures):
            completed += 1
            result = future.result()

            if result:
                found += 1
                port, label = result
                # Clear the current progress line before printing the discovered port
                sys.stdout.write("\r" + " " * 75 + "\r")
                print(f"    [+] Port {port:<5} -> {label}")

            # Update progress bar every 100 ports (or on final port) to avoid console I/O lag
            if completed % 100 == 0 or completed == total_ports:
                elapsed = time.time() - start_time
                percent = (completed / total_ports) * 100
                rate = completed / elapsed if elapsed > 0 else 0
                eta = (total_ports - completed) / rate if rate > 0 else 0

                status = f"\r    Progress: {percent:5.1f}% ({completed}/{total_ports}) | Elapsed: {elapsed:4.1f}s | ETA: {eta:4.1f}s"
                sys.stdout.write(status)
                sys.stdout.flush()

    # Clear progress line when finished
    sys.stdout.write("\r" + " " * 75 + "\r")
    total_time = time.time() - start_time
    print(f"[*] Completed in {total_time:.2f} seconds ({found} open ports found).")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MikroTik TCP Port & Winbox Finder")
    parser.add_argument("ip", help="Target MikroTik IP address")
    parser.add_argument("--full", action="store_true", help="Scan all 65,535 TCP ports (default: 1-10000)")
    parser.add_argument("--workers", type=int, default=200, help="Concurrent threads (default: 200)")
    parser.add_argument("--timeout", type=float, default=0.4, help="Socket timeout in seconds (default: 0.4)")
    args = parser.parse_args()

    max_port = 65535 if args.full else 10000
    scan_range(args.ip, start_port=1, end_port=max_port, workers=args.workers, timeout=args.timeout)