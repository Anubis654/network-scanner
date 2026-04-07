#!/usr/bin/env python3
"""
============================================================
  Network Scanner Tool
  Author : Your Name
  GitHub : github.com/yourusername
  Purpose: Reconnaissance tool for authorized network auditing
  Skills : Python | Networking | Cybersecurity (Security+)
============================================================

LEGAL DISCLAIMER:
  Only use this tool on networks you own or have
  explicit written permission to test.
"""

import socket
import ipaddress
import concurrent.futures
import datetime
import sys
import os


# ── COMMON PORTS & SERVICES ────────────────────────────────
COMMON_PORTS = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    135:  "RPC",
    139:  "NetBIOS",
    143:  "IMAP",
    443:  "HTTPS",
    445:  "SMB",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
}


# ── BANNER ─────────────────────────────────────────────────
def print_banner():
    banner = """
╔══════════════════════════════════════════════════════╗
║           NETWORK SCANNER v1.0                       ║
║           Python | Networking | Security             ║
║  [ Only scan networks you own or have permission ]   ║
╚══════════════════════════════════════════════════════╝
"""
    print(banner)


# ── PORT SCANNER ───────────────────────────────────────────
def scan_port(host: str, port: int, timeout: float = 0.5) -> dict:
    """
    Attempts a TCP connection to host:port.
    Returns a dict with port status and service name.
    """
    result = {
        "port":    port,
        "status":  "closed",
        "service": COMMON_PORTS.get(port, "unknown"),
        "banner":  ""
    }

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        connection = sock.connect_ex((host, port))

        if connection == 0:
            result["status"] = "open"
            # Try to grab a banner from the service
            try:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
                result["banner"] = banner[:80]   # first 80 chars only
            except Exception:
                pass

        sock.close()

    except socket.gaierror:
        result["status"] = "error"
    except Exception:
        pass

    return result


# ── HOST SCANNER ───────────────────────────────────────────
def is_host_alive(ip: str, timeout: float = 1.0) -> bool:
    """
    Checks if a host is alive by trying port 80 and 443.
    (ICMP ping is blocked in many environments, TCP is more reliable)
    """
    for port in [80, 443, 22, 135]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            if sock.connect_ex((ip, port)) == 0:
                sock.close()
                return True
            sock.close()
        except Exception:
            pass
    return False


def resolve_hostname(ip: str) -> str:
    """Tries to resolve IP to hostname using reverse DNS."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "N/A"


# ── NETWORK RANGE SCANNER ──────────────────────────────────
def discover_hosts(network: str) -> list:
    """
    Scans a CIDR range (e.g. 192.168.1.0/24) and returns
    a list of alive hosts.
    """
    print(f"\n[*] Discovering hosts in {network} ...")
    alive_hosts = []

    try:
        net = ipaddress.IPv4Network(network, strict=False)
    except ValueError as e:
        print(f"[!] Invalid network range: {e}")
        return []

    hosts = list(net.hosts())
    print(f"[*] Scanning {len(hosts)} addresses ...\n")

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(is_host_alive, str(ip)): str(ip) for ip in hosts}

        for i, future in enumerate(concurrent.futures.as_completed(futures)):
            ip = futures[future]
            try:
                if future.result():
                    hostname = resolve_hostname(ip)
                    alive_hosts.append({"ip": ip, "hostname": hostname})
                    print(f"  [+] HOST UP  →  {ip:16}  ({hostname})")
            except Exception:
                pass

            # Simple progress indicator
            if (i + 1) % 50 == 0:
                print(f"  [*] Progress: {i+1}/{len(hosts)} checked ...")

    print(f"\n[*] Found {len(alive_hosts)} alive host(s)")
    return alive_hosts


# ── FULL HOST SCAN ─────────────────────────────────────────
def scan_host(host: str, ports: list = None) -> dict:
    """
    Scans a single host for open ports using threading.
    Returns a full result dict.
    """
    if ports is None:
        ports = list(COMMON_PORTS.keys())

    print(f"\n[*] Scanning {host} — {len(ports)} ports ...")

    open_ports = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(scan_port, host, p): p for p in ports}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result["status"] == "open":
                open_ports.append(result)
                print(f"  [+] OPEN  {result['port']:5}/tcp  →  {result['service']}")

    open_ports.sort(key=lambda x: x["port"])

    return {
        "host":       host,
        "hostname":   resolve_hostname(host),
        "scan_time":  datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "open_ports": open_ports,
        "total_open": len(open_ports),
    }


# ── REPORT GENERATOR ───────────────────────────────────────
def generate_report(results: list, output_file: str = "scan_report.txt"):
    """
    Writes a clean scan report to a .txt file.
    """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(output_file, "w") as f:
        f.write("=" * 60 + "\n")
        f.write("  NETWORK SCAN REPORT\n")
        f.write(f"  Generated: {timestamp}\n")
        f.write("=" * 60 + "\n\n")

        if not results:
            f.write("No results to report.\n")
            return

        for r in results:
            f.write(f"HOST     : {r['host']}\n")
            f.write(f"HOSTNAME : {r['hostname']}\n")
            f.write(f"SCANNED  : {r['scan_time']}\n")
            f.write(f"OPEN PORTS ({r['total_open']} found):\n")

            if r["open_ports"]:
                f.write(f"  {'PORT':<8} {'SERVICE':<15} {'BANNER'}\n")
                f.write(f"  {'-'*50}\n")
                for p in r["open_ports"]:
                    f.write(f"  {str(p['port'])+'/ tcp':<8} {p['service']:<15} {p['banner']}\n")
            else:
                f.write("  No open ports found.\n")

            f.write("\n" + "-" * 60 + "\n\n")

    print(f"\n[+] Report saved to: {output_file}")


# ── MAIN ───────────────────────────────────────────────────
def main():
    print_banner()

    print("Select scan mode:")
    print("  [1] Scan a single host")
    print("  [2] Discover hosts in a network range (CIDR)")
    print("  [3] Exit")

    choice = input("\nEnter choice (1/2/3): ").strip()

    results = []

    if choice == "1":
        host = input("Enter target IP or hostname: ").strip()
        if not host:
            print("[!] No host entered.")
            return

        custom = input("Scan common ports only? (y/n): ").strip().lower()
        if custom == "n":
            try:
                start = int(input("Start port: "))
                end   = int(input("End port:   "))
                ports = list(range(start, end + 1))
            except ValueError:
                print("[!] Invalid port range. Using common ports.")
                ports = list(COMMON_PORTS.keys())
        else:
            ports = list(COMMON_PORTS.keys())

        result = scan_host(host, ports)
        results.append(result)

    elif choice == "2":
        network = input("Enter network range (e.g. 192.168.1.0/24): ").strip()
        hosts   = discover_hosts(network)

        if not hosts:
            print("[!] No alive hosts found.")
            return

        scan_all = input("\nScan open ports on all discovered hosts? (y/n): ").strip().lower()
        if scan_all == "y":
            for h in hosts:
                result = scan_host(h["ip"])
                results.append(result)

    elif choice == "3":
        print("Exiting. Stay ethical.")
        sys.exit(0)

    else:
        print("[!] Invalid choice.")
        return

    # Summary
    print("\n" + "=" * 50)
    print("SCAN COMPLETE")
    print("=" * 50)
    for r in results:
        print(f"  {r['host']:16} — {r['total_open']} open port(s)")

    # Save report
    save = input("\nSave report to file? (y/n): ").strip().lower()
    if save == "y":
        fname = input("Filename (default: scan_report.txt): ").strip()
        if not fname:
            fname = "scan_report.txt"
        generate_report(results, fname)


if __name__ == "__main__":
    main()
