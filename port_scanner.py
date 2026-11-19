"""
Simple TCP Port Scanner - learning project
Scans a target host for open TCP ports and tries to grab the service banner.

Usage:
    python port_scanner.py 127.0.0.1
    python port_scanner.py scanme.nmap.org --ports 21,22,80,443
    python port_scanner.py 192.168.1.1 --start 1 --end 1024

LEGAL: Only scan systems you own or have written permission to test.
"""
import argparse
import socket
import sys
from datetime import datetime

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 8080: "HTTP-Alt",
}

def grab_banner(sock):
    """Try to read a short banner the service sends on connect."""
    try:
        sock.settimeout(1.5)
        data = sock.recv(1024)
        return data.decode(errors="ignore").strip()
    except Exception:
        return ""

def scan_port(target, port, timeout=1.0):
    """Return (is_open, banner)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((target, port))  # 0 = success
            if result != 0:
                return False, ""
            return True, grab_banner(s)
    except socket.gaierror:
        print(f"[!] Cannot resolve host: {target}")
        sys.exit(1)
    except Exception as e:
        return False, ""

def main():
    parser = argparse.ArgumentParser(description="Simple TCP port scanner (learning project)")
    parser.add_argument("target", help="IP address or hostname to scan (only your own / permitted systems)")
    parser.add_argument("--ports", help="Comma list, e.g. 22,80,443 (default: common ports)")
    parser.add_argument("--start", type=int, help="Start port for a range scan")
    parser.add_argument("--end", type=int, help="End port for a range scan")
    args = parser.parse_args()

    if args.ports:
        ports = [int(p.strip()) for p in args.ports.split(",") if p.strip()]
    elif args.start and args.end:
        ports = list(range(args.start, args.end + 1))
    else:
        ports = sorted(COMMON_PORTS.keys())

    try:
        target_ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"[!] Cannot resolve host: {args.target}")
        sys.exit(1)

    print(f"[*] Target : {args.target} ({target_ip})")
    print(f"[*] Ports  : {len(ports)} port(s)")
    print(f"[*] Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 60)

    open_ports = []
    for port in ports:
        is_open, banner = scan_port(target_ip, port)
        if is_open:
            service = COMMON_PORTS.get(port, "unknown")
            line = f"[+] {port:<6} OPEN  {service}"
            if banner:
                line += f"  | banner: {banner[:60]}"
            print(line)
            open_ports.append(port)

    print("-" * 60)
    print(f"[*] Done. Open ports found: {open_ports if open_ports else 'none'}")

if __name__ == "__main__":
    main()
