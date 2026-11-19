# Python Port Scanner

A simple TCP port scanner built in Python as a **learning project** for cybersecurity basics.
It checks which TCP ports are open on a target and tries to read the service banner.

> ⚠️ **Legal use only:** Scan only systems you own or have written permission to test. Scanning other people's systems without permission is illegal.

## What I learnt
- How TCP connections work (`socket`, `connect_ex`)
- What ports and services are (22 = SSH, 80 = HTTP, 443 = HTTPS, etc.)
- Banner grabbing — reading what a service tells you when you connect
- Handling timeouts and errors in Python

## How to run
```bash
# Scan common ports on your own machine
python port_scanner.py 127.0.0.1

# Scan specific ports on a legal test target
python port_scanner.py scanme.nmap.org --ports 22,80,443

# Scan a port range on your own lab VM
python port_scanner.py 192.168.1.10 --start 1 --end 1024
```

## Sample output
```
[*] Target : 127.0.0.1 (127.0.0.1)
[*] Ports  : 13 port(s)
------------------------------------------------------------
[+] 22     OPEN  SSH  | banner: SSH-2.0-OpenSSH_9.6
[+] 80     OPEN  HTTP
------------------------------------------------------------
[*] Done. Open ports found: [22, 80]
```

## Tech
Python 3 — standard library only (`socket`, `argparse`). No installation needed.
