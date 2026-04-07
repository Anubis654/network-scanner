# 🔍 Network Scanner Tool

A Python-based network reconnaissance tool built for learning purposes as part of my cybersecurity journey.

## 📌 Features

- **Host Discovery** — scan a full CIDR range (e.g. `192.168.1.0/24`) to find alive hosts
- **Port Scanning** — check common ports or a custom range using multithreading
- **Service Detection** — identifies services running on open ports (HTTP, SSH, FTP, RDP, etc.)
- **Banner Grabbing** — attempts to read service banners for fingerprinting
- **Reverse DNS** — resolves IPs to hostnames
- **Report Export** — saves a clean `.txt` report of the scan results

## 🛠️ Technologies Used

- Python 3
- `socket` — TCP connection & DNS resolution
- `ipaddress` — CIDR network parsing
- `concurrent.futures` — multithreaded scanning
- `datetime` — timestamped reports

## 🚀 Usage

```bash
python3 network_scanner.py
```

Then choose:
1. Scan a single host
2. Discover all hosts in a network range
3. Exit

## ⚠️ Legal Disclaimer

> This tool is intended for **educational purposes only**.  
> Only use it on networks you **own** or have **explicit written permission** to test.  
> Unauthorized scanning is illegal.

## 📚 Learning Context

Built while studying:
- **CCNA** (Cisco Certified Network Associate) — Networking fundamentals
- **CompTIA Security+** — Security concepts & reconnaissance techniques
- **Python for Cybersecurity** — Scripting and automation
- **TryHackMe / Hack The Box** — Practical penetration testing labs

## 👤 Author

**Your Name**  
Dental Student & Cybersecurity Enthusiast  
[LinkedIn](https://linkedin.com/in/yourprofile) • [TryHackMe](https://tryhackme.com/p/yourprofile)
