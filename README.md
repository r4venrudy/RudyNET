<div align="center">

# RudyNET Security Tool

**A fast, extensible, multi-purpose security scanning toolkit for reconnaissance, auditing, and authorized penetration testing.**

[![Python](https://img.shields.io/badge/Python-3.7%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey)](#requirements)
[![License](https://img.shields.io/badge/License-As--Is-red)](#license)
[![Security](https://img.shields.io/badge/Use-Authorized%20Testing%20Only-darkred)](#security-and-legal-notice)

</div>

---

## Overview

**RudyNET** is a multi-purpose command-line security toolkit designed for reconnaissance, security auditing, and penetration testing workflows.

It combines essential network and web security analysis techniques within a single interface. RudyNET is built with speed, usability, and extensibility in mind, making it suitable for cybersecurity students, researchers, and professionals conducting authorized security assessments.

## Features

| Module | Capabilities |
|---|---|
| **Port Scanner** | TCP and UDP scanning, custom port ranges, service detection, banner grabbing, and multi-threaded execution |
| **Web Security Analysis** | SSL/TLS certificate inspection, HTTP security-header analysis, security posture evaluation, and focused SSL checks |
| **Subdomain Enumeration** | DNS-based discovery, custom wordlist support, multi-threaded enumeration, and efficient resolution |
| **Network Monitoring** | Real-time traffic monitoring, packet capture, packet inspection, BPF filtering, and cross-platform support |
| **Report Exporting** | Export scan results in JSON, CSV, or TXT format |

## Requirements

| Requirement | Details |
|---|---|
| **Python** | Python 3.7 or newer |
| **Operating Systems** | Linux, Windows, and macOS |
| **Internet Connection** | Required for remote scanning and DNS operations |
| **Privileges** | Some packet and network operations may require elevated privileges |
| **Recommended Platform** | Linux for complete network-monitoring functionality |

### Python Dependencies

- `click`
- `requests`
- `dnspython`
- `scapy` — optional and primarily used for Linux network features

## Installation

Clone the repository:

```bash
git clone https://github.com/USERNAME/RudyNET.git
cd RudyNET
```

Create a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install the required packages:

```bash
pip install -r requirements.txt
```

Display the help menu:

```bash
python rudynet.py --help
```

## Usage

RudyNET operates through dedicated subcommands for each security module.

### Port Scanning

Scan selected TCP or UDP ports and attempt service detection:

```bash
python rudynet.py scan -t example.com -p 80,443,8080
```

### Web Security Analysis

Inspect SSL/TLS configuration, security headers, and the general security posture of a website:

```bash
python rudynet.py web -u https://example.com
```

### Subdomain Enumeration

Discover DNS-based subdomains:

```bash
python rudynet.py subdomain -d example.com
```

### Network Monitoring

Capture and inspect packets from a selected network interface:

```bash
python rudynet.py monitor -i eth0 -c 100
```

> Network monitoring may require administrator or root privileges.

## Command Overview

| Command | Purpose | Example |
|---|---|---|
| `scan` | Scan ports and identify exposed services | `python rudynet.py scan -t example.com -p 1-1000` |
| `web` | Analyze web and SSL/TLS security | `python rudynet.py web -u https://example.com` |
| `subdomain` | Enumerate subdomains | `python rudynet.py subdomain -d example.com` |
| `monitor` | Monitor and inspect network traffic | `python rudynet.py monitor -i eth0 -c 100` |

## Output

RudyNET provides readable terminal output designed for fast analysis:

- Color-coded findings
- Real-time progress indicators
- Clear status and error messages
- Partial results when individual checks fail
- JSON, CSV, and TXT export support

Example export formats:

```text
results.json
results.csv
results.txt
```

## Error Handling

RudyNET is designed to handle common operational problems gracefully:

- Network timeouts do not terminate the entire process
- Invalid targets are detected and reported clearly
- Partial module failures still return usable findings
- Connection and permission errors produce understandable messages
- Interrupted operations preserve available results where possible

## Customization and Development

RudyNET can be expanded through additional modules and integrations, including:

- New network and application scanning modules
- External threat-intelligence API integrations
- Additional reporting and export formats
- Improved service and vulnerability detection
- Automated reconnaissance workflows
- Custom security policies and detection rules

Contributions, feature suggestions, and responsible improvements are welcome.

## Security and Legal Notice

> [!CAUTION]
> RudyNET performs active network and web scanning operations. Only use this tool against systems you own or have explicit authorization to test.

Unauthorized scanning, packet capture, or security testing may violate applicable laws, regulations, contracts, or acceptable-use policies.

The author assumes no responsibility for misuse, damage, service disruption, data loss, or illegal activity resulting from the use of this software.

## Author

Created for security research, authorized penetration testing, and cybersecurity education by **[@r4ven.leet](https://github.com/r4ven-leet)**.

## License

RudyNET is provided **as-is**, without warranties or guarantees of any kind.

Use responsibly and exclusively for legitimate, authorized security testing.

---

<div align="center">

**RudyNET — Reconnaissance. Analysis. Security.**

</div>
