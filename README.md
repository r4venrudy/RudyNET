##################################################
#              RudyNET Security Tool             #
##################################################

Description:
-------------
RudyNET is a multi-purpose security scanning toolkit designed for reconnaissance,
security auditing, and penetration testing workflows. It combines several essential
network and web security analysis techniques into a single command-line interface.

The tool is built for speed, usability, and extensibility, making it suitable for
both learning environments and authorized real-world security assessments.

--------------------------------------------------

Features:
---------
1. Port Scanning
   - TCP and UDP port scanning
   - Custom port ranges
   - Service detection and banner grabbing
   - Multi-threaded scanning for performance

2. Web Security Analysis
   - SSL/TLS certificate inspection
   - Security headers analysis
   - Web security posture evaluation
   - Optional focused SSL-only checks

3. Subdomain Enumeration
   - DNS-based subdomain discovery
   - Custom wordlist support
   - Multi-threaded enumeration
   - Fast and efficient discovery process

4. Network Monitoring
   - Real-time traffic monitoring
   - Packet capture and inspection
   - BPF filter support
   - Cross-platform compatibility

--------------------------------------------------

Requirements:
-------------
- Python 3.7 or newer
- Supported OS: Linux, Windows, macOS
- Internet access
- Elevated privileges for some network features (Linux)

Required Python packages:
-------------------------
- click
- requests
- dnspython
- scapy (optional, Linux only)

--------------------------------------------------

Installation:
-------------
1. Clone or download the project files.

2. Install dependencies:
   pip install -r requirements.txt

3. Run the tool:
   python rudynet.py --help

--------------------------------------------------

Usage:
------
RudyNET is operated through subcommands.

Examples:

- Port scanning:
  python rudynet.py scan -t example.com -p 80,443,8080

- Web security analysis:
  python rudynet.py web -u https://example.com

- Subdomain enumeration:
  python rudynet.py subdomain -d example.com

- Network monitoring:
  python rudynet.py monitor -i eth0 -c 100

--------------------------------------------------

Output Format:
--------------
- Results are displayed directly in the terminal.
- Color-coded output improves readability.
- Progress indicators show real-time scan status.
- Results can be exported as JSON, CSV, or TXT files.

--------------------------------------------------

Error Handling:
---------------
- Network timeouts are handled gracefully.
- Invalid targets do not crash the application.
- Partial failures still return usable results.
- Clear error messages are displayed when issues occur.

--------------------------------------------------

Security Notes:
---------------
- RudyNET performs active scanning operations.
- Only scan systems you own or have explicit authorization to test.
- Unauthorized scanning may be illegal.
- The authors are not responsible for misuse.

--------------------------------------------------

Customization:
--------------
RudyNET can be extended by:
- Adding new scanning modules
- Integrating external APIs
- Expanding output formats
- Improving detection logic
- Adding automation workflows

--------------------------------------------------

Author:
-------
Created for security research, penetration testing, and educational use. by @r4ven.leet.

--------------------------------------------------

License:
--------
Provided as-is.
Use responsibly.
For authorized testing only.
