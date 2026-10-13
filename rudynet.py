#!/usr/bin/env python3

import os
import sys
from PIL import Image

BASE = os.path.dirname(os.path.abspath(__file__))
RAVEN = os.path.join(BASE, "raven.png")

def raven_fail():
    print("Kabul etmesende mahçupsun - r4ven.leet. Fotoğrafımı geri yükle")
    sys.exit(1)

if not os.path.isfile(RAVEN):
    raven_fail()

try:
    if os.path.getsize(RAVEN) < 1024:
        raven_fail()
    with Image.open(RAVEN) as img:
        img.verify()
except:
    raven_fail()

import click
import socket
from typing import List, Optional
import importlib
from utils.colors import Colors
from utils.output import OutputFormatter


def load_module(module: str, cls: str):
    # Modules are imported per command so one missing optional dependency
    # (e.g. scapy for `monitor`) doesn't break every other command.
    try:
        return getattr(importlib.import_module(f"modules.{module}"), cls)
    except ImportError as e:
        click.echo(f"{Colors.ERROR}The '{module}' module is unavailable: {e}{Colors.RESET}")
        sys.exit(1)

@click.group()
@click.version_option(version='1.1.0', prog_name='RudyNET')
def cli():
    """RudyNET: port scanning, web security grading and subdomain discovery for systems you are authorized to test."""

@cli.command()
@click.option('-t', '--target', required=True, help='Target IP or hostname')
@click.option('-p', '--ports', default='1-1000', help='Ports: 1-1000 or 80,443,8080')
@click.option('-T', '--timeout', default=1.0, type=float, help='Timeout (seconds)')
@click.option('-s', '--scan-type', default='tcp', type=click.Choice(['tcp', 'udp', 'both']))
@click.option('-o', '--output', type=click.Choice(['json', 'csv', 'txt']))
@click.option('-f', '--file', help='Output file')
@click.option('--banner', is_flag=True, help='Grab banners')
def scan(target: str, ports: str, timeout: float, scan_type: str, output: Optional[str], file: Optional[str], banner: bool):
    """Scan TCP/UDP ports on a host and optionally read service banners."""
    Colors.print_banner()
    click.echo(f"{Colors.INFO}Scanning {Colors.BOLD}{target}{Colors.RESET}\n")

    PortScanner = load_module('port_scanner', 'PortScanner')

    try:
        port_list = parse_ports(ports)
        # Resolving the host can fail, so it belongs inside the error handling
        scanner = PortScanner(target, timeout, banner)
        results = scanner.scan(port_list, scan_type)
        OutputFormatter.display_scan_results(results, output, file)
    except socket.gaierror:
        click.echo(f"{Colors.ERROR}Error: could not resolve host '{target}'{Colors.RESET}")
        sys.exit(1)
    except KeyboardInterrupt:
        click.echo(f"\n{Colors.WARNING}Interrupted{Colors.RESET}")
        sys.exit(1)
    except Exception as e:
        click.echo(f"{Colors.ERROR}Error: {e}{Colors.RESET}")
        sys.exit(1)

@cli.command()
@click.option('-u', '--url', required=True, help='Target URL')
@click.option('-o', '--output', type=click.Choice(['json', 'csv', 'txt']))
@click.option('-f', '--file', help='Output file')
@click.option('--ssl-only', is_flag=True, help='SSL/TLS only')
@click.option('-T', '--timeout', default=10.0, type=float, help='Timeout per request (seconds)')
def web(url: str, output: Optional[str], file: Optional[str], ssl_only: bool, timeout: float):
    """Grade a website's TLS certificate, security headers and cookies (A+ to F)."""
    Colors.print_banner()
    click.echo(f"{Colors.INFO}Analyzing {Colors.BOLD}{url}{Colors.RESET}\n")

    WebSecurity = load_module('web_security', 'WebSecurity')
    try:
        web_sec = WebSecurity(url, timeout)
        results = web_sec.check_ssl_only() if ssl_only else web_sec.full_analysis()
        OutputFormatter.display_web_results(results, output, file)
    except Exception as e:
        click.echo(f"{Colors.ERROR}Error: {e}{Colors.RESET}")
        sys.exit(1)

@cli.command()
@click.option('-d', '--domain', required=True, help='Target domain')
@click.option('-w', '--wordlist', help='Wordlist file')
@click.option('-t', '--threads', default=50, type=int, help='Threads')
@click.option('--crtsh', is_flag=True, help='Also pull names from certificate-transparency logs (crt.sh)')
@click.option('-T', '--timeout', default=3.0, type=float, help='DNS timeout per name (seconds)')
@click.option('-o', '--output', type=click.Choice(['json', 'csv', 'txt']))
@click.option('-f', '--file', help='Output file')
def subdomain(domain: str, wordlist: Optional[str], threads: int, crtsh: bool, timeout: float, output: Optional[str], file: Optional[str]):
    """Find subdomains with a wordlist (and optionally crt.sh), filtering wildcard DNS."""
    Colors.print_banner()
    click.echo(f"{Colors.INFO}Enumerating {Colors.BOLD}{domain}{Colors.RESET}\n")

    SubdomainEnum = load_module('subdomain_enum', 'SubdomainEnum')
    try:
        sub_enum = SubdomainEnum(domain, wordlist, threads, timeout)
    except OSError as e:
        click.echo(f"{Colors.ERROR}Error: cannot read wordlist: {e}{Colors.RESET}")
        sys.exit(1)

    try:
        extra = []
        if crtsh:
            from modules.subdomain_enum import crtsh_names
            try:
                extra = crtsh_names(sub_enum.domain)
                click.echo(f"{Colors.INFO}crt.sh returned {len(extra)} names")
            except Exception as e:
                click.echo(f"{Colors.WARNING}crt.sh lookup failed, continuing with wordlist only: {e}")
        results = sub_enum.enumerate(extra)
        OutputFormatter.display_subdomain_results(results, output, file)
    except KeyboardInterrupt:
        click.echo(f"\n{Colors.WARNING}Interrupted{Colors.RESET}")
        sys.exit(1)
    except Exception as e:
        click.echo(f"{Colors.ERROR}Error: {e}{Colors.RESET}")
        sys.exit(1)

def parse_ports(ports_str: str) -> List[int]:
    try:
        if '-' in ports_str:
            parts = ports_str.split('-')
            if len(parts) != 2:
                raise ValueError
            start, end = int(parts[0]), int(parts[1])
            if start > end or start < 1 or end > 65535:
                raise ValueError
            return list(range(start, end + 1))
        if ',' in ports_str:
            ports = sorted({int(p.strip()) for p in ports_str.split(',') if p.strip()})
            if any(p < 1 or p > 65535 for p in ports):
                raise ValueError
            return ports
        port = int(ports_str)
        if port < 1 or port > 65535:
            raise ValueError
        return [port]
    except:
        raise ValueError(f"Invalid port format: {ports_str}")

if __name__ == '__main__':
    cli()
