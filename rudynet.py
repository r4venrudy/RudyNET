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
from utils.output import OutputFormatter, human_view


def load_module(module: str, cls: str):
    # Modules are imported per command so one missing optional dependency
    # (e.g. dnspython for `subdomain`) doesn't break every other command.
    try:
        return getattr(importlib.import_module(f"modules.{module}"), cls)
    except ImportError as e:
        click.echo(f"{Colors.ERROR}The '{module}' module is unavailable: {e}{Colors.RESET}")
        sys.exit(1)

@click.group()
@click.version_option(version='1.2.0', prog_name='RudyNET')
def cli():
    """RudyNET: port scanning, web security grading and subdomain discovery for systems you are authorized to test."""

@cli.command()
@click.option('-t', '--target', required=True, help='Target IP or hostname')
@click.option('-p', '--ports', default='1-1000', help="Ports: 1-1000, 80,443, 22,80-90 or top100")
@click.option('-T', '--timeout', default=1.0, type=click.FloatRange(0, min_open=True), help='Timeout (seconds)')
@click.option('-s', '--scan-type', default='tcp', type=click.Choice(['tcp', 'udp', 'both']))
@click.option('-o', '--output', type=click.Choice(['json', 'csv', 'txt']))
@click.option('-f', '--file', help='Output file')
@click.option('--banner', is_flag=True, help='Grab banners')
@click.option('-w', '--workers', default=200, type=click.IntRange(1, 1000), help='Parallel connections (1-1000)')
def scan(target: str, ports: str, timeout: float, scan_type: str, output: Optional[str], file: Optional[str], banner: bool, workers: int):
    """Scan TCP/UDP ports on a host and optionally read service banners."""
    with human_view(output, file):
        Colors.print_banner()
        click.echo(f"{Colors.INFO}Scanning {Colors.BOLD}{target}{Colors.RESET}\n")

    PortScanner = load_module('port_scanner', 'PortScanner')

    try:
        port_list = parse_ports(ports)
        # Resolving the host can fail, so it belongs inside the error handling
        scanner = PortScanner(target, timeout, banner, workers)
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
@click.option('-T', '--timeout', default=10.0, type=click.FloatRange(0, min_open=True), help='Timeout per request (seconds)')
@click.option('--fail-under', type=click.IntRange(0, 100), help='Exit with status 2 when the score is below this (for CI)')
def web(url: str, output: Optional[str], file: Optional[str], ssl_only: bool, timeout: float, fail_under: Optional[int]):
    """Grade a website's TLS certificate, security headers and cookies (A+ to F)."""
    with human_view(output, file):
        Colors.print_banner()
        click.echo(f"{Colors.INFO}Analyzing {Colors.BOLD}{url}{Colors.RESET}\n")

    WebSecurity = load_module('web_security', 'WebSecurity')
    try:
        web_sec = WebSecurity(url, timeout)
        results = web_sec.check_ssl_only() if ssl_only else web_sec.full_analysis()
        OutputFormatter.display_web_results(results, output, file)
    except KeyboardInterrupt:
        click.echo(f"\n{Colors.WARNING}Interrupted{Colors.RESET}")
        sys.exit(1)
    except Exception as e:
        click.echo(f"{Colors.ERROR}Error: {e}{Colors.RESET}")
        sys.exit(1)
    if fail_under is not None and results["score"] < fail_under:
        click.echo(f"{Colors.ERROR}Score {results['score']} is below {fail_under}{Colors.RESET}", err=True)
        sys.exit(2)


@cli.command()
@click.option('-d', '--domain', required=True, help='Target domain')
@click.option('-w', '--wordlist', help='Wordlist file')
@click.option('-t', '--threads', default=50, type=click.IntRange(1, 500), help='Threads (1-500)')
@click.option('--crtsh', is_flag=True, help='Also pull names from certificate-transparency logs (crt.sh)')
@click.option('-T', '--timeout', default=3.0, type=click.FloatRange(0, min_open=True), help='DNS timeout per name (seconds)')
@click.option('-o', '--output', type=click.Choice(['json', 'csv', 'txt']))
@click.option('-f', '--file', help='Output file')
def subdomain(domain: str, wordlist: Optional[str], threads: int, crtsh: bool, timeout: float, output: Optional[str], file: Optional[str]):
    """Find subdomains with a wordlist (and optionally crt.sh), filtering wildcard DNS."""
    with human_view(output, file):
        Colors.print_banner()
        click.echo(f"{Colors.INFO}Enumerating {Colors.BOLD}{domain}{Colors.RESET}\n")

    SubdomainEnum = load_module('subdomain_enum', 'SubdomainEnum')
    try:
        sub_enum = SubdomainEnum(domain, wordlist, threads, timeout)
    except OSError as e:
        click.echo(f"{Colors.ERROR}Error: cannot read wordlist: {e}{Colors.RESET}")
        sys.exit(1)
    except ValueError as e:
        click.echo(f"{Colors.ERROR}Error: {e}{Colors.RESET}")
        sys.exit(1)

    try:
        extra = []
        if crtsh:
            from modules.subdomain_enum import crtsh_names
            try:
                extra = crtsh_names(sub_enum.domain)
                click.echo(f"{Colors.INFO}crt.sh returned {len(extra)} names", err=bool(output and not file))
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
    """Parse "80", "20-25", "80,443", a mix such as "22,80-90", or "top100" into sorted unique ports."""
    if ports_str.strip().lower() == 'top100':
        from modules.port_scanner import TOP_PORTS
        return sorted(TOP_PORTS)
    ports = set()
    try:
        for part in ports_str.split(','):
            part = part.strip()
            if not part:
                continue
            bounds = part.split('-')
            if len(bounds) == 1:
                start = end = int(bounds[0])
            elif len(bounds) == 2:
                start, end = int(bounds[0]), int(bounds[1])
            else:
                raise ValueError
            if start > end or start < 1 or end > 65535:
                raise ValueError
            ports.update(range(start, end + 1))
    except ValueError:
        raise ValueError(f"Invalid port format: {ports_str}")
    if not ports:
        raise ValueError(f"Invalid port format: {ports_str}")
    return sorted(ports)

if __name__ == '__main__':
    cli()
