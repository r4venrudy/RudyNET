#!/usr/bin/env python3

import click
import sys
from typing import List, Optional
from modules.port_scanner import PortScanner
from modules.web_security import WebSecurity
from modules.subdomain_enum import SubdomainEnum
from modules.network_monitor import NetworkMonitor
from utils.colors import Colors
from utils.output import OutputFormatter

@click.group()
@click.version_option(version='1.0.0', prog_name='NetShark')
def cli():
    pass

@cli.command()
@click.option('-t', '--target', required=True, help='Target IP or hostname')
@click.option('-p', '--ports', default='1-1000', help='Ports: 1-1000 or 80,443,8080')
@click.option('-T', '--timeout', default=1.0, type=float, help='Timeout (seconds)')
@click.option('-s', '--scan-type', default='tcp', type=click.Choice(['tcp', 'udp', 'both']))
@click.option('-o', '--output', type=click.Choice(['json', 'csv', 'txt']))
@click.option('-f', '--file', help='Output file')
@click.option('--banner', is_flag=True, help='Grab banners')
def scan(target: str, ports: str, timeout: float, scan_type: str, output: Optional[str], file: Optional[str], banner: bool):
    Colors.print_banner()
    click.echo(f"{Colors.INFO}Scanning {Colors.BOLD}{target}{Colors.RESET}\n")
    
    scanner = PortScanner(target, timeout, banner)
    
    try:
        port_list = parse_ports(ports)
        results = scanner.scan(port_list, scan_type)
        OutputFormatter.display_scan_results(results, output, file)
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
def web(url: str, output: Optional[str], file: Optional[str], ssl_only: bool):
    Colors.print_banner()
    click.echo(f"{Colors.INFO}Analyzing {Colors.BOLD}{url}{Colors.RESET}\n")
    
    web_sec = WebSecurity(url)
    
    try:
        results = web_sec.check_ssl_only() if ssl_only else web_sec.full_analysis()
        OutputFormatter.display_web_results(results, output, file)
    except Exception as e:
        click.echo(f"{Colors.ERROR}Error: {e}{Colors.RESET}")
        sys.exit(1)

@cli.command()
@click.option('-d', '--domain', required=True, help='Target domain')
@click.option('-w', '--wordlist', help='Wordlist file')
@click.option('-t', '--threads', default=50, type=int, help='Threads')
@click.option('-o', '--output', type=click.Choice(['json', 'csv', 'txt']))
@click.option('-f', '--file', help='Output file')
def subdomain(domain: str, wordlist: Optional[str], threads: int, output: Optional[str], file: Optional[str]):
    Colors.print_banner()
    click.echo(f"{Colors.INFO}Enumerating {Colors.BOLD}{domain}{Colors.RESET}\n")
    
    sub_enum = SubdomainEnum(domain, wordlist, threads)
    
    try:
        results = sub_enum.enumerate()
        OutputFormatter.display_subdomain_results(results, output, file)
    except KeyboardInterrupt:
        click.echo(f"\n{Colors.WARNING}Interrupted{Colors.RESET}")
        sys.exit(1)
    except Exception as e:
        click.echo(f"{Colors.ERROR}Error: {e}{Colors.RESET}")
        sys.exit(1)

@cli.command()
@click.option('-i', '--interface', help='Network interface')
@click.option('-c', '--count', default=100, type=int, help='Packet count')
@click.option('-f', '--filter', help='BPF filter')
@click.option('-o', '--output', type=click.Choice(['json', 'csv', 'txt']))
@click.option('--file', help='Output file')
def monitor(interface: Optional[str], count: int, filter: Optional[str], output: Optional[str], file: Optional[str]):
    Colors.print_banner()
    click.echo(f"{Colors.INFO}Monitoring network{Colors.RESET}\n")
    
    net_mon = NetworkMonitor(interface, count, filter)
    
    try:
        results = net_mon.monitor()
        OutputFormatter.display_network_results(results, output, file)
    except KeyboardInterrupt:
        click.echo(f"\n{Colors.WARNING}Stopped{Colors.RESET}")
        sys.exit(1)
    except Exception as e:
        click.echo(f"{Colors.ERROR}Error: {e}{Colors.RESET}")
        sys.exit(1)

def parse_ports(ports_str: str) -> List[int]:
    try:
        if '-' in ports_str:
            parts = ports_str.split('-')
            if len(parts) != 2:
                raise ValueError(f"Invalid port range: {ports_str}")
            start, end = int(parts[0]), int(parts[1])
            if start > end or start < 1 or end > 65535:
                raise ValueError(f"Invalid port range: {ports_str}")
            return list(range(start, end + 1))
        elif ',' in ports_str:
            ports = [int(p.strip()) for p in ports_str.split(',')]
            if any(p < 1 or p > 65535 for p in ports):
                raise ValueError(f"Ports must be between 1-65535")
            return ports
        else:
            port = int(ports_str)
            if port < 1 or port > 65535:
                raise ValueError(f"Port must be between 1-65535")
            return [port]
    except ValueError as e:
        raise ValueError(f"Invalid port format: {e}")

if __name__ == '__main__':
    cli()

