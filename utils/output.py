import contextlib
import csv
import io
import json
import sys
from typing import Any, Dict, Optional

from utils.colors import Colors


def _flatten(data: Any, prefix: str = "") -> Dict[str, Any]:
    """Flatten nested dicts/lists into dotted keys for CSV and TXT export."""
    flat: Dict[str, Any] = {}
    if isinstance(data, dict):
        for k, v in data.items():
            flat.update(_flatten(v, f"{prefix}{k}."))
    elif isinstance(data, list):
        for i, v in enumerate(data):
            flat.update(_flatten(v, f"{prefix}{i}."))
    else:
        flat[prefix.rstrip(".")] = data
    return flat


def _csv_safe(value: Any) -> Any:
    """Banners, headers and DNS names come from the target, so a value like "=HYPERLINK(...)" would
    run as a formula when the CSV is opened in a spreadsheet. Prefix such strings with a quote."""
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


def render(results: Any, fmt: str) -> str:
    """Serialize results as json, or as flattened key/value csv or txt."""
    if fmt == "json":
        return json.dumps(results, indent=2, default=str)
    rows = _flatten(results)
    if fmt == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["key", "value"])
        for k, v in rows.items():
            writer.writerow([k, _csv_safe(v)])
        return buf.getvalue()
    if fmt == "txt":
        return "\n".join(f"{k}: {v}" for k, v in rows.items()) + "\n"
    raise ValueError(f"Unknown output format: {fmt}")


def export(results: Any, fmt: Optional[str], file: Optional[str]) -> None:
    """Write results to `file` (format from -o, else the file extension, else JSON) or print them; no-op without either."""
    if not fmt:
        if file:
            ext = file.rsplit(".", 1)[-1].lower() if "." in file else ""
            # report.out or report.log would otherwise fail after the scan already ran
            fmt = ext if ext in ("json", "csv", "txt") else "json"
        else:
            return
    text = render(results, fmt)
    if file:
        with open(file, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)
        print(f"\n{Colors.SUCCESS}Saved {fmt.upper()} report to {file}")
    else:
        print(text)


def human_view(output: Optional[str], file: Optional[str]):
    """When the report itself goes to stdout (-o without -f), send the human-readable view to stderr
    so `rudynet ... -o json | jq` gets clean JSON."""
    if output and not file:
        return contextlib.redirect_stdout(sys.stderr)
    return contextlib.nullcontext()


class OutputFormatter:
    @staticmethod
    def display_web_results(results: Dict[str, Any], output: Optional[str] = None, file: Optional[str] = None) -> None:
        with human_view(output, file):
            tls = results.get("tls")
            if tls:
                print(f"{Colors.BOLD}TLS / Certificate{Colors.RESET}")
                if tls.get("error"):
                    print(f"  {Colors.ERROR}{tls['error']}")
                else:
                    print(f"  Protocol     {tls.get('protocol')}")
                    print(f"  Cipher       {tls.get('cipher')}")
                    print(f"  Subject      {tls.get('subject')}")
                    print(f"  Issuer       {tls.get('issuer')}")
                    print(f"  Expires      {tls.get('not_after')} ({tls.get('days_left')} days left)")
                    for issue in tls.get("issues", []):
                        print(f"  {Colors.WARNING}{issue}")
                print()

            headers = results.get("headers")
            if headers:
                print(f"{Colors.BOLD}Security Headers{Colors.RESET}")
                if headers.get("error"):
                    print(f"  {Colors.ERROR}{headers['error']}")
                else:
                    print(f"  Final URL    {headers.get('final_url')} (HTTP {headers.get('status')})")
                    for check in headers.get("checks", []):
                        mark = Colors.SUCCESS if check["ok"] else Colors.WARNING
                        print(f"  {mark}{check['header']}: {check['detail']}")
                    for leak in headers.get("leaks", []):
                        print(f"  {Colors.WARNING}Information leak: {leak}")
                    for issue in headers.get("cookie_issues", []):
                        print(f"  {Colors.WARNING}Cookie: {issue}")
                print()

            if "score" in results:
                print(f"{Colors.BOLD}Overall{Colors.RESET}  {Colors.grade(results['grade'])}  ({results['score']}/100)")

        export(results, output, file)

    @staticmethod
    def display_scan_results(results: Dict[str, Any], output: Optional[str] = None, file: Optional[str] = None) -> None:
        with human_view(output, file):
            print(f"{Colors.BOLD}Target{Colors.RESET}  {results['target']} ({results['ip']})")
            print(f"{Colors.BOLD}Scanned{Colors.RESET} {results['scanned']} ports ({results['scan_type']})\n")
            if not results["open"]:
                print(f"{Colors.WARNING}No open ports found")
            for r in results["open"]:
                line = f"{Colors.SUCCESS}{r['port']:>5}/{r['protocol']:<3}  {r['service']:<14}"
                if r.get("banner"):
                    line += f" {Colors.DIM}{r['banner']}{Colors.RESET}"
                print(line)
        export(results, output, file)

    @staticmethod
    def display_subdomain_results(results: Dict[str, Any], output: Optional[str] = None, file: Optional[str] = None) -> None:
        with human_view(output, file):
            if results["wildcard"]:
                print(f"{Colors.WARNING}Wildcard DNS detected ({', '.join(results['wildcard'])}); matching hits were filtered\n")
            for r in results["found"]:
                extra = f" {Colors.DIM}-> {r['cname']}{Colors.RESET}" if r.get("cname") else ""
                print(f"{Colors.SUCCESS}{r['subdomain']:<40} {', '.join(r['ips'])}{extra}")
            print(f"\n{Colors.INFO}{len(results['found'])} found out of {results['tried']} names tried")
        export(results, output, file)
