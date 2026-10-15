# Changelog

## Unreleased

### scan
- `--banner` reads banners over TLS on ports 443, 465, 993, 995 and 8443
- `-r/--rate` caps new connections per second for hosts or firewalls that drop bursts
- `-p` accepts `top100` inside a list (`top100,8081`) and `-` for all ports

### subdomain
- Wildcard DNS is probed with up to three random names, so round-robin wildcards are filtered fully
- A failed crt.sh lookup no longer writes its warning into JSON on stdout

### output
- CSV values that start with `=`, `+`, `-` or `@` are quoted so spreadsheets don't run them as formulas

### web
- A `Server` header only counts as an information leak when it carries a version number
- HSTS details say when a `preload` flag does not meet the preload list requirements

## 1.2.0

### scan
- IPv6 targets, and URLs or bracketed addresses as `-t` (`https://host/path`, `[::1]`)
- Mixed port lists such as `22,80-90`; duplicates are dropped
- `-p top100` scans 100 commonly open TCP ports
- `-w/--workers` to set how many connections run in parallel
- Clear errors for hosts that do not resolve and for zero or negative timeouts

### web
- `--fail-under SCORE` exits with status 2 for CI checks
- Header grading follows browser behavior: HSTS over plain HTTP earns nothing, `Referrer-Policy` lists are graded by their last value, headers sent twice with the same value are accepted, and `'unsafe-inline'` next to a CSP nonce or hash is not a weakness
- Cookies set on redirects are checked as well

### subdomain
- `-d` accepts a URL; names without a dot are rejected
- IPv6-only names (AAAA without A) are found
- A missing wordlist gives an error instead of a traceback

### Output
- With `-o` and no `-f`, the report is the only thing on stdout (the readable view goes to stderr), so it can be piped
- `-f` with an unknown extension saves JSON instead of failing after the scan

### Removed
- The unfinished `monitor` command

## 1.1.0
- Port scanner, web security grading and subdomain discovery with JSON, CSV and TXT export
