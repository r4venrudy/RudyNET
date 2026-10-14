# Changelog

## 1.2.0

### scan
- IPv6 targets, and URLs or bracketed addresses as `-t` (`https://host/path`, `[::1]`)
- Mixed port lists such as `22,80-90`; duplicates are dropped
- `-w/--workers` to set how many connections run in parallel
- Clear errors for hosts that do not resolve and for zero or negative timeouts

### web
- `--fail-under SCORE` exits with status 2 for CI checks
- Header grading follows browser behavior: HSTS over plain HTTP earns nothing, `Referrer-Policy` lists are graded by their last value, headers sent twice with the same value are accepted, and `'unsafe-inline'` next to a CSP nonce or hash is not a weakness
- Cookies set on redirects are checked as well

### subdomain
- `-d` accepts a URL; names without a dot are rejected
- A missing wordlist gives an error instead of a traceback

### Output
- With `-o` and no `-f`, the report is the only thing on stdout (the readable view goes to stderr), so it can be piped
- `-f` with an unknown extension saves JSON instead of failing after the scan

### Removed
- The unfinished `monitor` command

## 1.1.0
- Port scanner, web security grading and subdomain discovery with JSON, CSV and TXT export
