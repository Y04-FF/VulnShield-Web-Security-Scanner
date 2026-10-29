# Mini Vulnerability Scanner

A beginner-friendly Python project for authorized security assessment.

## Features
- Checks a limited list of common TCP ports.
- Checks basic HTTP response security headers when given a URL.
- Reports exposed services and server technology banners.
- Generates readable HTML and machine-readable JSON reports.
- Uses Python standard library only; no pip installation required.

## Run
Python 3.9+ is recommended. Open a terminal in this folder.

Scan your own computer:
```bash
python scanner.py 127.0.0.1 --authorized
```

Check a local web app:
```bash
python scanner.py 127.0.0.1 --authorized --url http://127.0.0.1:8000
```

Choose ports:
```bash
python scanner.py 127.0.0.1 --authorized --ports 22,80,443,8080
```

Open `scan_report.html` in a browser. The scanner also creates `scan_report.json`.

## Understanding results
- Open port: a TCP service accepted a connection. It is not automatically a vulnerability.
- Missing security header: review whether the web application should set that header.
- Server banner: a product/version string was disclosed. Verify it against official vendor advisories; the banner alone does not prove outdated software.
- Closed or filtered: the connection did not succeed; a firewall may be filtering it.

## Safety and limitations
Only scan systems you own or have explicit permission to assess. The `--authorized` flag is an acknowledgement, not a permission check. This educational tool performs limited checks only; it does not exploit vulnerabilities, brute-force credentials, or evade detection. Findings may be false positives or false negatives and must be manually verified. Never expose database or admin services unnecessarily.

## Learning outcomes
TCP ports, network services, HTTP headers, passive banner review, risk severity, remediation recommendations, and ethical authorization.
