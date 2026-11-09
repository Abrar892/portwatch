# Portwatch

Educational network port scanner, banner grabber, and security posture auditing engine built with pure Python.

## Key Capabilities
- **Fast Multi-Threaded TCP Connect Scanning:** Scans customizable port ranges or top well-known service presets.
- **Service Fingerprinting & Banner Grabbing:** Probes open sockets with protocol-specific handshakes (HTTP, SSH, SMTP, Redis).
- **Security Assessment:** Flags unencrypted plaintext protocols and common misconfiguration risks.
- **Standalone HTML Auditing Reports:** Produces visual vulnerability posture dashboards.
- **Zero Third-Party Dependencies:** 100% Python 3.12 standard library (`socket`, `concurrent.futures`, `json`, `argparse`).

## Usage
```bash
python -m portwatch.cli scan 127.0.0.1 --ports 20-1000 --threads 20
python -m portwatch.cli scan 127.0.0.1 --top-ports --html audit.html
```
