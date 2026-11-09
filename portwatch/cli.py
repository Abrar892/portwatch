"""CLI interface for portwatch."""
import argparse
from portwatch.services import TOP_PORTS
from portwatch.scanner import PortScanner
from portwatch.reporter import generate_text_report, generate_html_report


def parse_port_range(port_arg: str):
    if "-" in port_arg:
        start, end = port_arg.split("-", 1)
        return list(range(int(start), int(end) + 1))
    elif "," in port_arg:
        return [int(p.strip()) for p in port_arg.split(",") if p.strip()]
    return [int(port_arg)]


def main():
    parser = argparse.ArgumentParser(description="Portwatch - Network Port Scanner and Security Auditing Tool")
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument("--ports", help="Ports to scan (e.g. 80, 80-1000, 22,80,443)")
    parser.add_argument("--top-ports", action="store_true", help="Scan top well-known services")
    parser.add_argument("--threads", type=int, default=20, help="Concurrent scan worker threads")
    parser.add_argument("--timeout", type=float, default=1.0, help="Socket timeout in seconds")
    parser.add_argument("--html", help="Path to write standalone HTML report")

    args = parser.parse_args()

    if args.top_ports or not args.ports:
        ports = TOP_PORTS
    else:
        ports = parse_port_range(args.ports)

    scanner = PortScanner(args.target, timeout=args.timeout)
    results = scanner.scan_ports(ports, max_threads=args.threads)

    if args.html:
        html = generate_html_report(args.target, results)
        with open(args.html, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"Audit report saved to {args.html}")
    else:
        print(generate_text_report(args.target, results))


if __name__ == "__main__":
    main()
