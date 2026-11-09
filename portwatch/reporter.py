"""Auditing report generators for portwatch."""
from typing import List
from portwatch.scanner import ScanResult


def generate_text_report(target: str, results: List[ScanResult]) -> str:
    open_ports = [r for r in results if r.is_open]
    lines = [
        "=" * 60,
        f"  PORTWATCH SECURITY AUDIT — {target}",
        "=" * 60,
        f"Total Ports Scanned: {len(results)}",
        f"Open Ports Detected: {len(open_ports)}",
        "-" * 60,
    ]
    if not open_ports:
        lines.append("No open ports discovered.")
    else:
        for r in open_ports:
            banner_str = f" | Banner: {r.banner}" if r.banner else ""
            lines.append(f"  [{r.risk_level}] Port {r.port:<5} ({r.service}){banner_str}")

    lines.append("=" * 60)
    return "\n".join(lines)


def generate_html_report(target: str, results: List[ScanResult]) -> str:
    open_ports = [r for r in results if r.is_open]
    rows = []
    for r in open_ports:
        color = {
            "HIGH": "#ef4444",
            "MEDIUM": "#f59e0b",
            "LOW": "#3b82f6",
            "INFO": "#10b981",
        }.get(r.risk_level, "#94a3b8")

        banner_safe = r.banner or "N/A"
        rows.append(f"""
        <tr>
            <td><strong>{r.port}</strong></td>
            <td>{r.service}</td>
            <td><span style="color:{color};font-weight:bold;">{r.risk_level}</span></td>
            <td><code>{banner_safe}</code></td>
        </tr>
        """)

    return f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Portwatch Audit - {target}</title>
    <style>
        body {{ font-family: -apple-system, sans-serif; background: #0a0f1d; color: #f8fafc; padding: 24px; }}
        h1 {{ color: #38bdf8; }}
        .card {{ background: #111c33; border: 1px solid #1e293b; padding: 20px; border-radius: 8px; margin-bottom: 20px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 12px; }}
        th, td {{ padding: 10px; border-bottom: 1px solid #1e293b; text-align: left; font-size: 14px; }}
        th {{ background: #030712; color: #94a3b8; }}
        code {{ color: #cbd5e1; font-size: 13px; }}
    </style>
</head>
<body>
    <h1>Portwatch Audit — {target}</h1>
    <div class="card">
        <h2>Open Services & Security Risk Evaluation</h2>
        <p>Scanned <strong>{len(results)}</strong> ports | Discovered <strong>{len(open_ports)}</strong> open endpoints.</p>
        <table>
            <thead>
                <tr><th>Port</th><th>Service</th><th>Risk Level</th><th>Fingerprint Banner</th></tr>
            </thead>
            <tbody>
                {''.join(rows) if rows else '<tr><td colspan="4">No open ports discovered.</td></tr>'}
            </tbody>
        </table>
    </div>
</body>
</html>"""
