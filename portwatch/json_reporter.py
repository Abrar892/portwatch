"""json_reporter.py — Machine-readable JSON network security report generator for portwatch."""

from __future__ import annotations
import json
from typing import Dict, List, Any
from portwatch.scanner import ScanResult
from portwatch.cve_lookup import CVELookup, VulnerabilityAdvisory
from portwatch.timing import ScanTimingMetrics


class PortwatchJsonReporter:
    """Exports port scanning findings, service risks, and advisories to JSON."""

    @staticmethod
    def generate(
        target: str,
        results: List[ScanResult],
        timing: Optional[ScanTimingMetrics] = None,
        output_path: Optional[str] = None,
        indent: int = 2,
    ) -> str:
        open_ports = [r.port for r in results if r.is_open]
        advisories = CVELookup.audit_scan_results(open_ports)

        data: Dict[str, Any] = {
            "target": target,
            "total_ports_scanned": len(results),
            "open_ports_count": len(open_ports),
            "timing": timing.to_dict() if timing else None,
            "open_services": [
                {
                    "port": r.port,
                    "service": r.service,
                    "banner": r.banner,
                }
                for r in results if r.is_open
            ],
            "vulnerability_advisories": [
                {
                    "cve_id": adv.cve_id,
                    "service": adv.service,
                    "port": adv.port,
                    "severity": adv.severity,
                    "description": adv.description,
                    "remediation": adv.remediation,
                }
                for adv in advisories
            ],
        }

        json_str = json.dumps(data, indent=indent)
        if output_path:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(json_str)

        return json_str
