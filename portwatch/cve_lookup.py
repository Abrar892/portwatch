"""cve_lookup.py — Local vulnerability and advisory knowledgebase mapper for portwatch."""

from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class VulnerabilityAdvisory:
    cve_id: str
    service: str
    port: int
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    description: str
    remediation: str


# Offline curated security advisory knowledgebase for common unencrypted or exposed network protocols
KNOWLEDGE_BASE: List[VulnerabilityAdvisory] = [
    VulnerabilityAdvisory(
        cve_id="CVE-2017-0144",
        service="SMB",
        port=445,
        severity="CRITICAL",
        description="EternalBlue remote code execution vulnerability in Microsoft SMBv1 server.",
        remediation="Disable SMBv1 immediately and patch to current OS security update.",
    ),
    VulnerabilityAdvisory(
        cve_id="CVE-GEN-TELNET",
        service="Telnet",
        port=23,
        severity="HIGH",
        description="Cleartext transmission of authentication credentials and remote shell session data.",
        remediation="Disable Telnet daemon; migrate to SSH on port 22.",
    ),
    VulnerabilityAdvisory(
        cve_id="CVE-GEN-FTP",
        service="FTP",
        port=21,
        severity="MEDIUM",
        description="Cleartext authentication and file data transfer susceptible to network eavesdropping.",
        remediation="Enforce SFTP or FTPS (FTP over TLS).",
    ),
    VulnerabilityAdvisory(
        cve_id="CVE-GEN-REDIS",
        service="Redis",
        port=6379,
        severity="HIGH",
        description="Default unauthenticated Redis key-value store exposed to public interface.",
        remediation="Bind Redis to 127.0.0.1, enable password authentication (requirepass), or use TLS.",
    ),
    VulnerabilityAdvisory(
        cve_id="CVE-GEN-RDP",
        service="RDP",
        port=3389,
        severity="HIGH",
        description="Exposed Remote Desktop protocol susceptible to brute-force attacks (BlueKeep risk).",
        remediation="Place RDP behind a secure VPN gateway or enforce Network Level Authentication (NLA).",
    ),
]


class CVELookup:
    """Matches discovered open ports and services with known security advisories."""

    @staticmethod
    def find_advisories_for_port(port: int) -> List[VulnerabilityAdvisory]:
        return [adv for adv in KNOWLEDGE_BASE if adv.port == port]

    @staticmethod
    def audit_scan_results(open_ports: List[int]) -> List[VulnerabilityAdvisory]:
        """Audit all open ports against knowledge base."""
        matched = []
        for p in open_ports:
            matched.extend(CVELookup.find_advisories_for_port(p))
        return matched
