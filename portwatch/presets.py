"""presets.py — Target profile and port scanning presets for portwatch."""

from __future__ import annotations
from typing import Dict, List


SCAN_PRESETS: Dict[str, List[int]] = {
    "web": [80, 443, 8000, 8080, 8443, 8888, 9000],
    "databases": [1433, 1521, 3306, 5432, 6379, 27017, 9200, 9300],
    "remote_access": [21, 22, 23, 3389, 5900, 5901],
    "mail": [25, 110, 143, 465, 587, 993, 995],
    "fast": [21, 22, 80, 443, 8080],
}


def get_preset_ports(preset_name: str) -> List[int]:
    """Retrieve list of ports for a given preset name. Defaults to 'fast' if unknown."""
    return SCAN_PRESETS.get(preset_name.lower(), SCAN_PRESETS["fast"])


def list_available_presets() -> Dict[str, int]:
    """Return dict of preset name -> count of ports in preset."""
    return {k: len(v) for k, v in SCAN_PRESETS.items()}
