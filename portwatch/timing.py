"""timing.py — Scan execution performance metrics, rate monitoring, and benchmarking."""

from __future__ import annotations
import time
from dataclasses import dataclass, field
from typing import Dict, Any


@dataclass
class ScanTimingMetrics:
    target: str
    ports_scanned: int
    open_ports_count: int
    start_time: float = field(default_factory=time.time)
    end_time: float = field(default=0.0)

    def finish(self) -> None:
        self.end_time = time.time()

    @property
    def elapsed_seconds(self) -> float:
        end = self.end_time if self.end_time > 0 else time.time()
        return max(0.0001, end - self.start_time)

    @property
    def ports_per_second(self) -> float:
        return self.ports_scanned / self.elapsed_seconds

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "ports_scanned": self.ports_scanned,
            "open_ports_count": self.open_ports_count,
            "elapsed_seconds": round(self.elapsed_seconds, 3),
            "ports_per_second": round(self.ports_per_second, 1),
        }

    def summary_text(self) -> str:
        return (
            f"Scanned {self.ports_scanned} ports on {self.target} in "
            f"{self.elapsed_seconds:.2f}s ({self.ports_per_second:.1f} ports/sec). "
            f"Discovered {self.open_ports_count} open port(s)."
        )
