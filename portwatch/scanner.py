"""TCP port scanner and banner grabber."""
import socket
from dataclasses import dataclass
from typing import Optional, List
from concurrent.futures import ThreadPoolExecutor
from portwatch.services import COMMON_PORTS


@dataclass
class ScanResult:
    port: int
    is_open: bool
    service: str
    banner: Optional[str] = None
    risk_level: str = "INFO"  # INFO, LOW, MEDIUM, HIGH


class PortScanner:
    def __init__(self, target: str, timeout: float = 1.0):
        self.target = target
        self.timeout = timeout

    def probe_port(self, port: int) -> ScanResult:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        try:
            res = s.connect_ex((self.target, port))
            if res == 0:
                service = COMMON_PORTS.get(port, "Unknown")
                banner = self._grab_banner(s, port)
                risk = self._evaluate_risk(port, service)
                return ScanResult(port=port, is_open=True, service=service, banner=banner, risk_level=risk)
            return ScanResult(port=port, is_open=False, service=COMMON_PORTS.get(port, "Unknown"))
        except Exception:
            return ScanResult(port=port, is_open=False, service=COMMON_PORTS.get(port, "Unknown"))
        finally:
            s.close()

    def _grab_banner(self, sock: socket.socket, port: int) -> Optional[str]:
        try:
            sock.settimeout(1.0)
            if port in (80, 8080):
                sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            elif port == 6379:
                sock.sendall(b"PING\r\n")
            data = sock.recv(256)
            if data:
                return data.decode("utf-8", errors="replace").strip()[:120]
        except Exception:
            pass
        return None

    def _evaluate_risk(self, port: int, service: str) -> str:
        # High-risk plaintext or direct database access exposed
        if port in (21, 23):  # FTP, Telnet
            return "HIGH"
        if port in (3306, 5432, 6379, 27017):  # Databases
            return "MEDIUM"
        if port in (80, 8080):  # Plain HTTP
            return "LOW"
        return "INFO"

    def scan_ports(self, ports: List[int], max_threads: int = 20) -> List[ScanResult]:
        results = []
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            for res in executor.map(self.probe_port, ports):
                results.append(res)
        return sorted(results, key=lambda x: x.port)
