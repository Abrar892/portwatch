"""Test suite for portwatch."""
import unittest
from unittest.mock import patch, MagicMock
from portwatch.services import COMMON_PORTS, TOP_PORTS
from portwatch.scanner import PortScanner, ScanResult
from portwatch.reporter import generate_text_report, generate_html_report


class TestPortwatch(unittest.TestCase):
    def test_services_preset(self):
        self.assertIn(80, COMMON_PORTS)
        self.assertIn(22, TOP_PORTS)

    @patch("socket.socket")
    def test_scan_probe_open_port(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_sock.recv.return_value = b"SSH-2.0-OpenSSH_9.0\r\n"
        mock_socket_cls.return_value = mock_sock

        scanner = PortScanner("127.0.0.1", timeout=1.0)
        res = scanner.probe_port(22)
        self.assertTrue(res.is_open)
        self.assertEqual(res.service, "SSH")
        self.assertIn("OpenSSH", res.banner)

    @patch("socket.socket")
    def test_scan_closed_port(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 111  # ECONNREFUSED
        mock_socket_cls.return_value = mock_sock

        scanner = PortScanner("127.0.0.1", timeout=0.2)
        res = scanner.probe_port(65530)
        self.assertFalse(res.is_open)

    def test_risk_evaluation(self):
        scanner = PortScanner("127.0.0.1")
        self.assertEqual(scanner._evaluate_risk(21, "FTP"), "HIGH")
        self.assertEqual(scanner._evaluate_risk(6379, "Redis"), "MEDIUM")
        self.assertEqual(scanner._evaluate_risk(80, "HTTP"), "LOW")

    def test_reports_generation(self):
        results = [
            ScanResult(port=22, is_open=True, service="SSH", banner="OpenSSH", risk_level="INFO"),
            ScanResult(port=80, is_open=False, service="HTTP"),
        ]
        text = generate_text_report("127.0.0.1", results)
        self.assertIn("PORTWATCH", text)
        self.assertIn("Port 22", text)

        html = generate_html_report("127.0.0.1", results)
        self.assertIn("<!DOCTYPE html>", html)
        self.assertIn("OpenSSH", html)


if __name__ == "__main__":
    unittest.main()
