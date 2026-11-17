"""Tests for portwatch CVE knowledgebase lookup and JSON reporting modules."""

import unittest
import tempfile
import os
import json
from portwatch.scanner import ScanResult
from portwatch.cve_lookup import CVELookup
from portwatch.json_reporter import PortwatchJsonReporter
from portwatch.timing import ScanTimingMetrics


class TestCVELookupAndJsonReport(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.sample_results = [
            ScanResult(port=80, is_open=True, service="HTTP", banner="Apache"),
            ScanResult(port=445, is_open=True, service="SMB", banner=""),
            ScanResult(port=22, is_open=False, service="SSH", banner=""),
        ]

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_cve_lookup_smb(self):
        advisories = CVELookup.find_advisories_for_port(445)
        self.assertTrue(len(advisories) > 0)
        self.assertEqual(advisories[0].cve_id, "CVE-2017-0144")
        self.assertEqual(advisories[0].severity, "CRITICAL")

    def test_cve_audit_multiple(self):
        advisories = CVELookup.audit_scan_results([23, 6379, 80])
        cve_ids = [a.cve_id for a in advisories]
        self.assertIn("CVE-GEN-TELNET", cve_ids)
        self.assertIn("CVE-GEN-REDIS", cve_ids)

    def test_json_reporter(self):
        timing = ScanTimingMetrics(target="192.168.1.1", ports_scanned=3, open_ports_count=2)
        out_file = os.path.join(self.tmp_dir.name, "report.json")
        json_str = PortwatchJsonReporter.generate("192.168.1.1", self.sample_results, timing=timing, output_path=out_file)

        self.assertTrue(os.path.exists(out_file))
        data = json.loads(json_str)
        self.assertEqual(data["target"], "192.168.1.1")
        self.assertEqual(data["open_ports_count"], 2)
        self.assertTrue(len(data["vulnerability_advisories"]) > 0)
        self.assertEqual(data["vulnerability_advisories"][0]["port"], 445)


if __name__ == "__main__":
    unittest.main()
