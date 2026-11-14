"""Tests for portwatch presets and scan timing modules."""

import unittest
import time
from portwatch.presets import get_preset_ports, list_available_presets, SCAN_PRESETS
from portwatch.timing import ScanTimingMetrics


class TestPresetsAndTiming(unittest.TestCase):
    def test_presets(self):
        presets = list_available_presets()
        self.assertIn("web", presets)
        self.assertIn("databases", presets)
        self.assertIn("fast", presets)

        web_ports = get_preset_ports("web")
        self.assertIn(80, web_ports)
        self.assertIn(443, web_ports)

        unknown_ports = get_preset_ports("nonexistent_preset")
        self.assertEqual(unknown_ports, SCAN_PRESETS["fast"])

    def test_scan_timing_metrics(self):
        metrics = ScanTimingMetrics(target="127.0.0.1", ports_scanned=100, open_ports_count=3)
        time.sleep(0.01)
        metrics.finish()

        self.assertTrue(metrics.elapsed_seconds > 0)
        self.assertTrue(metrics.ports_per_second > 0)

        data = metrics.to_dict()
        self.assertEqual(data["target"], "127.0.0.1")
        self.assertEqual(data["ports_scanned"], 100)
        self.assertEqual(data["open_ports_count"], 3)

        summary = metrics.summary_text()
        self.assertIn("127.0.0.1", summary)
        self.assertIn("100 ports", summary)


if __name__ == "__main__":
    unittest.main()
