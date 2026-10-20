
import tempfile
import unittest
from pathlib import Path

from main import analyze_log_file, create_report


class TestLogAnalyzer(unittest.TestCase):

    def analyze_text(self, text):
        """Create a temporary log file and analyze it."""
        with tempfile.TemporaryDirectory() as folder:
            log_path = Path(folder) / "test.log"
            log_path.write_text(text, encoding="utf-8")
            return analyze_log_file(log_path)

    def test_counts_sample_logs(self):
        log_path = Path(__file__).resolve().parent / "sample.log"
        results = analyze_log_file(log_path)

        self.assertEqual(results["total_lines"], 12)
        self.assertEqual(results["successful_logins"], 4)
        self.assertEqual(sum(results["failed_logins"].values()), 6)
        self.assertEqual(sum(results["unauthorized_ips"].values()), 2)

    def test_repeated_failed_logins_trigger_alert(self):
        logs = (
            "WARNING Failed login for user admin from 192.0.2.10\n"
            "WARNING Failed login for user admin from 192.0.2.10\n"
            "WARNING Failed login for user admin from 192.0.2.10\n"
        )

        results = self.analyze_text(logs)

        self.assertEqual(results["alerts"]["192.0.2.10"], 3)

    def test_two_failed_logins_do_not_trigger_alert(self):
        logs = (
            "WARNING Failed login for user admin from 192.0.2.20\n"
            "WARNING Failed login for user admin from 192.0.2.20\n"
        )

        results = self.analyze_text(logs)

        self.assertNotIn("192.0.2.20", results["alerts"])

    def test_empty_file(self):
        results = self.analyze_text("")

        self.assertEqual(results["total_lines"], 0)
        self.assertEqual(results["successful_logins"], 0)
        self.assertEqual(results["alerts"], {})

    def test_report_contains_title(self):
        results = self.analyze_text(
            "INFO Login successful for user test from 192.0.2.30\n"
        )

        report = create_report(results)

        self.assertIn("CYBERSECURITY LOG ANALYSIS REPORT", report)
        self.assertIn("Successful logins: 1", report)


if __name__ == "__main__":
    unittest.main()
