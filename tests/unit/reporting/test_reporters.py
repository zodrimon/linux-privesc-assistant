import unittest
import json
import datetime
from privesc_assistant.core.finding import Finding, Severity
from privesc_assistant.core.scan_context import ScanContext
from privesc_assistant.reporting.terminal_reporter import TerminalReporter
from privesc_assistant.reporting.json_reporter import JsonReporter
from privesc_assistant.reporting.markdown_reporter import MarkdownReporter
from privesc_assistant.reporting.html_reporter import HtmlReporter

class TestReporters(unittest.TestCase):
    def setUp(self):
        self.context = ScanContext(
            target_os="linux",
            hostname="testhost",
            timestamp=datetime.datetime(2026, 1, 1, 12, 0, 0),
            config={},
            is_root=False
        )
        self.findings = [
            Finding("Test Crit", Severity.CRITICAL, "crit desc", "crit ev", "crit rem", [], "c1"),
            Finding("Test Info", Severity.INFO, "info desc", "info ev", "info rem", [], "c2")
        ]

    def test_terminal_reporter(self):
        reporter = TerminalReporter()
        output = reporter.render(self.findings, self.context)
        self.assertIn("testhost", output)
        self.assertIn("Test Crit", output)
        self.assertIn("Test Info", output)

    def test_json_reporter(self):
        reporter = JsonReporter()
        output = reporter.render(self.findings, self.context)
        parsed = json.loads(output)
        
        self.assertEqual(parsed["metadata"]["hostname"], "testhost")
        self.assertEqual(parsed["statistics"]["total_findings"], 2)
        self.assertEqual(parsed["statistics"]["severity_counts"]["CRITICAL"], 1)
        self.assertEqual(len(parsed["findings"]), 2)
        self.assertEqual(parsed["findings"][0]["title"], "Test Crit")

    def test_markdown_reporter(self):
        reporter = MarkdownReporter()
        output = reporter.render(self.findings, self.context)
        
        self.assertIn("# Linux Privilege Escalation Scan Report", output)
        self.assertIn("**Target OS:** linux", output)
        self.assertIn("### 1. Test Crit [CRITICAL]", output)
        self.assertIn("crit ev", output)

    def test_html_reporter(self):
        reporter = HtmlReporter()
        output = reporter.render(self.findings, self.context)
        
        self.assertIn("<!DOCTYPE html>", output)
        self.assertIn("Linux Privilege Escalation Scan Report", output)
        self.assertIn("Test Crit", output)
        self.assertIn("sev-CRITICAL", output)
        self.assertIn("CRITICAL</span></h3>", output)

if __name__ == '__main__':
    unittest.main()
