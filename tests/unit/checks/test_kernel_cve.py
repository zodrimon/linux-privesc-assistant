import unittest
from unittest.mock import patch, mock_open, MagicMock
from privesc_assistant.checks.linux.kernel_cve import (
    KernelCveCheck, get_kernel_version, get_os_release_info,
    match_known_kernel_cves, flag_exploit_suggestions, _parse_version
)
from privesc_assistant.core.scan_context import ScanContext
from privesc_assistant.core.finding import Severity
import datetime
import json
import os

class TestKernelCveCheck(unittest.TestCase):
    def setUp(self):
        self.context = ScanContext(
            target_os="linux",
            hostname="test",
            timestamp=datetime.datetime.now(),
            config={},
            is_root=False
        )

    @patch('subprocess.run')
    def test_get_kernel_version(self, mock_run):
        mock_result = MagicMock()
        mock_result.stdout = "5.15.0-72-generic\n"
        mock_run.return_value = mock_result
        
        self.assertEqual(get_kernel_version(), "5.15.0-72-generic")

    @patch('builtins.open', new_callable=mock_open, read_data='PRETTY_NAME="Ubuntu 20.04"\nID=ubuntu\n')
    @patch('os.path.exists')
    def test_get_os_release_info(self, mock_exists, mock_file):
        mock_exists.return_value = True
        info = get_os_release_info()
        self.assertEqual(info.get("PRETTY_NAME"), "Ubuntu 20.04")
        self.assertEqual(info.get("ID"), "ubuntu")

    def test_parse_version(self):
        self.assertEqual(_parse_version("5.15.0-72-generic"), (5, 15, 0))
        self.assertEqual(_parse_version("4.15"), (4, 15))
        self.assertEqual(_parse_version("invalid"), (0, 0, 0))

    def test_match_known_kernel_cves(self):
        fake_db = [
            {"cve": "CVE-TEST-1", "affected_versions": "5.0 <= x < 5.10"},
            {"cve": "CVE-TEST-2", "affected_versions": "all"}
        ]
        
        # Test file reading mock
        with patch('builtins.open', mock_open(read_data=json.dumps(fake_db))):
            # Version in range
            matches = match_known_kernel_cves("5.5.0-generic", db_path="dummy")
            self.assertEqual(len(matches), 2)
            cves = [m["cve"] for m in matches]
            self.assertIn("CVE-TEST-1", cves)
            self.assertIn("CVE-TEST-2", cves)
            
            # Version out of range
            matches_out = match_known_kernel_cves("5.11.0", db_path="dummy")
            self.assertEqual(len(matches_out), 1)
            self.assertEqual(matches_out[0]["cve"], "CVE-TEST-2")

    def test_flag_exploit_suggestions(self):
        matches = [
            {"cve": "CVE-1", "name": "Name1", "exploit_link": "http://link1"},
            {"cve": "CVE-2", "name": "Name2"}
        ]
        suggestions = flag_exploit_suggestions(matches)
        self.assertEqual(len(suggestions), 2)
        self.assertEqual(suggestions[0], ("CVE-1", "Name1", "http://link1"))
        self.assertEqual(suggestions[1], ("CVE-2", "Name2", "No link available"))

    @patch('privesc_assistant.checks.linux.kernel_cve.get_kernel_version')
    @patch('privesc_assistant.checks.linux.kernel_cve.get_os_release_info')
    @patch('privesc_assistant.checks.linux.kernel_cve.match_known_kernel_cves')
    def test_check_run(self, mock_match, mock_os, mock_kver):
        mock_kver.return_value = "5.8.0"
        mock_os.return_value = {"PRETTY_NAME": "Linux"}
        
        # With matches -> CRITICAL
        mock_match.return_value = [{"cve": "CVE-1", "name": "Test", "exploit_link": "link"}]
        check = KernelCveCheck()
        findings = check.run(self.context)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.CRITICAL)
        self.assertIn("CVE-1", findings[0].description)
        
        # Without matches -> INFO
        mock_match.return_value = []
        findings_info = check.run(self.context)
        self.assertEqual(len(findings_info), 1)
        self.assertEqual(findings_info[0].severity, Severity.INFO)

if __name__ == '__main__':
    unittest.main()
