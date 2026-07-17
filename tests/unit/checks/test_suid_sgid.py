import unittest
from unittest.mock import patch, MagicMock
from privesc_assistant.checks.linux.suid_sgid import SuidSgidCheck, find_suid_binaries, filter_known_safe_binaries, cross_reference_gtfobins
from privesc_assistant.core.scan_context import ScanContext
from privesc_assistant.core.finding import Severity
import datetime

class TestSuidSgidCheck(unittest.TestCase):
    def setUp(self):
        self.context = ScanContext(
            target_os="linux",
            hostname="test",
            timestamp=datetime.datetime.now(),
            config={},
            is_root=False
        )
        self.gtfobins_db = {
            "find": {"description": "exploitable", "url": "http://example.com/find"}
        }

    @patch('subprocess.run')
    def test_find_suid_binaries(self, mock_run):
        mock_result = MagicMock()
        mock_result.stdout = "/usr/bin/find\n/usr/bin/passwd\n/custom/suid_bin"
        mock_run.return_value = mock_result
        
        bins = find_suid_binaries()
        self.assertEqual(len(bins), 3)
        self.assertIn("/usr/bin/find", bins)

    def test_filter_known_safe_binaries(self):
        bins = ["/usr/bin/passwd", "/usr/bin/find", "/custom/bin"]
        dangerous, safe = filter_known_safe_binaries(bins)
        
        self.assertIn("/usr/bin/passwd", safe)
        self.assertIn("/usr/bin/find", dangerous)
        self.assertIn("/custom/bin", dangerous)

    def test_cross_reference_gtfobins(self):
        bins = ["/usr/bin/find", "/custom/bin"]
        matches = cross_reference_gtfobins(bins, self.gtfobins_db)
        
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0][0], "/usr/bin/find")
        self.assertEqual(matches[0][1]["description"], "exploitable")

    @patch('privesc_assistant.checks.linux.suid_sgid.find_sgid_binaries')
    @patch('privesc_assistant.checks.linux.suid_sgid.find_suid_binaries')
    @patch('privesc_assistant.checks.linux.suid_sgid.load_gtfobins_db')
    def test_check_run(self, mock_load_db, mock_find_suid, mock_find_sgid):
        mock_load_db.return_value = self.gtfobins_db
        mock_find_suid.return_value = ["/usr/bin/passwd", "/usr/bin/find", "/custom/bin"]
        mock_find_sgid.return_value = ["/usr/bin/wall"]
        
        check = SuidSgidCheck()
        findings = check.run(self.context)
        
        # We expect:
        # 1. Critical for find
        # 2. Medium for /custom/bin
        # 3. Info for safe suid (passwd)
        # 4. Info for sgid
        self.assertEqual(len(findings), 4)
        
        severities = [f.severity for f in findings]
        self.assertIn(Severity.CRITICAL, severities)
        self.assertIn(Severity.MEDIUM, severities)
        self.assertIn(Severity.INFO, severities)
        
        # Check non-linux OS
        windows_context = ScanContext(
            target_os="windows", hostname="test", timestamp=datetime.datetime.now(), config={}, is_root=False
        )
        windows_findings = check.run(windows_context)
        self.assertEqual(len(windows_findings), 0)

if __name__ == '__main__':
    unittest.main()
