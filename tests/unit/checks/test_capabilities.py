import unittest
from unittest.mock import patch, MagicMock
from privesc_assistant.checks.linux.capabilities import CapabilitiesCheck, enumerate_capabilities, cross_reference_dangerous_caps
from privesc_assistant.core.scan_context import ScanContext
from privesc_assistant.core.finding import Severity
import datetime

class TestCapabilitiesCheck(unittest.TestCase):
    def setUp(self):
        self.context = ScanContext(
            target_os="linux",
            hostname="test",
            timestamp=datetime.datetime.now(),
            config={},
            is_root=False
        )

    @patch('subprocess.run')
    def test_enumerate_capabilities(self, mock_run):
        mock_result = MagicMock()
        mock_result.stdout = "/usr/bin/ping = cap_net_raw+ep\n/usr/bin/tar = cap_dac_override+ep\n\n"
        mock_run.return_value = mock_result
        
        entries = enumerate_capabilities()
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0][0], "/usr/bin/ping")
        self.assertEqual(entries[0][1], "cap_net_raw+ep")
        self.assertEqual(entries[1][0], "/usr/bin/tar")
        self.assertEqual(entries[1][1], "cap_dac_override+ep")

    def test_cross_reference_dangerous_caps(self):
        entries = [
            ("/usr/bin/ping", "cap_net_raw+ep"),
            ("/usr/bin/tar", "cap_dac_override+ep"),
            ("/usr/bin/python", "cap_setuid,cap_setgid+ep")
        ]
        
        dangerous = cross_reference_dangerous_caps(entries)
        
        # ping has cap_net_raw (not in DANGEROUS_CAPS)
        # tar has cap_dac_override
        # python has cap_setuid, cap_setgid
        self.assertEqual(len(dangerous), 2)
        
        # Tar
        self.assertEqual(dangerous[0][0], "/usr/bin/tar")
        self.assertIn("cap_dac_override", dangerous[0][2])
        
        # Python
        self.assertEqual(dangerous[1][0], "/usr/bin/python")
        self.assertIn("cap_setuid", dangerous[1][2])
        self.assertIn("cap_setgid", dangerous[1][2])

    @patch('privesc_assistant.checks.linux.capabilities.enumerate_capabilities')
    def test_check_run(self, mock_enum):
        mock_enum.return_value = [
            ("/usr/bin/ping", "cap_net_raw+ep"),
            ("/usr/bin/tar", "cap_dac_override+ep")
        ]
        
        check = CapabilitiesCheck()
        findings = check.run(self.context)
        
        # Expect 1 HIGH for tar, 1 INFO for ping
        self.assertEqual(len(findings), 2)
        
        severities = [f.severity for f in findings]
        self.assertIn(Severity.HIGH, severities)
        self.assertIn(Severity.INFO, severities)
        
        # Check non-linux OS
        windows_context = ScanContext(
            target_os="windows", hostname="test", timestamp=datetime.datetime.now(), config={}, is_root=False
        )
        windows_findings = check.run(windows_context)
        self.assertEqual(len(windows_findings), 0)

if __name__ == '__main__':
    unittest.main()
