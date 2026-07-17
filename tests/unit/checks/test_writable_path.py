import unittest
import os
from unittest.mock import patch
from privesc_assistant.checks.linux.writable_path import WritablePathCheck, get_path_dirs, check_writable_dirs, detect_path_hijack_opportunity
from privesc_assistant.core.scan_context import ScanContext
from privesc_assistant.core.finding import Severity
import datetime

class TestWritablePathCheck(unittest.TestCase):
    def setUp(self):
        self.context = ScanContext(
            target_os="linux",
            hostname="test",
            timestamp=datetime.datetime.now(),
            config={},
            is_root=False
        )

    @patch.dict(os.environ, {"PATH": os.pathsep.join(["/usr/local/bin", "/usr/bin", "/custom/path"])})
    def test_get_path_dirs(self):
        dirs = get_path_dirs()
        self.assertEqual(len(dirs), 3)
        self.assertEqual(dirs[0], "/usr/local/bin")
        self.assertEqual(dirs[1], "/usr/bin")
        self.assertEqual(dirs[2], "/custom/path")

    @patch('os.path.exists')
    @patch('os.path.isdir')
    @patch('os.access')
    def test_check_writable_dirs(self, mock_access, mock_isdir, mock_exists):
        mock_exists.return_value = True
        mock_isdir.return_value = True
        
        # Make only /custom/path writable
        def side_effect(path, mode):
            if path == "/custom/path" and mode == os.W_OK:
                return True
            return False
            
        mock_access.side_effect = side_effect
        
        dirs = ["/usr/local/bin", "/usr/bin", "/custom/path"]
        writable = check_writable_dirs(dirs)
        
        self.assertEqual(len(writable), 1)
        self.assertEqual(writable[0], "/custom/path")

    def test_detect_path_hijack_opportunity(self):
        writable = ["/custom/path"]
        
        # Test without sudo commands
        opps = detect_path_hijack_opportunity(self.context, writable)
        self.assertEqual(len(opps), 1)
        self.assertIn("High risk of PATH hijacking", opps[0][1])
        
        # Test with sudo commands
        self.context.config["sudo_commands"] = ["/bin/cat file"]
        opps_sudo = detect_path_hijack_opportunity(self.context, writable)
        self.assertEqual(len(opps_sudo), 1)
        self.assertIn("user has sudo privileges", opps_sudo[0][1])

    @patch('privesc_assistant.checks.linux.writable_path.get_path_dirs')
    @patch('privesc_assistant.checks.linux.writable_path.check_writable_dirs')
    def test_check_run(self, mock_check, mock_get):
        mock_get.return_value = ["/usr/bin", "/custom/path"]
        mock_check.return_value = ["/custom/path"]
        
        check = WritablePathCheck()
        findings = check.run(self.context)
        
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.HIGH)
        self.assertIn("/custom/path", findings[0].title)

if __name__ == '__main__':
    unittest.main()
