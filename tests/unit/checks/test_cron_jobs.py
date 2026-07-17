import unittest
from unittest.mock import patch, mock_open, MagicMock
from privesc_assistant.checks.linux.cron_jobs import (
    CronJobsCheck, enumerate_system_cron, enumerate_user_cron,
    detect_writable_cron_scripts, detect_wildcard_injection_risk
)
from privesc_assistant.core.scan_context import ScanContext
from privesc_assistant.core.finding import Severity
import datetime
import os

class TestCronJobsCheck(unittest.TestCase):
    def setUp(self):
        self.context = ScanContext(
            target_os="linux",
            hostname="test",
            timestamp=datetime.datetime.now(),
            config={},
            is_root=False
        )

    @patch('builtins.open', new_callable=mock_open, read_data="* * * * * root /usr/bin/script.sh\n# comment\n")
    @patch('glob.glob')
    @patch('os.path.isfile')
    def test_enumerate_system_cron(self, mock_isfile, mock_glob, mock_file):
        mock_glob.return_value = ["/etc/cron.d/test"]
        mock_isfile.return_value = True
        
        entries = enumerate_system_cron()
        self.assertEqual(len(entries), 2)  # One from /etc/crontab, one from /etc/cron.d/test
        self.assertEqual(entries[0][1], "* * * * * root /usr/bin/script.sh")

    @patch('subprocess.run')
    @patch('os.walk')
    def test_enumerate_user_cron(self, mock_walk, mock_run):
        mock_result = MagicMock()
        mock_result.stdout = "* * * * * /tmp/test.sh\n"
        mock_run.return_value = mock_result
        mock_walk.return_value = []
        
        entries = enumerate_user_cron()
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0][1], "* * * * * /tmp/test.sh")

    @patch('os.path.exists')
    @patch('os.path.isfile')
    @patch('os.access')
    def test_detect_writable_cron_scripts(self, mock_access, mock_isfile, mock_exists):
        mock_exists.return_value = True
        mock_isfile.return_value = True
        
        def side_effect(path, mode):
            if path == "/tmp/writable.sh" and mode == os.W_OK:
                return True
            return False
            
        mock_access.side_effect = side_effect
        
        entries = [
            ("source1", "/tmp/writable.sh"),
            ("source2", "/usr/bin/secure.sh")
        ]
        
        writable = detect_writable_cron_scripts(entries)
        self.assertEqual(len(writable), 1)
        self.assertEqual(writable[0][1], "/tmp/writable.sh")

    def test_detect_wildcard_injection_risk(self):
        entries = [
            ("source1", "tar -cf archive.tar *"),
            ("source2", "echo *"),
            ("source3", "chown root:root *")
        ]
        
        risks = detect_wildcard_injection_risk(entries)
        self.assertEqual(len(risks), 2)
        
        cmds = [cmd for _, cmd in risks]
        self.assertIn("tar -cf archive.tar *", cmds)
        self.assertIn("chown root:root *", cmds)

    @patch('privesc_assistant.checks.linux.cron_jobs.enumerate_system_cron')
    @patch('privesc_assistant.checks.linux.cron_jobs.enumerate_user_cron')
    @patch('privesc_assistant.checks.linux.cron_jobs.detect_writable_cron_scripts')
    @patch('privesc_assistant.checks.linux.cron_jobs.detect_wildcard_injection_risk')
    def test_check_run(self, mock_wildcard, mock_writable, mock_user, mock_sys):
        mock_sys.return_value = [("sys", "cmd")]
        mock_user.return_value = [("user", "cmd2")]
        mock_writable.return_value = [("sys", "/tmp/writable.sh")]
        mock_wildcard.return_value = [("user", "tar *")]
        
        check = CronJobsCheck()
        findings = check.run(self.context)
        
        self.assertEqual(len(findings), 3) # 1 CRITICAL, 1 HIGH, 1 INFO
        severities = [f.severity for f in findings]
        self.assertIn(Severity.CRITICAL, severities)
        self.assertIn(Severity.HIGH, severities)
        self.assertIn(Severity.INFO, severities)

if __name__ == '__main__':
    unittest.main()
