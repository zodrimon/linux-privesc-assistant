import unittest
import tempfile
import os
import stat
import datetime
from unittest.mock import patch, MagicMock

from privesc_assistant.core.engine import ScanEngine
from privesc_assistant.core.scan_context import ScanContext
from privesc_assistant.core.finding import Severity

class TestFullScanIntegration(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root_dir = self.temp_dir.name
        
        # Setup context
        self.context = ScanContext(
            target_os="linux",
            hostname="test-integration",
            timestamp=datetime.datetime.now(),
            config={},
            is_root=False
        )
        self.engine = ScanEngine(config={})

    def tearDown(self):
        self.temp_dir.cleanup()

    @patch('privesc_assistant.checks.linux.suid_sgid.find_suid_binaries')
    @patch('privesc_assistant.checks.linux.weak_permissions.find_world_writable_files')
    @patch('privesc_assistant.checks.linux.weak_permissions.check_passwd_shadow_perms')
    @patch('privesc_assistant.checks.linux.weak_permissions.check_ssh_key_perms')
    @patch('privesc_assistant.checks.linux.weak_permissions.find_root_owned_user_writable_files')
    @patch('privesc_assistant.checks.linux.misconfigurations.check_writable_etc_passwd')
    @patch('privesc_assistant.checks.linux.cron_jobs.enumerate_system_cron')
    @patch('privesc_assistant.checks.linux.cron_jobs.enumerate_user_cron')
    @patch('privesc_assistant.checks.linux.cron_jobs._extract_paths_from_cmd')
    def test_full_scan_engine(self, mock_extract, mock_user_cron, mock_sys_cron, 
                             mock_writable_passwd, mock_root_writable, mock_ssh, 
                             mock_critical, mock_world_writable, mock_find_suid):
        
        # Mock SUID file
        suid_file = os.path.join(self.root_dir, "bin", "custom_suid")
        mock_find_suid.return_value = [suid_file]
        
        # Mock writable passwd
        mock_writable_passwd.return_value = True
        
        
        # We need a real file to trigger analyze_script
        vuln_script = os.path.join(self.root_dir, "vuln.sh")
        with open(vuln_script, "w") as f:
            f.write("#!/bin/sh\necho vulnerable")
        # make it world writable
        os.chmod(vuln_script, stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)
        
        # Mock exploitable cron job
        mock_sys_cron.return_value = [("mocked_source", f"* * * * * root {vuln_script}")]
        mock_user_cron.return_value = []
        mock_extract.return_value = [vuln_script]
        
        # Prevent other checks from interfering or adding noise
        mock_world_writable.return_value = []
        mock_critical.return_value = []
        mock_ssh.return_value = []
        mock_root_writable.return_value = []
        
        # Run scan
        findings = self.engine.run(self.context)
        
        # Assertions
        titles = [f.title for f in findings]
        print("TITLES:", titles)
        
        # SUID finding from SUIDCheck
        self.assertTrue(any("SUID Binary" in t for t in titles))
        
        # Cron finding from CronJobsCheck
        self.assertTrue(any("Writable Cron Script" in t for t in titles))
        
        # Writable passwd finding from MisconfigurationsCheck
        self.assertTrue(any("Writable /etc/passwd" in t for t in titles))
        
        # Ensure correct severities
        suid_findings = [f for f in findings if "SUID Binary" in f.title]
        self.assertGreaterEqual(len(suid_findings), 1)
        
        passwd_findings = [f for f in findings if "Writable /etc/passwd" in f.title]
        self.assertGreaterEqual(len(passwd_findings), 1)
        self.assertEqual(passwd_findings[0].severity, Severity.CRITICAL)

if __name__ == '__main__':
    unittest.main()
