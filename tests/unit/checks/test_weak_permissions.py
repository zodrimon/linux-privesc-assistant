import unittest
from unittest.mock import patch, MagicMock
from privesc_assistant.checks.linux.weak_permissions import (
    WeakPermissionsCheck, find_world_writable_files, find_world_writable_dirs,
    check_passwd_shadow_perms, check_ssh_key_perms, find_root_owned_user_writable_files
)
from privesc_assistant.core.scan_context import ScanContext
from privesc_assistant.core.finding import Severity
import datetime
import stat
import os

class TestWeakPermissionsCheck(unittest.TestCase):
    def setUp(self):
        self.context = ScanContext(
            target_os="linux",
            hostname="test",
            timestamp=datetime.datetime.now(),
            config={"weak_permissions_scopes": ["/test_scope"]},
            is_root=False
        )

    @patch('privesc_assistant.checks.linux.weak_permissions.os.stat')
    @patch('privesc_assistant.checks.linux.weak_permissions.os.path.exists')
    @patch('privesc_assistant.checks.linux.weak_permissions.os.walk')
    def test_find_world_writable_files(self, mock_walk, mock_exists, mock_stat):
        mock_exists.return_value = True
        mock_walk.return_value = [("/test_scope", [], ["file1", "file2"])]
        
        # Make file1 world-writable, file2 not
        def stat_side_effect(path):
            mock_st = MagicMock()
            if path.endswith("file1"):
                mock_st.st_mode = stat.S_IWOTH
            else:
                mock_st.st_mode = 0
            return mock_st
            
        mock_stat.side_effect = stat_side_effect
        
        files = find_world_writable_files(["/test_scope"])
        self.assertEqual(len(files), 1)
        # Note: os.path.join uses backslashes on Windows, so we use os.path.join for assertions or just normalize
        self.assertEqual(files[0].replace('\\', '/'), "/test_scope/file1")

    @patch('privesc_assistant.checks.linux.weak_permissions.os.stat')
    @patch('privesc_assistant.checks.linux.weak_permissions.os.path.exists')
    def test_check_passwd_shadow_perms(self, mock_exists, mock_stat):
        mock_exists.return_value = True
        
        def stat_side_effect(path):
            mock_st = MagicMock()
            if path == "/etc/passwd":
                mock_st.st_mode = stat.S_IWOTH # World writable
            elif path == "/etc/shadow":
                mock_st.st_mode = stat.S_IROTH # World readable
            elif path == "/etc/sudoers":
                mock_st.st_mode = 0
            return mock_st
            
        mock_stat.side_effect = stat_side_effect
        
        issues = check_passwd_shadow_perms()
        self.assertEqual(len(issues), 2)
        paths = [i[0] for i in issues]
        self.assertIn("/etc/passwd", paths)
        self.assertIn("/etc/shadow", paths)

    @patch('privesc_assistant.checks.linux.weak_permissions.find_world_writable_files')
    @patch('privesc_assistant.checks.linux.weak_permissions.find_world_writable_dirs')
    @patch('privesc_assistant.checks.linux.weak_permissions.check_passwd_shadow_perms')
    @patch('privesc_assistant.checks.linux.weak_permissions.check_ssh_key_perms')
    @patch('privesc_assistant.checks.linux.weak_permissions.find_root_owned_user_writable_files')
    def test_check_run(self, mock_root, mock_ssh, mock_passwd, mock_dirs, mock_files):
        mock_passwd.return_value = [("/etc/passwd", "World writable")]
        mock_ssh.return_value = []
        mock_root.return_value = ["/usr/bin/root_owned"]
        mock_files.return_value = ["/tmp/ww_file"]
        mock_dirs.return_value = ["/tmp/ww_dir"]
        
        check = WeakPermissionsCheck()
        findings = check.run(self.context)
        
        self.assertEqual(len(findings), 4) # Critical file, Root-owned, WW files, WW dirs
        
        severities = [f.severity for f in findings]
        self.assertEqual(severities.count(Severity.CRITICAL), 1)
        self.assertEqual(severities.count(Severity.HIGH), 1)
        self.assertEqual(severities.count(Severity.MEDIUM), 1)
        self.assertEqual(severities.count(Severity.INFO), 1)

if __name__ == '__main__':
    unittest.main()
