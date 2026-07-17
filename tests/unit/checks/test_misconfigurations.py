import unittest
from unittest.mock import patch, MagicMock, mock_open
import os
import stat
from privesc_assistant.checks.linux.misconfigurations import (
    MisconfigurationsCheck, check_sudo_permissions, check_docker_lxd_group_membership,
    check_nfs_no_root_squash, check_writable_etc_passwd, check_interesting_env_variables,
    check_readable_history_files, check_ssh_config_weaknesses, check_root_processes_for_exploitable_binaries
)
from privesc_assistant.core.scan_context import ScanContext
from privesc_assistant.core.finding import Severity
import datetime

class TestMisconfigurationsCheck(unittest.TestCase):
    def setUp(self):
        self.context = ScanContext(
            target_os="linux",
            hostname="test",
            timestamp=datetime.datetime.now(),
            config={},
            is_root=False
        )

    @patch('subprocess.run')
    def test_check_sudo_permissions(self, mock_run):
        mock_result = MagicMock()
        mock_result.stdout = "Matching Defaults entries for user on this host:\n    env_reset\n\nUser user may run the following commands on this host:\n    (ALL : ALL) NOPASSWD: ALL\n"
        mock_run.return_value = mock_result
        
        issues = check_sudo_permissions()
        self.assertEqual(len(issues), 1)
        self.assertIn("(ALL : ALL) NOPASSWD: ALL", issues[0][0])

    @patch('privesc_assistant.checks.linux.misconfigurations.os.getuid', create=True)
    def test_check_docker_lxd_group_membership(self, mock_getuid):
        import privesc_assistant.checks.linux.misconfigurations as misconfig
        
        # Manually mock pwd and grp for this test
        mock_pwd = MagicMock()
        mock_grp = MagicMock()
        
        misconfig.pwd = mock_pwd
        misconfig.grp = mock_grp
        
        mock_getuid.return_value = 1000
        
        mock_pw = MagicMock()
        mock_pw.pw_name = "testuser"
        mock_pw.pw_gid = 1000
        mock_pwd.getpwuid.return_value = mock_pw
        
        mock_g1 = MagicMock()
        mock_g1.gr_name = "testgroup"
        mock_g1.gr_mem = ["testuser"]
        
        mock_g2 = MagicMock()
        mock_g2.gr_name = "docker"
        mock_g2.gr_mem = ["testuser", "other"]
        
        mock_grp.getgrall.return_value = [mock_g1, mock_g2]
        
        mock_primary = MagicMock()
        mock_primary.gr_name = "testgroup"
        mock_grp.getgrgid.return_value = mock_primary
        
        groups = check_docker_lxd_group_membership()
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0], "docker")

    @patch('builtins.open', new_callable=mock_open, read_data="/home *(rw,sync,no_root_squash)\n# /opt *(ro)\n")
    @patch('os.path.exists')
    def test_check_nfs_no_root_squash(self, mock_exists, mock_file):
        mock_exists.return_value = True
        exports = check_nfs_no_root_squash()
        self.assertEqual(len(exports), 1)
        self.assertIn("no_root_squash", exports[0])

    @patch('os.access')
    @patch('os.path.exists')
    def test_check_writable_etc_passwd(self, mock_exists, mock_access):
        mock_exists.return_value = True
        mock_access.return_value = True
        self.assertTrue(check_writable_etc_passwd())

    @patch.dict(os.environ, {"LD_PRELOAD": "/tmp/evil.so", "LD_LIBRARY_PATH": "/tmp"})
    def test_check_interesting_env_variables(self):
        issues = check_interesting_env_variables()
        self.assertEqual(len(issues), 2)
        vars_found = [i[0] for i in issues]
        self.assertIn("LD_PRELOAD", vars_found)
        self.assertIn("LD_LIBRARY_PATH", vars_found)

    @patch('privesc_assistant.checks.linux.misconfigurations.check_sudo_permissions')
    @patch('privesc_assistant.checks.linux.misconfigurations.check_docker_lxd_group_membership')
    @patch('privesc_assistant.checks.linux.misconfigurations.check_nfs_no_root_squash')
    @patch('privesc_assistant.checks.linux.misconfigurations.check_writable_etc_passwd')
    @patch('privesc_assistant.checks.linux.misconfigurations.check_interesting_env_variables')
    @patch('privesc_assistant.checks.linux.misconfigurations.check_readable_history_files')
    @patch('privesc_assistant.checks.linux.misconfigurations.check_ssh_config_weaknesses')
    @patch('privesc_assistant.checks.linux.misconfigurations.check_root_processes_for_exploitable_binaries')
    def test_check_run(self, mock_proc, mock_ssh, mock_hist, mock_env, mock_passwd, mock_nfs, mock_docker, mock_sudo):
        mock_sudo.return_value = [("ALL", "NOPASSWD")]
        mock_docker.return_value = ["docker"]
        mock_nfs.return_value = ["/home *(no_root_squash)"]
        mock_passwd.return_value = True
        mock_env.return_value = [("LD_PRELOAD", "/tmp/x")]
        mock_hist.return_value = ["/home/user/.bash_history"]
        mock_ssh.return_value = ["PermitRootLogin yes"]
        mock_proc.return_value = ["mysql --user=root"]
        
        check = MisconfigurationsCheck()
        findings = check.run(self.context)
        
        self.assertEqual(len(findings), 8)
        
        severities = [f.severity for f in findings]
        self.assertEqual(severities.count(Severity.CRITICAL), 2) # docker, writable passwd
        self.assertEqual(severities.count(Severity.HIGH), 2) # sudo, nfs
        self.assertEqual(severities.count(Severity.MEDIUM), 3) # env, ssh, proc
        self.assertEqual(severities.count(Severity.LOW), 1) # history

if __name__ == '__main__':
    unittest.main()
