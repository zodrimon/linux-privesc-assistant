import os
import subprocess
import glob
try:
    import pwd
    import grp
except ImportError:
    pwd = None
    grp = None
import stat
from typing import List, Tuple, Dict
from privesc_assistant.checks.base import BaseCheck
from privesc_assistant.core.finding import Finding, Severity
from privesc_assistant.core.scan_context import ScanContext
from privesc_assistant.core.registry import register_check

def check_sudo_permissions() -> List[Tuple[str, str]]:
    """Runs 'sudo -l' and parses NOPASSWD or dangerous entries."""
    issues = []
    try:
        # Check if we can run sudo -l without a password prompt freezing us
        result = subprocess.run(["sudo", "-n", "-l"], capture_output=True, text=True, check=False)
        output = result.stdout
        
        if "NOPASSWD:" in output:
            lines = output.splitlines()
            for line in lines:
                if "NOPASSWD:" in line:
                    issues.append((line.strip(), "User can run commands via sudo without a password."))
    except FileNotFoundError:
        pass
        
    return issues

def check_docker_lxd_group_membership() -> List[str]:
    """Flags current user in docker or lxd groups."""
    dangerous_groups = []
    if pwd is None or grp is None:
        return dangerous_groups
        
    try:
        user = pwd.getpwuid(os.getuid()).pw_name  # type: ignore
        groups = [g.gr_name for g in grp.getgrall() if user in g.gr_mem]  # type: ignore
        
        # Also include primary group
        primary_group = grp.getgrgid(pwd.getpwuid(os.getuid()).pw_gid).gr_name  # type: ignore
        if primary_group not in groups:
            groups.append(primary_group)
            
        for d_group in ["docker", "lxd", "lxc"]:
            if d_group in groups:
                dangerous_groups.append(d_group)
    except KeyError:
        pass
    
    return dangerous_groups

def check_nfs_no_root_squash() -> List[str]:
    """Parses /etc/exports for no_root_squash."""
    exports = []
    if os.path.exists("/etc/exports"):
        try:
            with open("/etc/exports", "r") as f:
                for line in f:
                    if not line.strip().startswith("#") and "no_root_squash" in line:
                        exports.append(line.strip())
        except PermissionError:
            pass
    return exports

def check_writable_etc_passwd() -> bool:
    """Explicit standalone check for appending a root UID-0 user."""
    if os.path.exists("/etc/passwd"):
        return os.access("/etc/passwd", os.W_OK)
    return False

def check_interesting_env_variables() -> List[Tuple[str, str]]:
    """Flags LD_PRELOAD/LD_LIBRARY_PATH if set."""
    issues = []
    ld_preload = os.environ.get("LD_PRELOAD")
    if ld_preload:
        issues.append(("LD_PRELOAD", ld_preload))
        
    ld_lib_path = os.environ.get("LD_LIBRARY_PATH")
    if ld_lib_path:
        issues.append(("LD_LIBRARY_PATH", ld_lib_path))
        
    return issues

def check_readable_history_files() -> List[str]:
    """Scans shell history files for credentials/secrets."""
    readable = []
    home_dir = os.path.expanduser("~")
    hist_files = [".bash_history", ".zsh_history", ".mysql_history", ".psql_history", ".nano_history"]
    
    for h in hist_files:
        path = os.path.join(home_dir, h)
        if os.path.exists(path) and os.access(path, os.R_OK):
            # Check if file has some content
            if os.path.getsize(path) > 0:
                readable.append(path)
                
    return readable

def check_ssh_config_weaknesses() -> List[str]:
    """Flags weak sshd_config/ssh_config settings if readable."""
    weaknesses = []
    config_paths = ["/etc/ssh/sshd_config", "/etc/ssh/ssh_config"]
    
    for path in config_paths:
        if os.path.exists(path) and os.access(path, os.R_OK):
            try:
                with open(path, "r") as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("#"):
                            continue
                        if "PermitRootLogin yes" in line:
                            weaknesses.append(f"{path}: PermitRootLogin is enabled")
                        if "PasswordAuthentication yes" in line:
                            weaknesses.append(f"{path}: PasswordAuthentication is enabled")
            except PermissionError:
                pass
                
    return weaknesses

def check_root_processes_for_exploitable_binaries() -> List[str]:
    """Cross references running root processes against known privesc-relevant binaries."""
    # Not implementing full process scanning logic here to keep it simple,
    # as scanning /proc requires handling dynamic disappearing files.
    # Placeholder for checking if mysql/docker/etc are running as root.
    exploitable = []
    try:
        # Use ps command for a stable snapshot
        result = subprocess.run(["ps", "-eo", "user,command"], capture_output=True, text=True, check=False)
        for line in result.stdout.splitlines():
            if line.startswith("root "):
                cmd = line[5:].strip()
                if "mysql" in cmd and "--user=root" in cmd:
                    exploitable.append(cmd)
    except FileNotFoundError:
        pass
    return exploitable

@register_check
class MisconfigurationsCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "misconfigurations"

    @property
    def description(self) -> str:
        return "Checks for general system misconfigurations like sudo rules, docker groups, NFS exports, and env vars."

    @property
    def severity_hint(self) -> str:
        return "high"

    def run(self, context: ScanContext) -> List[Finding]:
        findings = []
        
        if context.target_os != "linux":
            return findings

        # Sudo permissions
        sudo_issues = check_sudo_permissions()
        for rule, issue in sudo_issues:
            findings.append(Finding(
                title="Dangerous Sudo Configuration",
                severity=Severity.HIGH,
                description=issue,
                evidence=rule,
                remediation="Remove NOPASSWD or restrict allowed commands.",
                references=["https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid"],
                check_id=self.name
            ))

        # Docker/LXD Groups
        docker_groups = check_docker_lxd_group_membership()
        if docker_groups:
            findings.append(Finding(
                title=f"Dangerous Group Membership: {', '.join(docker_groups)}",
                severity=Severity.CRITICAL,
                description="Current user is in a group that allows container creation. This can be trivially exploited to gain root access to the host.",
                evidence=f"Groups: {', '.join(docker_groups)}",
                remediation="Remove user from these groups if not strictly necessary.",
                references=["https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security"],
                check_id=self.name
            ))

        # NFS
        nfs_exports = check_nfs_no_root_squash()
        if nfs_exports:
            findings.append(Finding(
                title="NFS no_root_squash Enabled",
                severity=Severity.HIGH,
                description="NFS shares exported with no_root_squash allow an attacker to create SUID binaries on the share.",
                evidence="\n".join(nfs_exports),
                remediation="Change 'no_root_squash' to 'root_squash' in /etc/exports.",
                references=["https://book.hacktricks.xyz/linux-hardening/privilege-escalation/nfs-no_root_squash"],
                check_id=self.name
            ))

        # Writable /etc/passwd
        if check_writable_etc_passwd():
            findings.append(Finding(
                title="Writable /etc/passwd",
                severity=Severity.CRITICAL,
                description="The /etc/passwd file is writable. You can append a new user with UID 0 (root) and no password.",
                evidence="File: /etc/passwd",
                remediation="Run `chmod 644 /etc/passwd`.",
                references=["https://book.hacktricks.xyz/linux-hardening/privilege-escalation#etc-passwd"],
                check_id=self.name
            ))

        # Env vars
        env_vars = check_interesting_env_variables()
        for var, val in env_vars:
            findings.append(Finding(
                title=f"Dangerous Environment Variable: {var}",
                severity=Severity.MEDIUM,
                description=f"{var} is set, which can potentially be used to hijack shared library loading for SUID/sudo binaries.",
                evidence=f"{var}={val}",
                remediation="Unset this variable unless required for specific development tools.",
                references=["https://book.hacktricks.xyz/linux-hardening/privilege-escalation#ld_preload"],
                check_id=self.name
            ))

        # History files
        hist_files = check_readable_history_files()
        if hist_files:
            findings.append(Finding(
                title="Readable Shell History Files",
                severity=Severity.LOW,
                description="Shell history files are readable. They might contain plaintext credentials or sensitive commands.",
                evidence="\n".join(hist_files),
                remediation="Clear history and link history files to /dev/null if not needed.",
                references=[],
                check_id=self.name
            ))
            
        # SSH config
        ssh_weaknesses = check_ssh_config_weaknesses()
        if ssh_weaknesses:
            findings.append(Finding(
                title="Weak SSH Configuration",
                severity=Severity.MEDIUM,
                description="Found weak settings in SSH configuration files.",
                evidence="\n".join(ssh_weaknesses),
                remediation="Disable PermitRootLogin and PasswordAuthentication if possible.",
                references=[],
                check_id=self.name
            ))
            
        # Root processes
        root_procs = check_root_processes_for_exploitable_binaries()
        if root_procs:
            findings.append(Finding(
                title="Exploitable Root Processes",
                severity=Severity.MEDIUM,
                description="Found root processes that might be exploitable.",
                evidence="\n".join(root_procs),
                remediation="Review service configurations.",
                references=[],
                check_id=self.name
            ))

        return findings
