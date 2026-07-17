import os
import stat
import glob
from typing import List, Tuple
from privesc_assistant.checks.base import BaseCheck
from privesc_assistant.core.finding import Finding, Severity
from privesc_assistant.core.scan_context import ScanContext
from privesc_assistant.core.registry import register_check

# Default directories to scan for weak permissions to avoid full filesystem scan
DEFAULT_SCOPES = ["/etc", "/var", "/opt", "/home"]

def _walk_scopes(scope_paths: List[str]):
    for scope in scope_paths:
        if not os.path.exists(scope):
            continue
        try:
            for root, dirs, files in os.walk(scope):
                for d in dirs:
                    yield os.path.join(root, d), False
                for f in files:
                    yield os.path.join(root, f), True
        except PermissionError:
            pass

def find_world_writable_files(scope_paths: List[str]) -> List[str]:
    files = []
    for path, is_file in _walk_scopes(scope_paths):
        if is_file:
            try:
                st = os.stat(path)
                if bool(st.st_mode & stat.S_IWOTH):
                    files.append(path)
            except OSError:
                pass
    return files

def find_world_writable_dirs(scope_paths: List[str]) -> List[str]:
    dirs = []
    for path, is_file in _walk_scopes(scope_paths):
        if not is_file:
            try:
                st = os.stat(path)
                if bool(st.st_mode & stat.S_IWOTH):
                    # We usually care about world writable dirs that don't have the sticky bit set
                    # But for now, we'll just flag world writable. 
                    dirs.append(path)
            except OSError:
                pass
    return dirs

def check_passwd_shadow_perms() -> List[Tuple[str, str]]:
    """Checks /etc/passwd, /etc/shadow, /etc/sudoers for correct permissions."""
    issues = []
    
    # /etc/passwd should be readable by all, but NOT writable by others
    if os.path.exists("/etc/passwd"):
        try:
            st = os.stat("/etc/passwd")
            if bool(st.st_mode & stat.S_IWOTH):
                issues.append(("/etc/passwd", "World writable! This allows anyone to add a root user."))
        except OSError:
            pass

    # /etc/shadow should NOT be readable or writable by others
    if os.path.exists("/etc/shadow"):
        try:
            st = os.stat("/etc/shadow")
            if bool(st.st_mode & stat.S_IROTH):
                issues.append(("/etc/shadow", "World readable! Password hashes can be cracked offline."))
            if bool(st.st_mode & stat.S_IWOTH):
                issues.append(("/etc/shadow", "World writable! Allows modifying password hashes."))
        except OSError:
            pass

    # /etc/sudoers should NOT be readable or writable by others, usually 0440
    if os.path.exists("/etc/sudoers"):
        try:
            st = os.stat("/etc/sudoers")
            if bool(st.st_mode & stat.S_IWOTH):
                issues.append(("/etc/sudoers", "World writable! Allows granting sudo privileges."))
        except OSError:
            pass

    return issues

def check_ssh_key_perms() -> List[Tuple[str, str]]:
    """Scans ~/.ssh/ for private keys with overly permissive modes, and world-readable authorized_keys."""
    issues = []
    home_dir = os.path.expanduser("~")
    ssh_dir = os.path.join(home_dir, ".ssh")
    
    if not os.path.exists(ssh_dir):
        return issues
        
    try:
        for f in os.listdir(ssh_dir):
            path = os.path.join(ssh_dir, f)
            if not os.path.isfile(path):
                continue
                
            st = os.stat(path)
            mode = st.st_mode
            
            # authorized_keys
            if f == "authorized_keys":
                if bool(mode & stat.S_IWOTH):
                    issues.append((path, "authorized_keys is world-writable. Anyone can add their key and login as you."))
            
            # Private keys (id_rsa, id_ed25519, etc)
            elif "id_" in f and not f.endswith(".pub"):
                if bool(mode & stat.S_IROTH) or bool(mode & stat.S_IWOTH):
                    issues.append((path, "Private SSH key is world-readable or writable. Private keys should be 0600."))
                elif bool(mode & stat.S_IRGRP) or bool(mode & stat.S_IWGRP):
                    issues.append((path, "Private SSH key is group-readable or writable. Private keys should be 0600."))
                    
    except OSError:
        pass
        
    return issues

def find_root_owned_user_writable_files(scope_paths: List[str]) -> List[str]:
    """Finds files owned by root but writable by the current user."""
    files = []
    # If the user is root, this check is less meaningful for privesc
    if os.geteuid() == 0:
        return files
        
    for path, is_file in _walk_scopes(scope_paths):
        if is_file:
            try:
                st = os.stat(path)
                # Check if owner is root (uid 0)
                if st.st_uid == 0:
                    # Check if writable by the current user
                    if os.access(path, os.W_OK):
                        files.append(path)
            except OSError:
                pass
    return files

@register_check
class WeakPermissionsCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "weak_permissions"

    @property
    def description(self) -> str:
        return "Scans for world-writable files/dirs, weak critical file perms, and SSH key issues."

    @property
    def severity_hint(self) -> str:
        return "high"

    def run(self, context: ScanContext) -> List[Finding]:
        findings = []
        
        if context.target_os != "linux":
            return findings

        scope_paths = context.config.get("weak_permissions_scopes", DEFAULT_SCOPES)

        # 1. Critical Files (/etc/passwd, shadow, sudoers)
        critical_file_issues = check_passwd_shadow_perms()
        for path, issue in critical_file_issues:
            findings.append(Finding(
                title=f"Critical File Weak Permissions: {path}",
                severity=Severity.CRITICAL,
                description=issue,
                evidence=f"File: {path}",
                remediation="Fix permissions. For /etc/shadow use 0640 or 0000, for passwd 0644, for sudoers 0440.",
                references=[],
                check_id=self.name
            ))

        # 2. SSH Keys
        ssh_issues = check_ssh_key_perms()
        for path, issue in ssh_issues:
            findings.append(Finding(
                title=f"SSH Key Weak Permissions: {os.path.basename(path)}",
                severity=Severity.HIGH,
                description=issue,
                evidence=f"File: {path}",
                remediation="Run `chmod 600` on private keys and `chmod 644` on authorized_keys.",
                references=[],
                check_id=self.name
            ))

        # 3. Root-owned, User-writable
        root_owned_writable = find_root_owned_user_writable_files(scope_paths)
        if root_owned_writable:
            findings.append(Finding(
                title="Root-Owned User-Writable Files",
                severity=Severity.HIGH,
                description=f"Found {len(root_owned_writable)} files owned by root but writable by the current user.",
                evidence="\n".join(root_owned_writable[:50]) + ("\n..." if len(root_owned_writable) > 50 else ""),
                remediation="Remove user write permissions on these files.",
                references=[],
                check_id=self.name
            ))

        # 4. World-writable files
        ww_files = find_world_writable_files(scope_paths)
        if ww_files:
            findings.append(Finding(
                title="World-Writable Files",
                severity=Severity.MEDIUM,
                description=f"Found {len(ww_files)} world-writable files in scoped paths.",
                evidence="\n".join(ww_files[:50]) + ("\n..." if len(ww_files) > 50 else ""),
                remediation="Review and remove world-write permissions (chmod o-w) where not necessary.",
                references=[],
                check_id=self.name
            ))

        # 5. World-writable directories
        ww_dirs = find_world_writable_dirs(scope_paths)
        if ww_dirs:
            findings.append(Finding(
                title="World-Writable Directories",
                severity=Severity.INFO,
                description=f"Found {len(ww_dirs)} world-writable directories in scoped paths.",
                evidence="\n".join(ww_dirs[:50]) + ("\n..." if len(ww_dirs) > 50 else ""),
                remediation="Ensure sticky bit is set on world-writable directories (+t) if required.",
                references=[],
                check_id=self.name
            ))

        return findings
