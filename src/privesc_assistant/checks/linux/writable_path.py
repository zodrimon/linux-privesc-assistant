import os
from typing import List, Tuple
from privesc_assistant.checks.base import BaseCheck
from privesc_assistant.core.finding import Finding, Severity
from privesc_assistant.core.scan_context import ScanContext
from privesc_assistant.core.registry import register_check

def get_path_dirs() -> List[str]:
    """Parses the current PATH environment variable and returns a list of directories."""
    path_env = os.environ.get("PATH", "")
    return [p for p in path_env.split(os.pathsep) if p.strip()]

def check_writable_dirs(dirs: List[str]) -> List[str]:
    """Checks which directories in the provided list are writable by the current user."""
    writable_dirs = []
    for d in set(dirs):  # Use set to avoid duplicates
        if os.path.exists(d) and os.path.isdir(d):
            if os.access(d, os.W_OK):
                writable_dirs.append(d)
    return writable_dirs

def detect_path_hijack_opportunity(context: ScanContext, writable_dirs: List[str]) -> List[Tuple[str, str]]:
    """
    Cross-checks writable PATH dirs against sudo-runnable binaries.
    (This is a placeholder that looks in context for phase 9 sudo data if available, 
    otherwise just flags standalone).
    Returns list of tuples (directory, reason)
    """
    opportunities = []
    
    # If phase 9 has run and stored sudo info in context config/state:
    sudo_commands = context.config.get("sudo_commands", [])
    
    if sudo_commands:
        for d in writable_dirs:
            # Here we might check if a sudo command is invoked without an absolute path
            # For now, if we have sudo commands that use relative paths, we flag it.
            opportunities.append((d, "Writable PATH directory found, and user has sudo privileges. Potential for PATH hijacking if sudo commands use relative paths."))
    else:
        for d in writable_dirs:
            opportunities.append((d, "Directory in PATH is writable. High risk of PATH hijacking if privileged processes use relative paths."))
            
    return opportunities

@register_check
class WritablePathCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "writable_path"

    @property
    def description(self) -> str:
        return "Checks if any directory in the PATH environment variable is writable."

    @property
    def severity_hint(self) -> str:
        return "high"

    def run(self, context: ScanContext) -> List[Finding]:
        findings = []
        
        if context.target_os != "linux":
            return findings

        path_dirs = get_path_dirs()
        if not path_dirs:
            return findings
            
        writable = check_writable_dirs(path_dirs)
        
        if writable:
            opportunities = detect_path_hijack_opportunity(context, writable)
            for d, reason in opportunities:
                findings.append(Finding(
                    title=f"Writable PATH Directory: {d}",
                    severity=Severity.HIGH,
                    description=reason,
                    evidence=f"Directory: {d}",
                    remediation="Remove write permissions for non-root users from this directory in the PATH.",
                    references=["https://book.hacktricks.xyz/linux-hardening/privilege-escalation#path"],
                    check_id=self.name
                ))
        
        return findings
