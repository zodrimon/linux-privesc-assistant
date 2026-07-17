import os
import glob
import subprocess
import shlex
import re
from typing import List, Tuple, Dict
from privesc_assistant.checks.base import BaseCheck
from privesc_assistant.core.finding import Finding, Severity
from privesc_assistant.core.scan_context import ScanContext
from privesc_assistant.core.registry import register_check

# (file_source, command_line)
CronEntry = Tuple[str, str]

def _parse_cron_file(filepath: str) -> List[CronEntry]:
    entries = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" in line:
                    continue
                # Minimal parse: keep the whole line as command_line for analysis
                # System crons have user field, but we just capture the whole line
                entries.append((filepath, line))
    except (FileNotFoundError, PermissionError):
        pass
    return entries

def enumerate_system_cron() -> List[CronEntry]:
    """Reads /etc/crontab and /etc/cron.d/*"""
    entries = []
    entries.extend(_parse_cron_file("/etc/crontab"))
    for cron_file in glob.glob("/etc/cron.d/*"):
        if os.path.isfile(cron_file):
            entries.extend(_parse_cron_file(cron_file))
    return entries

def enumerate_user_cron() -> List[CronEntry]:
    """Runs crontab -l for current user."""
    entries = []
    try:
        result = subprocess.run(["crontab", "-l"], capture_output=True, text=True, check=False)
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            entries.append(("crontab -l", line))
    except FileNotFoundError:
        pass
    
    # Check /var/spool/cron/crontabs if readable
    try:
        for root, _, files in os.walk("/var/spool/cron/crontabs"):
            for f in files:
                entries.extend(_parse_cron_file(os.path.join(root, f)))
    except PermissionError:
        pass
        
    return list(set(entries))  # Deduplicate

def _extract_paths_from_cmd(cmd: str) -> List[str]:
    """Attempt to extract absolute file paths from a command string."""
    paths = []
    try:
        # A very naive shlex split. Might fail on malformed cron lines.
        parts = shlex.split(cmd)
    except ValueError:
        parts = cmd.split()
        
    for p in parts:
        if p.startswith("/") and os.path.exists(p) and os.path.isfile(p):
            paths.append(p)
    return paths

def detect_writable_cron_scripts(entries: List[CronEntry]) -> List[Tuple[str, str]]:
    """Flags any cron-invoked script writable by current user."""
    writable_scripts = []
    for source, cmd in entries:
        paths = _extract_paths_from_cmd(cmd)
        for p in paths:
            if os.access(p, os.W_OK):
                writable_scripts.append((source, p))
    return writable_scripts

def detect_wildcard_injection_risk(entries: List[CronEntry]) -> List[Tuple[str, str]]:
    """Flags cron lines using wildcards with tools vulnerable to wildcard injection."""
    risks = []
    # common wildcard injection targets
    vulnerable_tools = [r'\btar\b', r'\brsync\b', r'\bchown\b', r'\bchmod\b']
    
    for source, cmd in entries:
        if "*" in cmd:
            for tool_regex in vulnerable_tools:
                if re.search(tool_regex, cmd):
                    risks.append((source, cmd))
                    break
    return risks

@register_check
class CronJobsCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "cron_jobs"

    @property
    def description(self) -> str:
        return "Analyzes cron jobs for writable scripts and wildcard injection vulnerabilities."

    @property
    def severity_hint(self) -> str:
        return "critical"

    def run(self, context: ScanContext) -> List[Finding]:
        findings = []
        
        if context.target_os != "linux":
            return findings

        sys_cron = enumerate_system_cron()
        user_cron = enumerate_user_cron()
        all_cron = sys_cron + user_cron
        
        if not all_cron:
            return findings

        # Writable scripts
        writable_scripts = detect_writable_cron_scripts(all_cron)
        for source, script in writable_scripts:
            findings.append(Finding(
                title=f"Writable Cron Script: {script}",
                severity=Severity.CRITICAL,
                description="A script executed by a cron job is writable by the current user. This can lead to privilege escalation.",
                evidence=f"Source: {source}\nScript: {script}",
                remediation="Remove write permissions from the script for non-root users.",
                references=["https://book.hacktricks.xyz/linux-hardening/privilege-escalation#cron-jobs"],
                check_id=self.name
            ))

        # Wildcard injection
        wildcard_risks = detect_wildcard_injection_risk(all_cron)
        for source, cmd in wildcard_risks:
            findings.append(Finding(
                title="Potential Wildcard Injection in Cron Job",
                severity=Severity.HIGH,
                description="A cron job runs a command vulnerable to wildcard injection (e.g. tar, chown, rsync) with a wildcard '*'.",
                evidence=f"Source: {source}\nCommand: {cmd}",
                remediation="Provide explicit paths or use absolute wildcards cautiously, and use arguments like '--' to terminate flags.",
                references=["https://book.hacktricks.xyz/linux-hardening/privilege-escalation/wildcards-spare-tricks"],
                check_id=self.name
            ))
            
        # Info about found cron jobs
        if all_cron:
            findings.append(Finding(
                title="Cron Jobs Enumerated",
                severity=Severity.INFO,
                description=f"Found {len(all_cron)} cron jobs.",
                evidence="Check system for specifics if needed.",
                remediation="Review for misconfigurations.",
                references=[],
                check_id=self.name
            ))

        return findings
