import os
import json
import subprocess
from typing import List, Tuple
from privesc_assistant.checks.base import BaseCheck
from privesc_assistant.core.finding import Finding, Severity
from privesc_assistant.core.scan_context import ScanContext
from privesc_assistant.core.registry import register_check

KNOWN_SAFE_BINARIES = {
    "passwd", "chsh", "chfn", "su", "sudo", "mount", "umount", "newgrp", 
    "pkexec", "polkit-agent-helper-1", "fusermount", "ping", "ping6",
    "gpasswd", "unix_chkpwd", "chage", "crontab", "at"
}

def _run_find_command(perm: str) -> List[str]:
    """Helper to run the find command for given permissions."""
    try:
        # Using 2>/dev/null to suppress permission denied errors in stderr
        # But subprocess.run with capture_output=True handles stderr separately.
        # find / -type f -perm <perm>
        cmd = ["find", "/", "-type", "f", "-perm", perm]
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        # Check return code? find might return 1 if there are permission denied errors, which is normal for non-root.
        binaries = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        return binaries
    except FileNotFoundError:
        # If 'find' is somehow not on the system
        return []

def find_suid_binaries() -> List[str]:
    """Walk filesystem and return list of SUID binary paths."""
    return _run_find_command("-4000")

def find_sgid_binaries() -> List[str]:
    """Walk filesystem and return list of SGID binary paths."""
    return _run_find_command("-2000")

def load_gtfobins_db() -> dict:
    """Load the local GTFOBins JSON snapshot."""
    data_path = os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", "data", "gtfobins_suid.json")
    try:
        with open(data_path, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def cross_reference_gtfobins(binaries: List[str], gtfobins_db: dict) -> List[Tuple[str, dict]]:
    """Match found binaries against GTFOBins DB."""
    matches = []
    for binary_path in binaries:
        base_name = os.path.basename(binary_path)
        if base_name in gtfobins_db:
            matches.append((binary_path, gtfobins_db[base_name]))
    return matches

def filter_known_safe_binaries(binaries: List[str]) -> Tuple[List[str], List[str]]:
    """Separate binaries into potentially dangerous and known-safe."""
    dangerous = []
    safe = []
    for binary_path in binaries:
        base_name = os.path.basename(binary_path)
        if base_name in KNOWN_SAFE_BINARIES:
            safe.append(binary_path)
        else:
            dangerous.append(binary_path)
    return dangerous, safe

@register_check
class SuidSgidCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "suid_sgid"

    @property
    def description(self) -> str:
        return "Enumerates SUID and SGID binaries and cross-references with GTFOBins."

    @property
    def severity_hint(self) -> str:
        return "critical"

    def run(self, context: ScanContext) -> List[Finding]:
        findings = []
        
        # Only run actual Linux commands if the target OS is linux
        if context.target_os != "linux":
            return findings

        gtfobins_db = load_gtfobins_db()

        # Check SUID
        suid_bins = find_suid_binaries()
        suid_dangerous, suid_safe = filter_known_safe_binaries(suid_bins)
        suid_exploitable = cross_reference_gtfobins(suid_dangerous, gtfobins_db)
        
        for path, exploit_info in suid_exploitable:
            findings.append(Finding(
                title=f"Exploitable SUID Binary: {path}",
                severity=Severity.CRITICAL,
                description=exploit_info.get("description", "Known GTFOBins exploitable SUID binary."),
                evidence=f"Path: {path}",
                remediation="Remove the SUID bit if not required, or restrict access.",
                references=[exploit_info.get("url", "")],
                check_id=self.name
            ))
            
        for path in suid_dangerous:
            if not any(path == exploitable_path for exploitable_path, _ in suid_exploitable):
                findings.append(Finding(
                    title=f"Unknown SUID Binary: {path}",
                    severity=Severity.MEDIUM,
                    description="An unknown SUID binary was found. It may be custom and worth investigating.",
                    evidence=f"Path: {path}",
                    remediation="Verify if SUID is strictly necessary for this binary.",
                    references=[],
                    check_id=self.name
                ))

        if suid_safe:
            findings.append(Finding(
                title="Known Safe SUID Binaries",
                severity=Severity.INFO,
                description=f"Found {len(suid_safe)} known safe SUID binaries.",
                evidence="\\n".join(suid_safe),
                remediation="No action required.",
                references=[],
                check_id=self.name
            ))

        # Check SGID (Basic info reporting for now)
        sgid_bins = find_sgid_binaries()
        if sgid_bins:
            findings.append(Finding(
                title="SGID Binaries Enumerated",
                severity=Severity.INFO,
                description=f"Found {len(sgid_bins)} SGID binaries.",
                evidence="\\n".join(sgid_bins),
                remediation="Review if SGID is necessary.",
                references=[],
                check_id=self.name
            ))

        return findings
