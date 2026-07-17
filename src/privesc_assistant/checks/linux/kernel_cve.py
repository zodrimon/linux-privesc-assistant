import os
import json
import subprocess
import re
from typing import List, Dict, Tuple
from privesc_assistant.checks.base import BaseCheck
from privesc_assistant.core.finding import Finding, Severity
from privesc_assistant.core.scan_context import ScanContext
from privesc_assistant.core.registry import register_check

def get_kernel_version() -> str:
    """Returns the kernel version string via 'uname -r'."""
    try:
        result = subprocess.run(["uname", "-r"], capture_output=True, text=True, check=False)
        return result.stdout.strip()
    except FileNotFoundError:
        return "unknown"

def get_os_release_info() -> Dict[str, str]:
    """Parses /etc/os-release into a dictionary."""
    info = {}
    if os.path.exists("/etc/os-release"):
        with open("/etc/os-release", "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                info[k] = v.strip('"\'')
    return info

def _parse_version(v_str: str) -> Tuple[int, ...]:
    # A rough way to normalize kernel versions like 5.15.0-72-generic
    match = re.search(r'^(\d+\.\d+(?:\.\d+)?)', v_str)
    if match:
        return tuple(map(int, match.group(1).split('.')))
    return (0, 0, 0)

def match_known_kernel_cves(current_version: str, db_path: str = None) -> List[Dict]:
    """Matches the current kernel version against the local CVE database."""
    if db_path is None:
        db_path = os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", "data", "kernel_cve_db.json")
    
    matches = []
    
    try:
        with open(db_path, "r") as f:
            cve_db = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return matches

    current_v = _parse_version(current_version)

    for entry in cve_db:
        affected = entry.get("affected_versions", "")
        if affected == "all":
            matches.append(entry)
            continue
            
        # Parse range like '5.8 <= x < 5.16.11'
        match = re.search(r'([\d\.]+)\s*<=\s*x\s*<\s*([\d\.]+)', affected)
        if match:
            min_v = _parse_version(match.group(1))
            max_v = _parse_version(match.group(2))
            
            if min_v <= current_v < max_v:
                matches.append(entry)

    return matches

def flag_exploit_suggestions(matches: List[Dict]) -> List[Tuple[str, str, str]]:
    """Returns a list of (CVE, Name, Exploit Link)."""
    return [(m["cve"], m["name"], m.get("exploit_link", "No link available")) for m in matches]

@register_check
class KernelCveCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "kernel_cve"

    @property
    def description(self) -> str:
        return "Checks the kernel version against a local database of known privesc CVEs."

    @property
    def severity_hint(self) -> str:
        return "critical"

    def run(self, context: ScanContext) -> List[Finding]:
        findings = []
        
        if context.target_os != "linux":
            return findings

        k_ver = get_kernel_version()
        if k_ver == "unknown":
            return findings

        os_info = get_os_release_info()
        os_name = os_info.get("PRETTY_NAME", "Linux")

        matches = match_known_kernel_cves(k_ver)
        if matches:
            suggestions = flag_exploit_suggestions(matches)
            
            desc_lines = [f"The system ({os_name}) is running kernel {k_ver}, which may be vulnerable to:"]
            for cve, name, link in suggestions:
                desc_lines.append(f"- {cve} ({name}): {link}")
                
            findings.append(Finding(
                title=f"Vulnerable Kernel Version: {k_ver}",
                severity=Severity.CRITICAL,
                description="\n".join(desc_lines),
                evidence=f"Kernel: {k_ver}\nOS: {os_name}",
                remediation="Upgrade the Linux kernel and reboot the system.",
                references=[link for _, _, link in suggestions if link != "No link available"],
                check_id=self.name
            ))
        else:
            findings.append(Finding(
                title="Kernel Version Information",
                severity=Severity.INFO,
                description=f"System is running kernel {k_ver} ({os_name}). No known major privesc CVEs matched in local DB.",
                evidence=f"Kernel: {k_ver}",
                remediation="Keep the system updated.",
                references=[],
                check_id=self.name
            ))

        return findings
