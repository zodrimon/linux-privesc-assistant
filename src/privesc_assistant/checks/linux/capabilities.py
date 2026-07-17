import subprocess
from typing import List, Tuple, Dict
from privesc_assistant.checks.base import BaseCheck
from privesc_assistant.core.finding import Finding, Severity
from privesc_assistant.core.scan_context import ScanContext
from privesc_assistant.core.registry import register_check

DANGEROUS_CAPS = {
    "cap_setuid": "Allows changing the UID, can be used to become root.",
    "cap_setgid": "Allows changing the GID.",
    "cap_dac_override": "Bypasses file read, write, and execute permission checks.",
    "cap_dac_read_search": "Bypasses file read permission checks and directory read/execute checks.",
    "cap_sys_admin": "Broad administrative privileges (often called the 'new root').",
    "cap_sys_ptrace": "Allows attaching to any process, reading memory, and injecting code.",
    "cap_sys_module": "Allows loading kernel modules.",
    "cap_chown": "Allows changing file ownership.",
    "cap_fowner": "Bypasses permission checks on operations that normally require the fs UID to match the file owner.",
    "cap_setfcap": "Allows setting file capabilities."
}

def enumerate_capabilities() -> List[Tuple[str, str]]:
    """
    Runs `getcap -r /` to find binaries with capabilities.
    Returns a list of tuples: (file_path, capabilities_string)
    """
    try:
        cmd = ["getcap", "-r", "/"]
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        # Expected output format: /path/to/binary = cap_setuid,cap_setgid+ep
        entries = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split(" = ")
            if len(parts) == 2:
                entries.append((parts[0].strip(), parts[1].strip()))
        return entries
    except FileNotFoundError:
        # getcap is not installed or not in PATH
        return []

def cross_reference_dangerous_caps(entries: List[Tuple[str, str]]) -> List[Tuple[str, str, Dict[str, str]]]:
    """
    Analyzes the capabilities of binaries and flags those with known dangerous capabilities.
    Returns: list of (file_path, raw_caps, matched_dangerous_caps_dict)
    """
    dangerous_entries = []
    
    for path, raw_caps in entries:
        matched_caps = {}
        # Simple string checking since capabilities output can be e.g. "cap_setuid,cap_setgid+ep"
        for cap, desc in DANGEROUS_CAPS.items():
            if cap in raw_caps:
                matched_caps[cap] = desc
        
        if matched_caps:
            dangerous_entries.append((path, raw_caps, matched_caps))
            
    return dangerous_entries

@register_check
class CapabilitiesCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "capabilities"

    @property
    def description(self) -> str:
        return "Enumerates file capabilities and flags potentially dangerous ones."

    @property
    def severity_hint(self) -> str:
        return "high"

    def run(self, context: ScanContext) -> List[Finding]:
        findings = []
        
        if context.target_os != "linux":
            return findings

        entries = enumerate_capabilities()
        if not entries:
            return findings

        dangerous_entries = cross_reference_dangerous_caps(entries)
        
        for path, raw_caps, matched_caps in dangerous_entries:
            caps_list = ", ".join(matched_caps.keys())
            desc_list = "\n".join(f"- {cap}: {desc}" for cap, desc in matched_caps.items())
            
            findings.append(Finding(
                title=f"Dangerous Capabilities on Binary: {path}",
                severity=Severity.HIGH,
                description=f"The binary has the following dangerous capabilities:\n{desc_list}",
                evidence=f"File: {path}\nCapabilities: {raw_caps}",
                remediation="Remove unnecessary capabilities using 'setcap -r <file>'.",
                references=["https://man7.org/linux/man-pages/man7/capabilities.7.html"],
                check_id=self.name
            ))
            
        # Report the rest as INFO
        dangerous_paths = {entry[0] for entry in dangerous_entries}
        safe_entries = [entry for entry in entries if entry[0] not in dangerous_paths]
        
        if safe_entries:
            evidence_lines = [f"{path} = {caps}" for path, caps in safe_entries]
            findings.append(Finding(
                title="Non-Critical Capabilities Enumerated",
                severity=Severity.INFO,
                description=f"Found {len(safe_entries)} binaries with non-critical capabilities.",
                evidence="\n".join(evidence_lines),
                remediation="Review if these capabilities are necessary.",
                references=[],
                check_id=self.name
            ))

        return findings
