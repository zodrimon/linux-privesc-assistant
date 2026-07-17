from typing import List, Dict, Any
from privesc_assistant.core.finding import Finding, Severity

# Weights for each severity level
SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 5,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0
}

def assign_severity_score(finding: Finding) -> int:
    """Maps a Finding's Severity enum to a numeric score."""
    return SEVERITY_WEIGHTS.get(finding.severity, 0)

def aggregate_findings(findings: List[Finding]) -> Dict[str, Any]:
    """
    Groups findings by severity, counts them, and computes an overall system risk score.
    Returns a dictionary with summary statistics.
    """
    counts = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 0,
        Severity.MEDIUM: 0,
        Severity.LOW: 0,
        Severity.INFO: 0
    }
    
    total_score = 0
    
    for finding in findings:
        counts[finding.severity] += 1
        total_score += assign_severity_score(finding)
        
    return {
        "counts": counts,
        "total_score": total_score,
        "total_findings": len(findings)
    }

def generate_priority_list(findings: List[Finding]) -> List[Finding]:
    """
    Sorts findings into a recommended attack-order list (most exploitable first).
    Sorts by severity descending. For tie-breaking, we could add more logic later,
    but for now, it's just Severity.
    """
    # Create a stable sort based on severity weight
    return sorted(findings, key=lambda f: SEVERITY_WEIGHTS.get(f.severity, 0), reverse=True)
