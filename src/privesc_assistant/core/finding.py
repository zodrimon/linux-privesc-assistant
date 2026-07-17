from dataclasses import dataclass, field
from enum import Enum

class Severity(Enum):
    """Enumeration representing the severity of a finding."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class Finding:
    """Represents a single security finding discovered by a check module."""
    title: str
    severity: Severity
    description: str
    evidence: str
    remediation: str
    references: list[str] = field(default_factory=list)
    check_id: str = ""
