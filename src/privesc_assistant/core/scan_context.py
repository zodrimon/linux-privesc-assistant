from dataclasses import dataclass, field
from typing import Any
import datetime

@dataclass
class ScanContext:
    """Holds scan-wide state passed to every check."""
    target_os: str
    hostname: str
    timestamp: datetime.datetime
    config: dict[str, Any]
    is_root: bool
    env_info: dict[str, Any] = field(default_factory=dict)
