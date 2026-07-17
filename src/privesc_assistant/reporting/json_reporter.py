import json
from typing import List, Union, Any, Dict
from privesc_assistant.core.finding import Finding
from privesc_assistant.core.scan_context import ScanContext
from privesc_assistant.reporting.base_reporter import BaseReporter
from privesc_assistant.scoring.risk_scorer import aggregate_findings, generate_priority_list

class CustomJSONEncoder(json.JSONEncoder):
    def default(self, obj: Any) -> Any:
        if isinstance(obj, Finding):
            return {
                "title": obj.title,
                "severity": obj.severity.name,
                "description": obj.description,
                "evidence": obj.evidence,
                "remediation": obj.remediation,
                "references": obj.references,
                "check_id": obj.check_id
            }
        if hasattr(obj, "isoformat"):
            return obj.isoformat()
        return super().default(obj)

class JsonReporter(BaseReporter):
    """Generates a structured JSON dump of all findings and metadata."""
    
    def render(self, findings: List[Finding], context: ScanContext) -> Union[str, bytes]:
        prioritized = generate_priority_list(findings)
        stats = aggregate_findings(findings)
        
        report: Dict[str, Any] = {
            "metadata": {
                "target_os": context.target_os,
                "hostname": context.hostname,
                "timestamp": context.timestamp.isoformat(),
                "is_root": context.is_root
            },
            "statistics": {
                "total_findings": stats["total_findings"],
                "total_score": stats["total_score"],
                "severity_counts": {k.name: v for k, v in stats["counts"].items()}
            },
            "findings": prioritized
        }
        
        return json.dumps(report, indent=4, cls=CustomJSONEncoder)
