from typing import List, Union
from privesc_assistant.core.finding import Finding
from privesc_assistant.core.scan_context import ScanContext
from privesc_assistant.reporting.base_reporter import BaseReporter
from privesc_assistant.scoring.risk_scorer import aggregate_findings, generate_priority_list

class MarkdownReporter(BaseReporter):
    """Generates a clean Markdown report."""
    
    def render(self, findings: List[Finding], context: ScanContext) -> Union[str, bytes]:
        prioritized = generate_priority_list(findings)
        stats = aggregate_findings(findings)
        
        lines = []
        lines.append("# Linux Privilege Escalation Scan Report")
        lines.append("")
        
        lines.append("## Metadata")
        lines.append(f"- **Target OS:** {context.target_os}")
        lines.append(f"- **Hostname:** {context.hostname}")
        lines.append(f"- **Scan Time:** {context.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"- **Run as Root:** {context.is_root}")
        lines.append("")
        
        lines.append("## Summary Statistics")
        lines.append(f"- **Total Findings:** {stats['total_findings']}")
        lines.append(f"- **Risk Score:** {stats['total_score']}")
        for sev, count in stats["counts"].items():
            lines.append(f"- **{sev.name}:** {count}")
        lines.append("")
        
        if not prioritized:
            lines.append("No findings to report. System looks clean!")
            return "\n".join(lines)
            
        lines.append("## Findings List")
        for i, f in enumerate(prioritized, 1):
            lines.append(f"### {i}. {f.title} [{f.severity.name}]")
            lines.append("")
            lines.append(f"**Check ID:** `{f.check_id}`")
            lines.append("")
            lines.append(f"**Description:**")
            lines.append(f"{f.description}")
            lines.append("")
            lines.append(f"**Evidence:**")
            lines.append("```")
            lines.append(f"{f.evidence}")
            lines.append("```")
            lines.append("")
            lines.append(f"**Remediation:**")
            lines.append(f"{f.remediation}")
            lines.append("")
            if f.references:
                lines.append(f"**References:**")
                for ref in f.references:
                    lines.append(f"- [{ref}]({ref})")
                lines.append("")
            lines.append("---")
            lines.append("")
            
        return "\n".join(lines)
