import html
from typing import List, Union
from privesc_assistant.core.finding import Finding
from privesc_assistant.core.scan_context import ScanContext
from privesc_assistant.reporting.base_reporter import BaseReporter
from privesc_assistant.scoring.risk_scorer import aggregate_findings, generate_priority_list

class HtmlReporter(BaseReporter):
    """Generates a standalone HTML report with inline CSS."""
    
    def render(self, findings: List[Finding], context: ScanContext) -> Union[str, bytes]:
        prioritized = generate_priority_list(findings)
        stats = aggregate_findings(findings)
        
        css = """
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #333; max-width: 1000px; margin: 0 auto; padding: 20px; }
        h1, h2, h3 { color: #2c3e50; }
        .summary-box { background-color: #f8f9fa; border: 1px solid #e9ecef; border-radius: 5px; padding: 15px; margin-bottom: 20px; }
        .finding { border: 1px solid #ddd; border-left: 5px solid #888; padding: 15px; margin-bottom: 20px; border-radius: 3px; }
        .sev-CRITICAL { border-left-color: #dc3545; }
        .sev-HIGH { border-left-color: #fd7e14; }
        .sev-MEDIUM { border-left-color: #ffc107; }
        .sev-LOW { border-left-color: #28a745; }
        .sev-INFO { border-left-color: #17a2b8; }
        .badge { display: inline-block; padding: 0.25em 0.4em; font-size: 75%; font-weight: 700; line-height: 1; text-align: center; white-space: nowrap; vertical-align: baseline; border-radius: 0.25rem; color: #fff; }
        .badge-CRITICAL { background-color: #dc3545; }
        .badge-HIGH { background-color: #fd7e14; }
        .badge-MEDIUM { background-color: #ffc107; color: #212529; }
        .badge-LOW { background-color: #28a745; }
        .badge-INFO { background-color: #17a2b8; }
        pre { background-color: #f1f1f1; padding: 10px; overflow-x: auto; border-radius: 3px; font-family: monospace; }
        """
        
        html_parts = []
        html_parts.append("<!DOCTYPE html>")
        html_parts.append("<html lang='en'>")
        html_parts.append(f"<head><meta charset='UTF-8'><title>PrivEsc Scan Report - {context.hostname}</title><style>{css}</style></head>")
        html_parts.append("<body>")
        html_parts.append(f"<h1>Linux Privilege Escalation Scan Report</h1>")
        
        html_parts.append("<div class='summary-box'>")
        html_parts.append("<h2>Scan Summary</h2>")
        html_parts.append(f"<p><strong>Target OS:</strong> {html.escape(context.target_os)}<br>")
        html_parts.append(f"<strong>Hostname:</strong> {html.escape(context.hostname)}<br>")
        html_parts.append(f"<strong>Scan Time:</strong> {context.timestamp.strftime('%Y-%m-%d %H:%M:%S')}<br>")
        html_parts.append(f"<strong>Run as Root:</strong> {context.is_root}</p>")
        
        html_parts.append(f"<p><strong>Total Findings:</strong> {stats['total_findings']}<br>")
        html_parts.append(f"<strong>Risk Score:</strong> {stats['total_score']}</p>")
        
        html_parts.append("<ul>")
        for sev, count in stats["counts"].items():
            if count > 0:
                html_parts.append(f"<li><span class='badge badge-{sev.name}'>{sev.name}</span> : {count}</li>")
        html_parts.append("</ul>")
        html_parts.append("</div>")
        
        if not prioritized:
            html_parts.append("<p>No findings to report. System looks clean!</p>")
        else:
            html_parts.append("<h2>Findings</h2>")
            for f in prioritized:
                html_parts.append(f"<div class='finding sev-{f.severity.name}'>")
                html_parts.append(f"<h3>{html.escape(f.title)} <span class='badge badge-{f.severity.name}'>{f.severity.name}</span></h3>")
                html_parts.append(f"<p><strong>Check ID:</strong> <code>{html.escape(f.check_id)}</code></p>")
                html_parts.append(f"<p><strong>Description:</strong><br>{html.escape(f.description).replace(chr(10), '<br>')}</p>")
                html_parts.append(f"<p><strong>Evidence:</strong></p><pre>{html.escape(f.evidence)}</pre>")
                html_parts.append(f"<p><strong>Remediation:</strong><br>{html.escape(f.remediation).replace(chr(10), '<br>')}</p>")
                
                if f.references:
                    html_parts.append("<p><strong>References:</strong></p><ul>")
                    for ref in f.references:
                        html_parts.append(f"<li><a href='{html.escape(ref)}'>{html.escape(ref)}</a></li>")
                    html_parts.append("</ul>")
                html_parts.append("</div>")
                
        html_parts.append("</body></html>")
        return "\n".join(html_parts)
