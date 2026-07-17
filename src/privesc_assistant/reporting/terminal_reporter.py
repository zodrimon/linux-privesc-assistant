from typing import List, Union
from privesc_assistant.core.finding import Finding, Severity
from privesc_assistant.core.scan_context import ScanContext
from privesc_assistant.reporting.base_reporter import BaseReporter
from privesc_assistant.scoring.risk_scorer import aggregate_findings, generate_priority_list

# Try to use rich if installed, fallback to basic ANSI
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

class TerminalReporter(BaseReporter):
    """Outputs a colored summary to the terminal."""
    
    def render(self, findings: List[Finding], context: ScanContext) -> Union[str, bytes]:
        if RICH_AVAILABLE:
            return self._render_rich(findings, context)
        else:
            return self._render_ansi(findings, context)
            
    def _render_rich(self, findings: List[Finding], context: ScanContext) -> str:
        console = Console()
        stats = aggregate_findings(findings)
        prioritized = generate_priority_list(findings)
        
        # Render a panel for summary
        summary_text = (
            f"Target: {context.hostname} ({context.target_os})\n"
            f"Findings: {stats['total_findings']} | Risk Score: {stats['total_score']}"
        )
        console.print(Panel.fit(summary_text, title="PrivEsc Scan Complete", border_style="green"))
        
        if not prioritized:
            console.print("No findings. System is clean!")
            return ""
            
        # Table for findings
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Severity", style="dim", width=12)
        table.add_column("Check ID")
        table.add_column("Title")
        
        sev_colors = {
            Severity.CRITICAL: "bold red",
            Severity.HIGH: "red",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "green",
            Severity.INFO: "blue"
        }
        
        for f in prioritized:
            color = sev_colors.get(f.severity, "white")
            table.add_row(
                Text(f.severity.name, style=color),
                f.check_id,
                f.title
            )
            
        console.print(table)
        
        # We also want to print detailed info for Critical/High? Or just return?
        # The interface returns a string. Rich renders to stdout by default, 
        # so we should capture it.
        with console.capture() as capture:
            console.print(table)
        
        # Actually since the caller will print the returned string, we should just build it
        # Let's recreate console with a string buffer for returning
        import io
        buf = io.StringIO()
        str_console = Console(file=buf, force_terminal=True)
        str_console.print(Panel.fit(summary_text, title="PrivEsc Scan Complete", border_style="green"))
        str_console.print(table)
        return buf.getvalue()

    def _render_ansi(self, findings: List[Finding], context: ScanContext) -> str:
        stats = aggregate_findings(findings)
        prioritized = generate_priority_list(findings)
        
        RED = '\033[91m'
        YELLOW = '\033[93m'
        GREEN = '\033[92m'
        BLUE = '\033[94m'
        ENDC = '\033[0m'
        BOLD = '\033[1m'
        
        def colorize_sev(sev):
            if sev == Severity.CRITICAL: return f"{BOLD}{RED}{sev.name}{ENDC}"
            if sev == Severity.HIGH: return f"{RED}{sev.name}{ENDC}"
            if sev == Severity.MEDIUM: return f"{YELLOW}{sev.name}{ENDC}"
            if sev == Severity.LOW: return f"{GREEN}{sev.name}{ENDC}"
            return f"{BLUE}{sev.name}{ENDC}"

        lines = []
        lines.append(f"{BOLD}=== PrivEsc Scan Complete ==={ENDC}")
        lines.append(f"Target: {context.hostname} ({context.target_os})")
        lines.append(f"Findings: {stats['total_findings']} | Risk Score: {stats['total_score']}")
        lines.append("="*30)
        
        if not prioritized:
            lines.append("No findings. System is clean!")
            return "\n".join(lines)
            
        for f in prioritized:
            lines.append(f"[{colorize_sev(f.severity)}] {f.check_id}: {f.title}")
            if f.severity in (Severity.CRITICAL, Severity.HIGH):
                lines.append(f"    {f.description}")
                
        return "\n".join(lines)
