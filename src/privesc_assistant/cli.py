import argparse
import logging
import sys
import datetime
import os
from privesc_assistant.core.scan_context import ScanContext
from privesc_assistant.core.engine import ScanEngine
from privesc_assistant.core.registry import get_registered_checks
from privesc_assistant.config.loader import load_config
from privesc_assistant.reporting.terminal_reporter import TerminalReporter
from privesc_assistant.reporting.json_reporter import JsonReporter
from privesc_assistant.reporting.markdown_reporter import MarkdownReporter
from privesc_assistant.reporting.html_reporter import HtmlReporter

__version__ = "0.1.0"

def setup_logging(verbose: bool):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format='%(levelname)s: %(message)s')

def cmd_scan(args):
    setup_logging(args.verbose)
    
    config = load_config(args.config)
    
    if args.checks:
        checks_list = args.checks.split(",")
        if "checks" not in config:
            config["checks"] = {}
        for c in checks_list:
            config["checks"][c.strip()] = True
            
    is_root = False
    try:
        is_root = os.getuid() == 0
    except AttributeError:
        pass
    
    context = ScanContext(
        target_os="linux",
        hostname=os.uname().nodename if hasattr(os, "uname") else "localhost",
        timestamp=datetime.datetime.now(),
        config=config,
        is_root=is_root
    )
    
    engine = ScanEngine(config=config)
    findings = engine.run(context)
    
    reporters = {
        "terminal": TerminalReporter(),
        "json": JsonReporter(),
        "md": MarkdownReporter(),
        "html": HtmlReporter()
    }
    
    reporter = reporters.get(args.format, TerminalReporter())
    output = reporter.render(findings, context)
    
    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
        print(f"Report saved to {args.output}")
    else:
        print(output)

def cmd_list_checks(args):
    checks = get_registered_checks()
    if not checks:
        print("No checks registered.")
        return
    for check_cls in checks:
        check = check_cls()
        print(f"- {check.name}: {check.description} (Max severity: {check.severity_hint})")

def main():
    parser = argparse.ArgumentParser(description="Linux Privilege Escalation Assistant")
    parser.add_argument("--version", action="version", version=f"privesc-assistant {__version__}")
    
    subparsers = parser.add_subparsers(dest="command", required=True)
    
    # scan command
    scan_parser = subparsers.add_parser("scan", help="Run the privilege escalation scan")
    scan_parser.add_argument("--config", help="Path to config file")
    scan_parser.add_argument("--output", help="Path to output report file")
    scan_parser.add_argument("--format", choices=["terminal", "json", "md", "html"], default="terminal", help="Output format")
    scan_parser.add_argument("--checks", help="Comma-separated list of check IDs to run")
    scan_parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    scan_parser.set_defaults(func=cmd_scan)
    
    # list-checks command
    list_parser = subparsers.add_parser("list-checks", help="List all available checks")
    list_parser.set_defaults(func=cmd_list_checks)
    
    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
