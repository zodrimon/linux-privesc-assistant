import argparse
import logging
import sys
import datetime
from privesc_assistant.core.scan_context import ScanContext
from privesc_assistant.core.engine import ScanEngine
from privesc_assistant.core.registry import get_registered_checks

__version__ = "0.1.0"

def setup_logging(verbose: bool):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format='%(levelname)s: %(message)s')

def cmd_scan(args):
    setup_logging(args.verbose)
    
    # Minimal config for now, will be expanded in Phase 3
    config = {}
    if args.checks:
        checks_list = args.checks.split(",")
        config["checks"] = {c.strip(): True for c in checks_list}
    
    context = ScanContext(
        target_os="linux",
        hostname="localhost",
        timestamp=datetime.datetime.now(),
        config=config,
        is_root=False
    )
    
    engine = ScanEngine(config=config)
    findings = engine.run(context)
    
    # Just printing 0 findings for Phase 2 skeleton. Formatters will be added in Phase 12.
    print(f"{len(findings)} findings")

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
