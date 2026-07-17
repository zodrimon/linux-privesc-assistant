import time
import logging
from typing import Any
from privesc_assistant.core.scan_context import ScanContext
from privesc_assistant.core.finding import Finding
from privesc_assistant.core.registry import get_registered_checks

class ScanEngine:
    """Discovers and runs enabled checks, collecting findings and statistics."""

    def __init__(self, config: dict[str, Any]):
        self.config = config
        self.findings: list[Finding] = []
        self.stats: dict[str, Any] = {
            "checks_run": 0,
            "checks_failed": 0,
            "timings": {}
        }

    def run(self, context: ScanContext) -> list[Finding]:
        """Execute all enabled checks and aggregate findings."""
        checks = get_registered_checks()
        enabled_checks_config = self.config.get("checks", {})
        
        for check_cls in checks:
            check_instance = check_cls()
            
            # If the config specifies enabled checks, we might filter them here.
            # Assuming a simple true/false dictionary for now.
            # Defaults to True if the check is not explicitly disabled.
            is_enabled = enabled_checks_config.get(check_instance.name, True)
            
            if not is_enabled:
                logging.debug(f"Skipping check {check_instance.name}, disabled in config.")
                continue

            start_time = time.time()
            try:
                check_findings = check_instance.run_safe(context)
                self.findings.extend(check_findings)
                self.stats["checks_run"] += 1
            except Exception as e:
                # run_safe handles its own exceptions, but this is a double safety net
                logging.error(f"Engine caught unexpected error running {check_instance.name}: {e}", exc_info=True)
                self.stats["checks_failed"] += 1
            finally:
                duration = time.time() - start_time
                self.stats["timings"][check_instance.name] = duration

        return self.findings
