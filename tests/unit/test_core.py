import unittest
import datetime
from privesc_assistant.core.finding import Finding, Severity
from privesc_assistant.core.scan_context import ScanContext
from privesc_assistant.checks.base import BaseCheck
from privesc_assistant.core.registry import register_check

class DummyCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "dummy_check"

    @property
    def description(self) -> str:
        return "A dummy check for testing"

    @property
    def severity_hint(self) -> str:
        return "info"

    def run(self, context: ScanContext) -> list[Finding]:
        return [
            Finding(
                title="Dummy Finding",
                severity=Severity.INFO,
                description="This is a test",
                evidence="N/A",
                remediation="N/A",
                references=[],
                check_id=self.name
            )
        ]

class ErrorCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "error_check"

    @property
    def description(self) -> str:
        return "A check that always raises an exception"

    @property
    def severity_hint(self) -> str:
        return "info"

    def run(self, context: ScanContext) -> list[Finding]:
        raise ValueError("Simulated check failure")

class TestCore(unittest.TestCase):
    def setUp(self):
        self.context = ScanContext(
            target_os="linux",
            hostname="test-box",
            timestamp=datetime.datetime.now(),
            config={"checks": {}},
            is_root=False
        )

    def test_finding_dataclass(self):
        f = Finding(
            title="Test",
            severity=Severity.LOW,
            description="Desc",
            evidence="Ev",
            remediation="Rem"
        )
        self.assertEqual(f.title, "Test")
        self.assertEqual(f.severity, Severity.LOW)
        self.assertEqual(f.references, [])
        self.assertEqual(f.check_id, "")

    def test_scan_context(self):
        self.assertEqual(self.context.target_os, "linux")
        self.assertFalse(self.context.is_root)

    def test_basecheck_safe_wrapper_success(self):
        check = DummyCheck()
        findings = check.run_safe(self.context)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].title, "Dummy Finding")

    def test_basecheck_safe_wrapper_error(self):
        check = ErrorCheck()
        findings = check.run_safe(self.context)
        # Should catch ValueError and return empty list rather than bubbling up
        self.assertEqual(len(findings), 0)

if __name__ == '__main__':
    unittest.main()
