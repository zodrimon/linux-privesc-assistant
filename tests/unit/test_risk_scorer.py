import unittest
from privesc_assistant.core.finding import Finding, Severity
from privesc_assistant.scoring.risk_scorer import (
    assign_severity_score, aggregate_findings, generate_priority_list
)

class TestRiskScorer(unittest.TestCase):
    def setUp(self):
        self.f_crit = Finding("Crit", Severity.CRITICAL, "d", "e", "r", [], "c1")
        self.f_high = Finding("High", Severity.HIGH, "d", "e", "r", [], "c2")
        self.f_med = Finding("Med", Severity.MEDIUM, "d", "e", "r", [], "c3")
        self.f_low = Finding("Low", Severity.LOW, "d", "e", "r", [], "c4")
        self.f_info = Finding("Info", Severity.INFO, "d", "e", "r", [], "c5")

    def test_assign_severity_score(self):
        self.assertEqual(assign_severity_score(self.f_crit), 10)
        self.assertEqual(assign_severity_score(self.f_high), 5)
        self.assertEqual(assign_severity_score(self.f_med), 2)
        self.assertEqual(assign_severity_score(self.f_low), 1)
        self.assertEqual(assign_severity_score(self.f_info), 0)

    def test_aggregate_findings(self):
        findings = [self.f_crit, self.f_crit, self.f_high, self.f_info]
        stats = aggregate_findings(findings)
        
        self.assertEqual(stats["total_findings"], 4)
        self.assertEqual(stats["total_score"], 25) # 10 + 10 + 5 + 0
        
        counts = stats["counts"]
        self.assertEqual(counts[Severity.CRITICAL], 2)
        self.assertEqual(counts[Severity.HIGH], 1)
        self.assertEqual(counts[Severity.MEDIUM], 0)
        self.assertEqual(counts[Severity.LOW], 0)
        self.assertEqual(counts[Severity.INFO], 1)

    def test_generate_priority_list(self):
        findings = [self.f_info, self.f_high, self.f_low, self.f_crit, self.f_med]
        prioritized = generate_priority_list(findings)
        
        # Expected order: CRITICAL, HIGH, MEDIUM, LOW, INFO
        self.assertEqual(prioritized[0].severity, Severity.CRITICAL)
        self.assertEqual(prioritized[1].severity, Severity.HIGH)
        self.assertEqual(prioritized[2].severity, Severity.MEDIUM)
        self.assertEqual(prioritized[3].severity, Severity.LOW)
        self.assertEqual(prioritized[4].severity, Severity.INFO)

if __name__ == '__main__':
    unittest.main()
