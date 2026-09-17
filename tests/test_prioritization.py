"""
Unit tests for CVSS, EPSS, and Composite Risk Prioritization Engine.
"""

import unittest
from backend.prioritization.cvss_service import CVSSService
from backend.prioritization.epss_service import epss_service
from backend.prioritization.risk_engine import risk_engine


class TestPrioritization(unittest.TestCase):
    def test_cvss_calculation(self):
        # Critical network exploit: AV:N, AC:L, PR:N, UI:N, S:U, C:H, I:H, A:H -> 9.8
        score, vector = CVSSService.calculate_v31(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="H")
        self.assertAlmostEqual(score, 9.8, delta=0.1)
        self.assertIn("CVSS:3.1", vector)
        self.assertEqual(CVSSService.get_severity(score), "CRITICAL")

    def test_cvss_estimation_from_cwe(self):
        score_sqli, _ = CVSSService.estimate_from_cwe("CWE-89", "SQL Injection")
        self.assertGreaterEqual(score_sqli, 9.0)

        score_xss, _ = CVSSService.estimate_from_cwe("CWE-79", "XSS")
        self.assertLess(score_xss, 8.0)

    def test_epss_benchmarks_and_caching(self):
        # Log4Shell benchmark
        score, pct = epss_service.get_epss("CVE-2021-44228")
        self.assertGreater(score, 0.90)
        self.assertGreater(pct, 0.95)

    def test_composite_risk_quadrants(self):
        # 1. High CVSS + High EPSS -> ACT_NOW
        res_actnow = risk_engine.calculate_composite_risk(cvss_score=9.8, epss_score=0.85, epss_percentile=0.98)
        self.assertEqual(res_actnow["quadrant"], "ACT_NOW")
        self.assertEqual(res_actnow["sla_days"], 2)

        # 2. High CVSS + Low EPSS -> CRITICAL_PATCH
        res_patch = risk_engine.calculate_composite_risk(cvss_score=8.5, epss_score=0.01, epss_percentile=0.30)
        self.assertEqual(res_patch["quadrant"], "CRITICAL_PATCH")
        self.assertEqual(res_patch["sla_days"], 14)

        # 3. Low CVSS + High EPSS -> OPPORTUNISTIC
        res_opp = risk_engine.calculate_composite_risk(cvss_score=5.0, epss_score=0.45, epss_percentile=0.92)
        self.assertEqual(res_opp["quadrant"], "OPPORTUNISTIC")
        self.assertEqual(res_opp["sla_days"], 30)

        # 4. Low CVSS + Low EPSS -> ROUTINE
        res_routine = risk_engine.calculate_composite_risk(cvss_score=3.5, epss_score=0.01, epss_percentile=0.20)
        self.assertEqual(res_routine["quadrant"], "ROUTINE")
        self.assertEqual(res_routine["sla_days"], 90)


if __name__ == "__main__":
    unittest.main()
