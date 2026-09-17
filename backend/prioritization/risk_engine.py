"""
AegisSec - Composite Risk Engine
Unifies CVSS (Impact) and EPSS (Exploit Probability) into an actionable prioritization matrix.
"""

from typing import Dict, Any, Tuple
from .cvss_service import CVSSService
from .epss_service import epss_service


class RiskEngine:
    @staticmethod
    def calculate_composite_risk(
        cvss_score: float,
        epss_score: float,
        epss_percentile: float,
        is_production: bool = True,
        is_public_facing: bool = True,
        has_compliance_mandate: bool = True
    ) -> Dict[str, Any]:
        """
        Calculates normalized risk score (0 - 100), urgency quadrant, and remediation SLA.
        Formula:
          Base Impact (CVSS) = cvss_score * 5.0 (0 to 50 pts)
          Exploit Probability (EPSS) = epss_score * 35.0 (0 to 35 pts)
          Percentile Bonus = epss_percentile * 5.0 (0 to 5 pts)
          Environment / Reachability Factor = 5.0 pts
          Compliance & Safety Criticality = 5.0 pts
        """
        impact_component = cvss_score * 5.0
        exploit_component = (epss_score * 35.0) + (epss_percentile * 5.0)
        env_component = 5.0 if (is_production and is_public_facing) else 2.0
        compliance_component = 5.0 if has_compliance_mandate else 1.0

        raw_score = impact_component + exploit_component + env_component + compliance_component
        score = min(max(round(raw_score, 1), 0.0), 100.0)

        # Quadrant Determination (CVSS threshold: 7.0, EPSS threshold: 0.20)
        high_cvss = cvss_score >= 7.0
        high_epss = epss_score >= 0.20 or epss_percentile >= 0.85

        if high_cvss and high_epss:
            quadrant = "ACT_NOW"
            urgency = "IMMEDIATE"
            sla_days = 2
            badge_color = "#ef4444"  # Red
            recommendation = "Active in-the-wild exploitation risk with severe impact. Hotfix or mitigate within 24-48 hours."
        elif high_cvss and not high_epss:
            quadrant = "CRITICAL_PATCH"
            urgency = "HIGH"
            sla_days = 14
            badge_color = "#f97316"  # Orange
            recommendation = "Severe structural flaw with low current in-the-wild exploitation. Patch in next sprint cycle."
        elif not high_cvss and high_epss:
            quadrant = "OPPORTUNISTIC"
            urgency = "ELEVATED"
            sla_days = 30
            badge_color = "#eab308"  # Yellow
            recommendation = "Low impact flaw actively scanned by automated botnets. Deploy WAF rule or patch within 30 days."
        else:
            quadrant = "ROUTINE"
            urgency = "LOW"
            sla_days = 90
            badge_color = "#10b981"  # Green
            recommendation = "Low severity flaw with negligible threat activity. Track in backlog or routine maintenance."

        return {
            "composite_score": score,
            "quadrant": quadrant,
            "urgency": urgency,
            "sla_days": sla_days,
            "badge_color": badge_color,
            "recommendation": recommendation,
            "metrics": {
                "cvss_score": cvss_score,
                "epss_score": epss_score,
                "epss_percentile": epss_percentile
            }
        }

    @classmethod
    def prioritize_finding(
        cls,
        cwe_id: str,
        vuln_name: str,
        cve_id: str = None,
        provided_cvss: float = None,
        provided_vector: str = None,
        is_production: bool = True
    ) -> Dict[str, Any]:
        """
        Complete end-to-end prioritization for any SAST or SCA finding.
        """
        # 1. Determine CVSS
        if provided_cvss is not None and provided_cvss > 0:
            cvss_score = provided_cvss
            cvss_vector = provided_vector or f"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        else:
            cvss_score, cvss_vector = CVSSService.estimate_from_cwe(cwe_id, vuln_name)

        # 2. Query EPSS
        epss_score, epss_percentile = epss_service.get_epss(cve_id, cwe_id, vuln_name)

        # 3. Calculate Risk
        risk_data = cls.calculate_composite_risk(
            cvss_score=cvss_score,
            epss_score=epss_score,
            epss_percentile=epss_percentile,
            is_production=is_production
        )

        risk_data["cvss_vector"] = cvss_vector
        risk_data["severity"] = CVSSService.get_severity(cvss_score)
        return risk_data


risk_engine = RiskEngine()
