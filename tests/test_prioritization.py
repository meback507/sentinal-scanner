"""
AegisSec Prioritization & Risk Engine Unit Test Suite
Validates CVSS v3.1 scoring, EPSS integration, CISA KEV service, and composite 4-quadrant prioritization.
"""

import pytest
from backend.prioritization.cvss_service import CVSSService
from backend.prioritization.epss_service import epss_service
from backend.prioritization.cisa_service import cisa_service
from backend.prioritization.risk_engine import RiskEngine, risk_engine


def test_cvss_service_v31_calculation():
    # Critical CVSS: Network, Low Complexity, No Privileges, No User Interaction, Scope Unchanged, High CIA
    score, vector = CVSSService.calculate_v31(
        av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="H"
    )
    assert score == 9.8
    assert "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" in vector
    assert CVSSService.get_severity(score) == "CRITICAL"

    # Medium CVSS: Local, High Complexity, High Privileges
    med_score, med_vector = CVSSService.calculate_v31(
        av="L", ac="H", pr="H", ui="R", s="U", c="L", i="L", a="N"
    )
    assert 0.0 < med_score < 7.0
    assert CVSSService.get_severity(med_score) in ["LOW", "MEDIUM"]


def test_epss_service_known_cve_lookup():
    # Test known high-profile CVE lookup (e.g. Log4Shell CVE-2021-44228)
    score, percentile = epss_service.get_epss("CVE-2021-44228")
    assert score >= 0.80  # Highly weaponized
    assert percentile >= 0.90

    # Test unknown CVE fallback / heuristic
    score_unk, perc_unk = epss_service.get_epss("CVE-2099-99999", cwe_id="CWE-89")
    assert 0.0 <= score_unk <= 1.0
    assert 0.0 <= perc_unk <= 1.0


def test_cisa_kev_service_lookup():
    # Check known CISA KEV vulnerability
    is_kev, meta = cisa_service.is_known_exploited("CVE-2021-44228")
    assert is_kev is True
    assert "Log4j" in meta.get("vulnerability_name", "") or "Apache" in meta.get("vendor_project", "")

    # Non-KEV CVE
    is_kev_fake, meta_fake = cisa_service.is_known_exploited("CVE-9999-00000")
    assert is_kev_fake is False


def test_risk_engine_act_now_quadrant():
    # CVSS >= 7.0 and EPSS >= 0.20 -> ACT_NOW
    result = RiskEngine.calculate_composite_risk(
        cvss_score=9.8,
        epss_score=0.75,
        epss_percentile=0.98,
        is_production=True,
        is_public_facing=True
    )
    assert result["quadrant"] == "ACT_NOW"
    assert result["urgency"] == "IMMEDIATE"
    assert result["sla_days"] == 2
    assert result["composite_score"] >= 80.0


def test_risk_engine_critical_patch_quadrant():
    # High CVSS (>= 7.0) but low EPSS (< 0.20) -> CRITICAL_PATCH
    result = RiskEngine.calculate_composite_risk(
        cvss_score=8.5,
        epss_score=0.03,
        epss_percentile=0.40,
        is_production=True,
        is_public_facing=True
    )
    assert result["quadrant"] == "CRITICAL_PATCH"
    assert result["urgency"] == "HIGH"
    assert result["sla_days"] == 14


def test_risk_engine_opportunistic_quadrant():
    # Low CVSS (< 7.0) but high EPSS (>= 0.20) -> OPPORTUNISTIC
    result = RiskEngine.calculate_composite_risk(
        cvss_score=5.5,
        epss_score=0.35,
        epss_percentile=0.88,
        is_production=True,
        is_public_facing=True
    )
    assert result["quadrant"] == "OPPORTUNISTIC"
    assert result["urgency"] == "ELEVATED"
    assert result["sla_days"] == 30


def test_risk_engine_routine_quadrant():
    # Low CVSS (< 7.0) and low EPSS (< 0.20) -> ROUTINE
    result = RiskEngine.calculate_composite_risk(
        cvss_score=4.0,
        epss_score=0.01,
        epss_percentile=0.20,
        is_production=False,
        is_public_facing=False
    )
    assert result["quadrant"] == "ROUTINE"
    assert result["urgency"] == "LOW"
    assert result["sla_days"] == 90

