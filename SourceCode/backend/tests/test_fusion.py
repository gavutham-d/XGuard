"""
Unit tests for the Risk Fusion and Decision Engine.
"""

import pytest
import os
import sys

backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.append(backend_dir)

from app.detection.fusion import RiskFusionEngine
from app.schemas.scan import EvidenceItem, IntelligenceMatch


def test_fusion_confirmed_threat_intel():
    engine = RiskFusionEngine()
    intel_matches = [
        IntelligenceMatch(
            source="XGuard Local IOC Feed",
            matched=True,
            threat_category="malware",
            confidence="critical",
            last_checked="2026-10-12T12:00:00Z"
        )
    ]
    intel_evidence = [
        EvidenceItem(
            name="local_threat_feed_malware",
            category="intel",
            description="Confirmed malware drop",
            severity="critical",
            source="threat_intelligence"
        )
    ]
    res = engine.fuse(
        url="http://malware-site.com/dropper.exe",
        metadata={"hostname": "malware-site.com", "registered_domain": "malware-site.com"},
        lexical_evidence=[],
        lexical_points=0,
        brand_evidence=[],
        brand_points=0,
        ml_prediction=1,
        ml_probability=0.9,
        ml_meta={"status": "success", "model_name": "TestModel"},
        intelligence_matches=intel_matches,
        intel_evidence=intel_evidence,
        redirect_hops=[],
        redirect_evidence=[],
        page_evidence=[],
        page_points=0,
        mode="balanced"
    )

    assert res["risk_score"] >= 90
    assert res["risk_level"] == "critical"
    assert res["recommended_action"] == "block"
    assert res["predicted_category"] == "malware"


def test_fusion_benign_url():
    engine = RiskFusionEngine()
    intel_matches = [
        IntelligenceMatch(
            source="Local Feed",
            matched=False,
            last_checked="2026-10-12T12:00:00Z"
        )
    ]
    res = engine.fuse(
        url="https://www.google.com/search",
        metadata={"hostname": "www.google.com", "registered_domain": "google.com"},
        lexical_evidence=[],
        lexical_points=0,
        brand_evidence=[],
        brand_points=0,
        ml_prediction=0,
        ml_probability=0.02,
        ml_meta={"status": "success", "model_name": "TestModel"},
        intelligence_matches=intel_matches,
        intel_evidence=[],
        redirect_hops=[],
        redirect_evidence=[],
        page_evidence=[],
        page_points=0,
        mode="balanced"
    )

    assert res["risk_score"] < 25
    assert res["risk_level"] == "low"
    assert res["recommended_action"] == "allow"
