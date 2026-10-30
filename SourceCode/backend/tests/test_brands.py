"""
Unit tests for Brand Impersonation and Typosquatting detection.
"""

import pytest
import os
import sys

backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.append(backend_dir)

from app.detection.brands import BrandDetector


def test_legitimate_brand_domain_not_flagged():
    detector = BrandDetector()
    meta = {
        "subdomain": "www",
        "domain": "paypal",
        "registered_domain": "paypal.com",
        "path": "/signin"
    }
    evidence, points = detector.analyze(meta)
    assert len(evidence) == 0
    assert points == 0


def test_subdomain_brand_spoofing():
    detector = BrandDetector()
    meta = {
        "subdomain": "paypal.com.account-verification-service",
        "domain": "account-verification-service",
        "registered_domain": "account-verification-service.net",
        "path": "/login.php"
    }
    evidence, points = detector.analyze(meta)
    assert any(e.name == "subdomain_brand_spoofing" for e in evidence)
    assert points >= 45


def test_typosquatting_detection():
    detector = BrandDetector()
    meta = {
        "subdomain": "www",
        "domain": "paypa1",
        "registered_domain": "paypa1.com",
        "path": "/webscr"
    }
    evidence, points = detector.analyze(meta)
    assert any(e.name == "typosquatting_brand_impersonation" for e in evidence)
    assert points >= 40
