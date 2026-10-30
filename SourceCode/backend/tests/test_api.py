"""
Integration tests for FastAPI endpoints in XGuard.
"""

import pytest
import os
import sys
from fastapi.testclient import TestClient

backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.append(backend_dir)

from app.main import app
from app.database.session import engine, Base

Base.metadata.create_all(bind=engine)
client = TestClient(app)


def test_root_endpoint():
    resp = client.get("/")
    assert resp.status_code == 200
    assert resp.json()["status"] == "online"


def test_health_endpoint():
    resp = client.get("/api/v1/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] in ("operational", "degraded")
    assert "ml_model_loaded" in data


def test_model_info_endpoint():
    resp = client.get("/api/v1/model-info")
    assert resp.status_code == 200
    data = resp.json()
    assert "model_name" in data
    assert "features_count" in data


def test_scan_benign_url():
    payload = {
        "url": "https://www.google.com/search?q=threatguard",
        "options": {
            "mode": "balanced",
            "resolve_redirects": False
        }
    }
    resp = client.post("/api/v1/scan", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert "scan_id" in data
    assert data["risk_score"] < 40
    assert data["risk_level"] in ("low", "medium")
    assert data["recommended_action"] == "allow"


def test_scan_phishing_url():
    payload = {
        "url": "http://paypal.com.account-verification-service.net/login.php",
        "options": {
            "mode": "balanced",
            "resolve_redirects": False
        }
    }
    resp = client.post("/api/v1/scan", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["risk_score"] >= 60
    assert data["risk_level"] in ("high", "critical")
    assert data["recommended_action"] in ("warn", "block")
    assert any("brand" in e["category"] or "subdomain" in e["name"] for e in data["evidence"])


def test_chat_endpoint_grounded_answer():
    payload = {
        "message": "Why was this link flagged as risky?",
        "current_scan_context": {
            "url": "http://paypal.com.account-verification-service.net/login.php",
            "risk_score": 88,
            "risk_level": "critical",
            "predicted_category": "phishing",
            "evidence": [
                {
                    "name": "subdomain_brand_spoofing",
                    "category": "brand",
                    "description": "Embedded PayPal in subdomain",
                    "severity": "critical",
                    "source": "brand_detector"
                }
            ]
        }
    }
    resp = client.post("/api/v1/chat", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert "answer" in data
    assert len(data["suggested_followups"]) > 0


def test_feedback_submission():
    payload = {
        "url": "https://example.com/test",
        "feedback_type": "false_positive",
        "user_comment": "This was an internal developer URL flagged unexpectedly.",
        "user_consent": True
    }
    resp = client.post("/api/v1/feedback", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    assert "feedback_id" in data
