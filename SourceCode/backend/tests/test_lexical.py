"""
Unit tests for URL lexical and structural feature analysis.
"""

import pytest
import os
import sys

# Ensure backend directory in sys.path
backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.append(backend_dir)

from app.detection.lexical import LexicalAnalyzer


def test_benign_url_lexical():
    analyzer = LexicalAnalyzer()
    evidence, meta, points = analyzer.analyze("https://www.google.com/search?q=cybersecurity")
    assert meta["hostname"] == "www.google.com"
    assert meta["registered_domain"] == "google.com"
    assert meta["scheme"] == "https"
    assert points < 25
    # Should not have dangerous extension or raw IP host
    assert not any(e.name == "dangerous_file_extension" for e in evidence)
    assert not any(e.name == "ip_address_host" for e in evidence)


def test_ip_address_host_detection():
    analyzer = LexicalAnalyzer()
    evidence, meta, points = analyzer.analyze("http://194.26.29.112:8080/secure/login.php")
    assert any(e.name == "ip_address_host" for e in evidence)
    assert any(e.name == "unusual_port" for e in evidence)
    assert points >= 35


def test_punycode_homograph_detection():
    analyzer = LexicalAnalyzer()
    evidence, meta, points = analyzer.analyze("http://xn--pypal-4ve.com/signin/webscr")
    assert any(e.name == "punycode_internationalized_domain" for e in evidence)
    assert points >= 30


def test_dangerous_extension_detection():
    analyzer = LexicalAnalyzer()
    evidence, meta, points = analyzer.analyze("http://malware-drop-zone.com/invoices/urgent_doc.pdf.exe")
    assert any(e.name == "dangerous_file_extension" for e in evidence)
    assert points >= 45


def test_credential_harvesting_tokens():
    analyzer = LexicalAnalyzer()
    evidence, meta, points = analyzer.analyze("http://random-host-123.com/banking/login/verify-account.php")
    assert any(e.name == "credential_harvesting_tokens" for e in evidence)
