"""
Unit tests for SSRF protection and safe redirect analysis.
"""

import pytest
import os
import sys

backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.append(backend_dir)

from app.core.security import is_ssrf_safe_ip, validate_destination_ssrf
from app.detection.redirects import SafeRedirectResolver


def test_ssrf_safe_ip_blocks_private_and_loopback():
    assert not is_ssrf_safe_ip("127.0.0.1")
    assert not is_ssrf_safe_ip("10.0.0.5")
    assert not is_ssrf_safe_ip("192.168.1.1")
    assert not is_ssrf_safe_ip("172.16.5.10")
    assert not is_ssrf_safe_ip("169.254.169.254") # Cloud metadata
    assert not is_ssrf_safe_ip("::1") # IPv6 loopback


def test_ssrf_safe_ip_allows_public_ips():
    assert is_ssrf_safe_ip("8.8.8.8")
    assert is_ssrf_safe_ip("1.1.1.1")
    assert is_ssrf_safe_ip("142.250.190.46") # Google


def test_validate_destination_ssrf_blocks_localhost():
    is_safe, msg = validate_destination_ssrf("127.0.0.1")
    assert not is_safe
    assert "SSRF blocked" in msg


@pytest.mark.asyncio
async def test_redirect_resolver_aborts_on_ssrf_target():
    resolver = SafeRedirectResolver()
    hops, evidence, reason = await resolver.trace_redirects("http://127.0.0.1:8000/internal-admin")
    assert any(e.name == "ssrf_target_blocked" for e in evidence)
    assert len(hops) == 1
    assert "SSRF Blocked" in hops[0].note
