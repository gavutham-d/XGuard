"""
Security and validation utilities for XGuard.
Provides SSRF mitigation, IP address classification, URL sanitization,
and sensitive query parameter redaction.
"""

import ipaddress
import re
import socket
from typing import Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

SENSITIVE_PARAM_NAMES = {
    "token", "password", "pwd", "secret", "auth", "api_key", "apikey",
    "access_token", "session", "session_id", "key", "code", "otp",
    "signature", "sig", "credential", "credit_card", "cvv", "ssn"
}

ALLOWED_SCHEMES = {"http", "https"}


def is_ssrf_safe_ip(ip_str: str) -> bool:
    """
    Verify whether an IP address is publicly routable and safe from SSRF targets:
    Reject private, loopback, link-local, reserved, multicast, or cloud metadata IP.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False

    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    ):
        return False

    # Block AWS / GCP / Azure metadata service explicitly: 169.254.169.254
    if str(ip) == "169.254.169.254":
        return False

    return True


def validate_destination_ssrf(hostname: str) -> Tuple[bool, str]:
    """
    Resolve destination hostname to IP and verify against SSRF protections.
    Returns (is_safe, resolved_ip_or_error).
    """
    if not hostname:
        return False, "Empty hostname"

    # If raw IP
    try:
        ip = ipaddress.ip_address(hostname)
        if not is_ssrf_safe_ip(str(ip)):
            return False, f"Target IP {hostname} is non-routable or private (SSRF blocked)"
        return True, str(ip)
    except ValueError:
        pass

    # Resolve via DNS
    try:
        addr_info = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for family, _, _, _, sockaddr in addr_info:
            ip_candidate = sockaddr[0]
            if not is_ssrf_safe_ip(ip_candidate):
                return False, f"Resolved IP {ip_candidate} is non-routable or private (SSRF blocked)"
        return True, addr_info[0][4][0] if addr_info else "OK"
    except socket.gaierror as e:
        return False, f"DNS resolution failed: {str(e)}"
    except Exception as e:
        return False, f"Network validation error: {str(e)}"


def sanitize_and_redact_url(raw_url: str) -> str:
    """
    Redact sensitive query parameters from URLs before logging, storage,
    or transmission to external intelligence feeds.
    """
    try:
        parsed = urlparse(raw_url.strip())
        if not parsed.scheme or not parsed.netloc:
            return raw_url

        query_params = parse_qsl(parsed.query, keep_blank_values=True)
        redacted_params = []
        for key, val in query_params:
            if key.lower() in SENSITIVE_PARAM_NAMES or any(s in key.lower() for s in ("token", "pass", "secret")):
                redacted_params.append((key, "[REDACTED]"))
            else:
                redacted_params.append((key, val))

        new_query = urlencode(redacted_params)
        redacted_url = urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment
        ))
        return redacted_url
    except Exception:
        return raw_url


def validate_url_scheme(url: str) -> bool:
    """Ensure URL uses standard HTTP/HTTPS schemes only."""
    try:
        parsed = urlparse(url.strip())
        return parsed.scheme.lower() in ALLOWED_SCHEMES
    except Exception:
        return False
