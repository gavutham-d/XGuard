"""
Layer A: URL Lexical and Structural Analysis Module for XGuard.
Extracts security indicators from the raw URL structure without making network requests.
"""

import math
import re
from typing import Dict, List, Tuple
from urllib.parse import urlparse
import tldextract
from app.schemas.scan import EvidenceItem
from app.core.security import is_ssrf_safe_ip

SUSPICIOUS_KEYWORDS = {
    "login": "Credential prompt keyword in URL",
    "signin": "Authentication keyword in URL",
    "verify": "Verification prompt keyword in URL",
    "verification": "Account verification prompt in URL",
    "account": "Account management token in URL",
    "banking": "Banking keyword in URL path/query",
    "wallet": "Crypto/payment wallet keyword in URL",
    "password": "Password reference in URL",
    "recover": "Account recovery keyword in URL",
    "suspended": "Urgency/account suspension token in URL",
    "billing": "Financial billing token in URL",
    "invoice": "Invoice/payment cue in URL",
    "security": "Security alert token in URL path/query",
    "update": "Account update cue in URL"
}

RISKY_EXTENSIONS = {
    ".exe": "Windows Executable File",
    ".scr": "Windows Screensaver (often malware dropper)",
    ".bat": "Batch Script File",
    ".cmd": "Command Script File",
    ".vbs": "VBScript File",
    ".msi": "Windows Installer Package",
    ".jar": "Java Archive",
    ".apk": "Android Application Package",
    ".dmg": "macOS Disk Image",
    ".iso": "Disk Image File",
    ".ps1": "PowerShell Script"
}

COMMON_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly",
    "ow.ly", "rb.gy", "cutt.ly", "tiny.cc", "tr.im"
}


def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    char_counts = {}
    for char in data:
        char_counts[char] = char_counts.get(char, 0) + 1
    for count in char_counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


class LexicalAnalyzer:
    def __init__(self):
        self._tld_extractor = tldextract.TLDExtract()

    def analyze(self, raw_url: str) -> Tuple[List[EvidenceItem], Dict[str, any], int]:
        """
        Analyze URL structure and return (evidence_list, metadata, heuristic_risk_points).
        """
        evidence: List[EvidenceItem] = []
        heuristic_points = 0

        url = raw_url.strip()
        if not (url.startswith("http://") or url.startswith("https://")):
            parsed = urlparse("http://" + url)
            has_explicit_scheme = False
        else:
            parsed = urlparse(url)
            has_explicit_scheme = True

        scheme = parsed.scheme.lower() if parsed.scheme else "http"
        hostname = (parsed.hostname or "").lower()
        path = parsed.path or ""
        query = parsed.query or ""
        port = parsed.port

        # Public suffix extraction
        ext = self._tld_extractor(hostname)
        subdomain = ext.subdomain.lower()
        domain = ext.domain.lower()
        suffix = ext.suffix.lower()
        registered_domain = f"{domain}.{suffix}" if suffix else domain

        metadata = {
            "scheme": scheme,
            "hostname": hostname,
            "subdomain": subdomain,
            "domain": domain,
            "suffix": suffix,
            "registered_domain": registered_domain,
            "path": path,
            "query": query,
            "port": port
        }

        # 1. Scheme checks
        if scheme == "http":
            evidence.append(EvidenceItem(
                name="insecure_http_scheme",
                category="lexical",
                description="URL uses unencrypted HTTP instead of modern HTTPS.",
                severity="low",
                source="lexical_analyzer"
            ))
            heuristic_points += 10

        # 2. IP address as host
        ipv4_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
        if re.match(ipv4_pattern, hostname) or ":" in hostname:
            evidence.append(EvidenceItem(
                name="ip_address_host",
                category="lexical",
                description=f"Destination hostname is a raw IP address ({hostname}) rather than a registered domain name.",
                severity="high",
                source="lexical_analyzer"
            ))
            heuristic_points += 35

        # 3. Non-standard port
        if port is not None and port not in (80, 443):
            evidence.append(EvidenceItem(
                name="unusual_port",
                category="lexical",
                description=f"URL specifies non-standard service port {port}.",
                severity="medium",
                source="lexical_analyzer"
            ))
            heuristic_points += 15

        # 4. Punycode / IDN
        if "xn--" in hostname:
            evidence.append(EvidenceItem(
                name="punycode_internationalized_domain",
                category="lexical",
                description=f"Hostname uses Punycode ({hostname}), a common technique in homograph and lookalike attacks.",
                severity="high",
                source="lexical_analyzer"
            ))
            heuristic_points += 30

        # 5. Excessive subdomains
        subdomain_parts = [p for p in subdomain.split(".") if p]
        if len(subdomain_parts) >= 3:
            evidence.append(EvidenceItem(
                name="excessive_subdomains",
                category="lexical",
                description=f"Hostname contains {len(subdomain_parts)} subdomain levels, frequently used to disguise origin.",
                severity="medium",
                source="lexical_analyzer"
            ))
            heuristic_points += 15

        # 6. Authority confusion / @ symbol in URL
        if "@" in raw_url:
            evidence.append(EvidenceItem(
                name="authority_confusion_at_symbol",
                category="lexical",
                description="URL contains '@' symbol, which can mislead users about the actual destination server.",
                severity="high",
                source="lexical_analyzer"
            ))
            heuristic_points += 25

        # 7. Shannon Entropy
        host_entropy = shannon_entropy(hostname)
        if host_entropy > 4.2 and len(hostname) > 15:
            evidence.append(EvidenceItem(
                name="high_hostname_entropy",
                category="lexical",
                description=f"Hostname exhibits high character randomness (entropy {host_entropy}), typical of algorithmically generated domains.",
                severity="medium",
                source="lexical_analyzer"
            ))
            heuristic_points += 15

        # 8. Risky file extensions
        lower_url = url.lower()
        for ext_name, ext_desc in RISKY_EXTENSIONS.items():
            if lower_url.endswith(ext_name) or f"{ext_name}?" in lower_url:
                evidence.append(EvidenceItem(
                    name="dangerous_file_extension",
                    category="lexical",
                    description=f"URL points to a potentially dangerous downloadable executable or script ({ext_desc}).",
                    severity="critical",
                    source="lexical_analyzer"
                ))
                heuristic_points += 45
                break

        # 9. Credential and urgency keywords in URL
        found_keywords = []
        for kw, desc in SUSPICIOUS_KEYWORDS.items():
            if kw in path.lower() or kw in query.lower() or kw in subdomain.lower():
                found_keywords.append(kw)

        if len(found_keywords) >= 2:
            evidence.append(EvidenceItem(
                name="credential_harvesting_tokens",
                category="lexical",
                description=f"URL contains sensitive authentication/urgency keywords: {', '.join(found_keywords[:4])}.",
                severity="medium",
                source="lexical_analyzer"
            ))
            heuristic_points += 20
        elif len(found_keywords) == 1:
            heuristic_points += 8

        # 10. URL Shortener detection
        if registered_domain in COMMON_SHORTENERS or hostname in COMMON_SHORTENERS:
            evidence.append(EvidenceItem(
                name="url_shortener_detected",
                category="redirect",
                description=f"Destination uses a known URL shortening service ({registered_domain}), obscuring the final destination.",
                severity="low",
                source="lexical_analyzer"
            ))
            heuristic_points += 10

        return evidence, metadata, min(heuristic_points, 100)
