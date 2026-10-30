"""
URL Feature Extraction Module for XGuard.
Extracts lexical, structural, and brand-based features from raw URLs
for machine learning classification and heuristic risk assessment.
"""

import math
import re
from typing import Dict, List, Any
from urllib.parse import urlparse
import tldextract

# Canonical brand definitions and their authentic domains
TOP_BRANDS = {
    "google": "google.com",
    "microsoft": "microsoft.com",
    "apple": "apple.com",
    "paypal": "paypal.com",
    "amazon": "amazon.com",
    "netflix": "netflix.com",
    "chase": "chase.com",
    "bankofamerica": "bankofamerica.com",
    "wellsfargo": "wellsfargo.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "twitter": "twitter.com",
    "x": "x.com",
    "binance": "binance.com",
    "coinbase": "coinbase.com",
    "steam": "steampowered.com",
    "dropbox": "dropbox.com",
    "adobe": "adobe.com",
    "linkedin": "linkedin.com",
    "yahoo": "yahoo.com",
    "ebay": "ebay.com"
}

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "verification", "secure", "security",
    "account", "update", "confirm", "banking", "wallet", "password",
    "credential", "recover", "authenticate", "auth", "suspended",
    "billing", "payment", "invoice", "validate", "support", "service",
    "alert", "unlock", "notification", "bonus", "free", "gift"
]

RISKY_EXTENSIONS = [
    ".exe", ".scr", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
    ".wsf", ".wsh", ".ps1", ".msi", ".jar", ".apk", ".dmg", ".iso"
]

COMMON_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly",
    "ow.ly", "rb.gy", "cutt.ly", "tiny.cc", "tr.im"
]


def shannon_entropy(data: str) -> float:
    """Compute the Shannon entropy of a string."""
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
    return entropy


def levenshtein_distance(s1: str, s2: str) -> int:
    """Compute the Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def is_ip_address(hostname: str) -> bool:
    """Check if hostname is a raw IPv4 or IPv6 address."""
    # IPv4 regex
    ipv4_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    if re.match(ipv4_pattern, hostname):
        parts = hostname.split(".")
        return all(0 <= int(p) <= 255 for p in parts)
    # IPv6 check
    if ":" in hostname:
        return True
    return False


class URLLexicalFeatureExtractor:
    """Extracts a vector of numeric features suitable for ML models and scoring."""

    FEATURE_NAMES = [
        "url_length",
        "hostname_length",
        "path_length",
        "query_length",
        "count_dots",
        "count_hyphens",
        "count_underscores",
        "count_slashes",
        "count_question_marks",
        "count_equal_signs",
        "count_at_symbols",
        "count_percent_symbols",
        "count_subdomains",
        "is_https",
        "is_ip",
        "has_unusual_port",
        "is_punycode",
        "hostname_entropy",
        "path_entropy",
        "digit_ratio_hostname",
        "digit_ratio_url",
        "suspicious_keyword_count",
        "risky_extension_flag",
        "is_known_shortener",
        "brand_name_in_subdomain",
        "brand_name_in_path",
        "min_brand_edit_distance",
        "is_typosquatting_suspect"
    ]

    def __init__(self):
        # Cache tldextract extractor for efficiency
        self._tld_extractor = tldextract.TLDExtract()

    def extract_features(self, url: str) -> Dict[str, Any]:
        """Parse URL and extract all defined features."""
        url = url.strip()
        if not (url.startswith("http://") or url.startswith("https://")):
            parsed_raw = urlparse("//" + url)
            url_norm = "http://" + url
            parsed = urlparse(url_norm)
        else:
            parsed = urlparse(url)

        hostname = (parsed.hostname or "").lower()
        path = parsed.path or ""
        query = parsed.query or ""
        port = parsed.port

        # Domain breakdown using Public Suffix List
        ext = self._tld_extractor(hostname)
        subdomain = ext.subdomain.lower()
        domain = ext.domain.lower()
        suffix = ext.suffix.lower()
        registered_domain = f"{domain}.{suffix}" if suffix else domain

        # Basic lengths
        url_length = len(url)
        hostname_length = len(hostname)
        path_length = len(path)
        query_length = len(query)

        # Character counts
        count_dots = url.count(".")
        count_hyphens = url.count("-")
        count_underscores = url.count("_")
        count_slashes = url.count("/")
        count_question_marks = url.count("?")
        count_equal_signs = url.count("=")
        count_at_symbols = url.count("@")
        count_percent_symbols = url.count("%")

        # Subdomain count
        subdomain_parts = [p for p in subdomain.split(".") if p]
        count_subdomains = len(subdomain_parts)

        # Scheme & Port
        is_https = 1 if parsed.scheme == "https" else 0
        is_ip = 1 if is_ip_address(hostname) else 0

        has_unusual_port = 0
        if port is not None:
            if port not in (80, 443, 8080, 8443):
                has_unusual_port = 1

        # Punycode / IDN
        is_punycode = 1 if "xn--" in hostname else 0

        # Entropies
        hostname_entropy = round(shannon_entropy(hostname), 4)
        path_entropy = round(shannon_entropy(path), 4)

        # Digit ratios
        digits_in_host = sum(1 for c in hostname if c.isdigit())
        digit_ratio_hostname = round(digits_in_host / max(1, hostname_length), 4)

        digits_in_url = sum(1 for c in url if c.isdigit())
        digit_ratio_url = round(digits_in_url / max(1, url_length), 4)

        # Suspicious keywords
        lower_url = url.lower()
        suspicious_keyword_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in lower_url)

        # Dangerous extensions
        risky_extension_flag = 1 if any(lower_url.endswith(ext_name) or ext_name + "?" in lower_url for ext_name in RISKY_EXTENSIONS) else 0

        # Shortened URL
        is_known_shortener = 1 if registered_domain in COMMON_SHORTENERS or hostname in COMMON_SHORTENERS else 0

        # Brand analysis
        brand_name_in_subdomain = 0
        brand_name_in_path = 0
        min_brand_edit_distance = 99
        is_typosquatting_suspect = 0

        for brand, official_domain in TOP_BRANDS.items():
            if brand in subdomain and registered_domain != official_domain:
                brand_name_in_subdomain = 1

            if brand in path.lower() and registered_domain != official_domain:
                brand_name_in_path = 1

            if domain and domain != brand:
                dist = levenshtein_distance(domain, brand)
                if dist < min_brand_edit_distance:
                    min_brand_edit_distance = dist
                # If edit distance is 1 or 2 and domain is roughly similar length
                if 1 <= dist <= 2 and abs(len(domain) - len(brand)) <= 1 and registered_domain != official_domain:
                    is_typosquatting_suspect = 1

        features = {
            "url_length": url_length,
            "hostname_length": hostname_length,
            "path_length": path_length,
            "query_length": query_length,
            "count_dots": count_dots,
            "count_hyphens": count_hyphens,
            "count_underscores": count_underscores,
            "count_slashes": count_slashes,
            "count_question_marks": count_question_marks,
            "count_equal_signs": count_equal_signs,
            "count_at_symbols": count_at_symbols,
            "count_percent_symbols": count_percent_symbols,
            "count_subdomains": count_subdomains,
            "is_https": is_https,
            "is_ip": is_ip,
            "has_unusual_port": has_unusual_port,
            "is_punycode": is_punycode,
            "hostname_entropy": hostname_entropy,
            "path_entropy": path_entropy,
            "digit_ratio_hostname": digit_ratio_hostname,
            "digit_ratio_url": digit_ratio_url,
            "suspicious_keyword_count": suspicious_keyword_count,
            "risky_extension_flag": risky_extension_flag,
            "is_known_shortener": is_known_shortener,
            "brand_name_in_subdomain": brand_name_in_subdomain,
            "brand_name_in_path": brand_name_in_path,
            "min_brand_edit_distance": min_brand_edit_distance,
            "is_typosquatting_suspect": is_typosquatting_suspect
        }

        metadata = {
            "hostname": hostname,
            "subdomain": subdomain,
            "domain": domain,
            "suffix": suffix,
            "registered_domain": registered_domain,
            "path": path,
            "query": query,
            "port": port,
            "scheme": parsed.scheme or "http"
        }

        return {"features": features, "metadata": metadata}

    def feature_vector(self, url: str) -> List[float]:
        """Return ordered numeric feature vector for scikit-learn models."""
        res = self.extract_features(url)
        feat_dict = res["features"]
        return [float(feat_dict[k]) for k in self.FEATURE_NAMES]
