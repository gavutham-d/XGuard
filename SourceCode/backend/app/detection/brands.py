"""
Brand Impersonation and Typosquatting Detection for XGuard.
Compares parsed domains against high-value commercial targets to detect
subdomain spoofing, edit-distance variations, and visual lookalikes.
"""

from typing import Dict, List, Tuple
from app.schemas.scan import EvidenceItem

# High-value targets and their official registered domains
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


def levenshtein(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return levenshtein(s2, s1)
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


class BrandDetector:
    def __init__(self, brands_map: Dict[str, str] = None):
        self.brands = brands_map or TOP_BRANDS

    def analyze(self, metadata: Dict[str, any]) -> Tuple[List[EvidenceItem], int]:
        evidence: List[EvidenceItem] = []
        brand_points = 0

        subdomain = metadata.get("subdomain", "").lower()
        domain = metadata.get("domain", "").lower()
        registered_domain = metadata.get("registered_domain", "").lower()
        path = metadata.get("path", "").lower()

        for brand_name, official_domain in self.brands.items():
            # If the user is on the legitimate official brand domain, skip
            if registered_domain == official_domain:
                continue

            # 1. Subdomain brand spoofing (e.g. paypal.com.attackersite.com or paypal.verify-login.biz)
            if brand_name in subdomain:
                evidence.append(EvidenceItem(
                    name="subdomain_brand_spoofing",
                    category="brand",
                    description=f"Hostname embeds trusted brand '{brand_name}' as a subdomain, but registered domain is '{registered_domain}' (Official: '{official_domain}').",
                    severity="critical",
                    source="brand_detector"
                ))
                brand_points += 45
                break

            # 2. Typosquatting / Edit distance on second-level domain (e.g. paypa1.com, goog1e.com, micros0ft.com)
            if domain and domain != brand_name:
                dist = levenshtein(domain, brand_name)
                # Check for 1-character typo or character substitution (0->o, 1->l, etc)
                if dist == 1 or (dist == 2 and abs(len(domain) - len(brand_name)) <= 1):
                    evidence.append(EvidenceItem(
                        name="typosquatting_brand_impersonation",
                        category="brand",
                        description=f"Domain '{registered_domain}' is an edit-distance {dist} permutation of trusted brand '{brand_name}' (Official: '{official_domain}').",
                        severity="high",
                        source="brand_detector"
                    ))
                    brand_points += 40
                    break

            # 3. Brand name embedded in suspicious path/query on unfamiliar third-party domain
            if brand_name in path:
                # E.g. /paypal/login.php or /chase/verify.html
                if any(k in path for k in ("login", "signin", "verify", "secure", "auth", "account")):
                    evidence.append(EvidenceItem(
                        name="path_brand_credential_impersonation",
                        category="brand",
                        description=f"Path references brand '{brand_name}' alongside credential tokens on unverified host '{registered_domain}'.",
                        severity="high",
                        source="brand_detector"
                    ))
                    brand_points += 30
                    break

        return evidence, min(brand_points, 100)
