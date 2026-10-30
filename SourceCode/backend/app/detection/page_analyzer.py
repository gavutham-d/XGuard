"""
Layer E: Live Webpage Signals and Form Analysis for XGuard.
Assesses submitted DOM signals, including cross-domain login form actions,
payment field exposures, and anchor text mismatches.
"""

from typing import List, Tuple, Optional
from urllib.parse import urlparse
import tldextract
from app.schemas.scan import EvidenceItem, PageSignalsInput


class PageSignalsAnalyzer:
    def __init__(self):
        self._tld_extractor = tldextract.TLDExtract()

    def analyze(
        self, signals: Optional[PageSignalsInput], metadata: dict
    ) -> Tuple[List[EvidenceItem], int]:
        evidence: List[EvidenceItem] = []
        page_points = 0

        if not signals:
            return evidence, page_points

        target_reg_domain = metadata.get("registered_domain", "")

        # 1. Password field on page
        if signals.has_password_field:
            if signals.has_cross_domain_form:
                evidence.append(EvidenceItem(
                    name="cross_domain_credential_submission",
                    category="page",
                    description="Page contains an authentication form that submits credentials to a different external domain.",
                    severity="critical",
                    source="page_analyzer"
                ))
                page_points += 40
            else:
                evidence.append(EvidenceItem(
                    name="login_form_present",
                    category="page",
                    description="Page contains an active password input field requesting user credentials.",
                    severity="low",
                    source="page_analyzer"
                ))
                page_points += 5

        # 2. Payment / Credit Card field
        if signals.has_card_field:
            if metadata.get("scheme") == "http":
                evidence.append(EvidenceItem(
                    name="unencrypted_payment_form",
                    category="page",
                    description="Page contains financial or card input fields over an unencrypted HTTP connection.",
                    severity="critical",
                    source="page_analyzer"
                ))
                page_points += 50
            else:
                evidence.append(EvidenceItem(
                    name="payment_fields_present",
                    category="page",
                    description="Page requests financial card details.",
                    severity="medium",
                    source="page_analyzer"
                ))
                page_points += 15

        # 3. Link text vs href mismatch
        if signals.link_text_mismatch:
            evidence.append(EvidenceItem(
                name="misleading_anchor_text",
                category="page",
                description="The clickable link text visibly differs from the actual underlying destination URL (deceptive anchor).",
                severity="high",
                source="page_analyzer"
            ))
            page_points += 30

        # 4. Excessive hidden or nested iframes
        if signals.iframe_count >= 5:
            evidence.append(EvidenceItem(
                name="excessive_iframes_detected",
                category="page",
                description=f"Page embeds {signals.iframe_count} iframes, an indicator often seen in clickjacking or ad injection.",
                severity="medium",
                source="page_analyzer"
            ))
            page_points += 15

        return evidence, min(page_points, 100)
