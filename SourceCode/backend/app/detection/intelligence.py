"""
Reputation and Threat Intelligence Adapters for XGuard.
Integrates live URLhaus queries and local threat feed lookups with
strict query-parameter privacy redaction and fail-safe handling.
"""

from datetime import datetime, timezone
from typing import List, Tuple
from urllib.parse import urlparse
import httpx
from app.schemas.scan import IntelligenceMatch, EvidenceItem
from app.core.security import sanitize_and_redact_url
from app.core.config import settings

# Curated local known-bad IOC indicators (verified test fixtures and confirmed malware drops)
KNOWN_BAD_INDICATORS = {
    "account-verification-service.net": ("phishing", "high", "Known credential harvester domain"),
    "update-payment-info.cc": ("phishing", "high", "Impersonating streaming provider billing"),
    "driver_update.scr": ("malware", "critical", "Known dropper binary payload"),
    "wallet_generator.exe": ("malware", "critical", "Cryptocurrency wallet stealer trojan"),
    "claim-free-eth-airdrop.html": ("scam", "high", "Crypto air-drop wallet drainer scam"),
    "statement_q3.pdf.exe": ("malware", "critical", "Double extension disguise malware"),
    "185.220.101.5": ("phishing", "high", "Known bulletproof host for PayPal credential phishing"),
    "45.145.185.9": ("malware", "critical", "Distribution IP for ransomware loaders")
}


class ThreatIntelligenceEngine:
    def __init__(self):
        self.urlhaus_enabled = settings.URLHAUS_API_ENABLED
        self.timeout = settings.URLHAUS_TIMEOUT_SECONDS

    async def query_feeds(
        self, raw_url: str, metadata: dict, privacy_mode: bool = False
    ) -> Tuple[List[IntelligenceMatch], List[EvidenceItem]]:
        matches: List[IntelligenceMatch] = []
        evidence: List[EvidenceItem] = []
        now_iso = datetime.now(timezone.utc).isoformat()

        hostname = metadata.get("hostname", "").lower()
        registered_domain = metadata.get("registered_domain", "").lower()
        clean_url = sanitize_and_redact_url(raw_url)

        # 1. Local Threat Feed / Curated IOC Lookups (100% private, runs offline)
        local_matched = False
        for indicator, (threat_type, confidence, desc) in KNOWN_BAD_INDICATORS.items():
            if indicator in raw_url.lower() or indicator == hostname or indicator == registered_domain:
                matches.append(IntelligenceMatch(
                    source="XGuard Local IOC Feed",
                    matched=True,
                    threat_category=threat_type,
                    confidence=confidence,
                    last_checked=now_iso,
                    details={"indicator": indicator, "description": desc}
                ))
                evidence.append(EvidenceItem(
                    name=f"local_threat_feed_{threat_type}",
                    category="intel",
                    description=f"Destination matches XGuard verified indicator ({desc}).",
                    severity="critical" if confidence == "critical" else "high",
                    source="threat_intelligence"
                ))
                local_matched = True
                break

        if not local_matched:
            matches.append(IntelligenceMatch(
                source="XGuard Local IOC Feed",
                matched=False,
                threat_category=None,
                confidence="low",
                last_checked=now_iso,
                details={"status": "No match in curated local IOC database"}
            ))

        # 2. Remote URLhaus lookup (if enabled and privacy mode is False)
        if self.urlhaus_enabled and not privacy_mode:
            try:
                # Query URLhaus API for URL reputation
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    data = {"url": clean_url}
                    resp = await client.post("https://urlhaus-api.abuse.ch/v1/url/", data=data)
                    if resp.status_code == 200:
                        res_json = resp.json()
                        query_status = res_json.get("query_status")
                        if query_status == "ok":
                            threat = res_json.get("threat", "malware_download")
                            matches.append(IntelligenceMatch(
                                source="abuse.ch URLhaus",
                                matched=True,
                                threat_category=threat,
                                confidence="high",
                                last_checked=now_iso,
                                details={
                                    "url_status": res_json.get("url_status"),
                                    "tags": res_json.get("tags", [])
                                }
                            ))
                            evidence.append(EvidenceItem(
                                name="urlhaus_malware_confirmed",
                                category="intel",
                                description=f"URLhaus threat feed confirmed malicious record ({threat}).",
                                severity="critical",
                                source="threat_intelligence"
                            ))
                        else:
                            # Negative match: explicitly record that feed has no entry, NOT safe!
                            matches.append(IntelligenceMatch(
                                source="abuse.ch URLhaus",
                                matched=False,
                                threat_category=None,
                                confidence="low",
                                last_checked=now_iso,
                                details={"query_status": query_status}
                            ))
                    else:
                        matches.append(IntelligenceMatch(
                            source="abuse.ch URLhaus",
                            matched=False,
                            last_checked=now_iso,
                            error=f"HTTP {resp.status_code} response from provider"
                        ))
            except httpx.TimeoutException:
                matches.append(IntelligenceMatch(
                    source="abuse.ch URLhaus",
                    matched=False,
                    last_checked=now_iso,
                    error="Lookup timed out (network latency)"
                ))
            except Exception as e:
                matches.append(IntelligenceMatch(
                    source="abuse.ch URLhaus",
                    matched=False,
                    last_checked=now_iso,
                    error=f"Lookup failed: {str(e)}"
                ))
        elif privacy_mode:
            matches.append(IntelligenceMatch(
                source="abuse.ch URLhaus",
                matched=False,
                last_checked=now_iso,
                details={"status": "External lookups disabled in Privacy Mode"}
            ))

        return matches, evidence
