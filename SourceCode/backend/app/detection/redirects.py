"""
Safe Redirect Analysis Engine with strict SSRF Protection for XGuard.
Traces redirect chains hop-by-hop, pre-validating each destination IP
against RFC 1918, loopback, and cloud metadata ranges before dispatch.
"""

from typing import List, Tuple, Optional
from urllib.parse import urlparse, urljoin
import httpx
import tldextract
from app.schemas.scan import RedirectHop, EvidenceItem
from app.core.security import validate_destination_ssrf, validate_url_scheme
from app.core.logging import logger

COMMON_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly",
    "ow.ly", "rb.gy", "cutt.ly", "tiny.cc", "tr.im"
}


class SafeRedirectResolver:
    def __init__(self, max_hops: int = 5, timeout_seconds: float = 2.0):
        self.max_hops = max_hops
        self.timeout_seconds = timeout_seconds
        self._tld_extractor = tldextract.TLDExtract()

    async def trace_redirects(
        self, initial_url: str
    ) -> Tuple[List[RedirectHop], List[EvidenceItem], Optional[str]]:
        """
        Safely inspect redirect hops without SSRF exposure or downloading full bodies.
        Returns (redirect_hops, evidence_items, failure_reason_if_any).
        """
        hops: List[RedirectHop] = []
        evidence: List[EvidenceItem] = []
        current_url = initial_url
        visited_urls = set()

        initial_parsed = urlparse(initial_url)
        initial_ext = self._tld_extractor(initial_parsed.hostname or "")
        initial_reg_domain = f"{initial_ext.domain}.{initial_ext.suffix}" if initial_ext.suffix else initial_ext.domain

        # Custom safe client with strict limits
        async with httpx.AsyncClient(
            follow_redirects=False,
            timeout=self.timeout_seconds,
            headers={"User-Agent": "XGuard-Security-Scanner/1.0"}
        ) as client:
            for hop_num in range(1, self.max_hops + 1):
                if current_url in visited_urls:
                    evidence.append(EvidenceItem(
                        name="redirect_loop_detected",
                        category="redirect",
                        description=f"Redirect chain entered an infinite loop at hop {hop_num}.",
                        severity="high",
                        source="redirect_resolver"
                    ))
                    break
                visited_urls.add(current_url)

                if not validate_url_scheme(current_url):
                    evidence.append(EvidenceItem(
                        name="unsupported_redirect_scheme",
                        category="redirect",
                        description=f"Redirect attempted unsafe or non-HTTP scheme at hop {hop_num}.",
                        severity="high",
                        source="redirect_resolver"
                    ))
                    break

                parsed = urlparse(current_url)
                hostname = parsed.hostname or ""

                # CRITICAL SSRF GUARD: Validate destination IP before making request
                is_safe, resolved_ip = validate_destination_ssrf(hostname)
                if not is_safe:
                    hops.append(RedirectHop(
                        order=hop_num,
                        url=current_url,
                        domain=hostname,
                        resolved_ip=resolved_ip,
                        note="SSRF Blocked: Destination IP is private or restricted"
                    ))
                    evidence.append(EvidenceItem(
                        name="ssrf_target_blocked",
                        category="redirect",
                        description=f"Redirect attempted navigation to private or cloud metadata IP ({resolved_ip}). Blocked for security.",
                        severity="critical",
                        source="redirect_resolver"
                    ))
                    return hops, evidence, "SSRF destination blocked"

                ext = self._tld_extractor(hostname)
                curr_reg_domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
                is_cross_domain = (curr_reg_domain != initial_reg_domain) and (hop_num > 1)

                try:
                    # Make HEAD or shallow GET to read headers only
                    resp = await client.head(current_url)
                    # If HEAD is disallowed (405 or 501), fallback to GET stream
                    if resp.status_code in (405, 501):
                        async with client.stream("GET", current_url) as stream_resp:
                            status_code = stream_resp.status_code
                            location = stream_resp.headers.get("location")
                    else:
                        status_code = resp.status_code
                        location = resp.headers.get("location")

                    hops.append(RedirectHop(
                        order=hop_num,
                        url=current_url,
                        domain=curr_reg_domain,
                        status_code=status_code,
                        is_cross_domain=is_cross_domain,
                        resolved_ip=resolved_ip
                    ))

                    # Check for redirect status codes (301, 302, 303, 307, 308)
                    if status_code in (301, 302, 303, 307, 308) and location:
                        next_url = urljoin(current_url, location)
                        current_url = next_url
                        continue
                    else:
                        # Reached terminal destination
                        break

                except httpx.TimeoutException:
                    hops.append(RedirectHop(
                        order=hop_num,
                        url=current_url,
                        domain=curr_reg_domain,
                        resolved_ip=resolved_ip,
                        note="Network request timed out during redirect inspection"
                    ))
                    return hops, evidence, "Redirect check timed out"
                except Exception as e:
                    hops.append(RedirectHop(
                        order=hop_num,
                        url=current_url,
                        domain=curr_reg_domain,
                        resolved_ip=resolved_ip,
                        note=f"Inspection aborted: {str(e)}"
                    ))
                    return hops, evidence, f"Redirect resolution stopped: {str(e)}"

        # Analyze aggregate hops for risks
        if len(hops) > 1:
            final_hop = hops[-1]
            if final_hop.is_cross_domain:
                evidence.append(EvidenceItem(
                    name="cross_domain_redirect",
                    category="redirect",
                    description=f"Redirect chain routed from initial domain '{initial_reg_domain}' to differing domain '{final_hop.domain}'.",
                    severity="medium",
                    source="redirect_resolver"
                ))

            if len(hops) >= 4:
                evidence.append(EvidenceItem(
                    name="excessive_redirect_chain",
                    category="redirect",
                    description=f"Observed {len(hops)} intermediate redirect hops, a tactic frequently used to bypass scanners.",
                    severity="medium",
                    source="redirect_resolver"
                ))

        return hops, evidence, None
