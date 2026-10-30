"""
Multi-Layer Risk Fusion and Decision Engine for XGuard.
Combines Lexical (Layer A), Machine Learning (Layer B), Threat Intelligence (Layer C),
Redirects (Layer D), and Page Signals (Layer E) into a calibrated risk assessment.
"""

from typing import List, Dict, Any, Tuple
from app.schemas.scan import EvidenceItem, IntelligenceMatch, RedirectHop


class RiskFusionEngine:
    def fuse(
        self,
        url: str,
        metadata: Dict[str, Any],
        lexical_evidence: List[EvidenceItem],
        lexical_points: int,
        brand_evidence: List[EvidenceItem],
        brand_points: int,
        ml_prediction: int,
        ml_probability: float,
        ml_meta: Dict[str, Any],
        intelligence_matches: List[IntelligenceMatch],
        intel_evidence: List[EvidenceItem],
        redirect_hops: List[RedirectHop],
        redirect_evidence: List[EvidenceItem],
        page_evidence: List[EvidenceItem],
        page_points: int,
        mode: str = "balanced"
    ) -> Dict[str, Any]:
        """
        Synthesize multi-layered security signals into unified risk metrics.
        """
        all_evidence: List[EvidenceItem] = []
        checks_completed: List[str] = ["lexical_analysis", "brand_verification"]
        checks_failed: List[str] = []

        # Deduplicate and aggregate evidence items
        seen_evidence_names = set()
        for ev in (
            intel_evidence
            + brand_evidence
            + lexical_evidence
            + redirect_evidence
            + page_evidence
        ):
            if ev.name not in seen_evidence_names:
                all_evidence.append(ev)
                seen_evidence_names.add(ev.name)

        # 1. Threat Intelligence Evaluation (Layer C - Strongest verified signal)
        intel_confirmed = any(m.matched for m in intelligence_matches)
        if intel_confirmed:
            checks_completed.append("threat_intelligence_feeds")
        else:
            if any(m.error for m in intelligence_matches):
                checks_failed.append("threat_intelligence_network_lookup")
            else:
                checks_completed.append("threat_intelligence_feeds")

        # 2. ML Classification Evaluation (Layer B)
        if ml_meta.get("status") == "success":
            checks_completed.append("machine_learning_classifier")
            if ml_probability >= 0.65:
                all_evidence.append(EvidenceItem(
                    name="ml_high_confidence_phishing",
                    category="model",
                    description=f"ML URL classifier predicted high malicious likelihood ({ml_probability*100:.1f}% confidence, {ml_meta.get('model_name')}).",
                    severity="high",
                    source="ml_classifier"
                ))
            elif ml_probability >= 0.40:
                all_evidence.append(EvidenceItem(
                    name="ml_moderate_risk_cue",
                    category="model",
                    description=f"ML URL classifier detected elevated suspicious structure ({ml_probability*100:.1f}% probability).",
                    severity="medium",
                    source="ml_classifier"
                ))
        else:
            checks_failed.append("machine_learning_inference")

        # 3. Redirect Tracking (Layer D)
        if redirect_hops:
            checks_completed.append("redirect_analysis")
        else:
            checks_completed.append("redirect_analysis")

        # 4. Synthesize Numeric Risk Score (0 - 100)
        # Priority rules:
        # A. Confirmed intelligence match immediately sets critical score (90-98)
        if intel_confirmed:
            final_score = max(90, min(99, 90 + int(ml_probability * 10)))
            primary_category = "malware" if any("malware" in ev.name for ev in intel_evidence) else "phishing"
        else:
            # Weighted multi-signal fusion without double counting:
            # ML contributes 0 to 45 points
            ml_component = int(ml_probability * 45)

            # Heuristics: Brand impersonation is heavy (up to 40), lexical (up to 30), page (up to 25)
            heuristic_component = min(55, brand_points + int(lexical_points * 0.4) + page_points)

            # Redirect anomalies (SSRF, loops, excessive hops)
            redirect_component = 0
            if any(ev.name == "ssrf_target_blocked" for ev in redirect_evidence):
                redirect_component = 50
            elif any(ev.name == "redirect_loop_detected" for ev in redirect_evidence):
                redirect_component = 25
            elif any(ev.name == "cross_domain_redirect" for ev in redirect_evidence):
                redirect_component = 15

            raw_score = ml_component + heuristic_component + redirect_component
            final_score = max(0, min(99, raw_score))

            # Deduce primary threat category
            if any(ev.name == "dangerous_file_extension" for ev in all_evidence):
                primary_category = "malware"
            elif any("brand" in ev.name or "typosquatting" in ev.name for ev in all_evidence):
                primary_category = "brand_impersonation" if "spoof" in str(all_evidence) else "typosquatting"
            elif any(ev.name in ("credential_harvesting_tokens", "cross_domain_credential_submission", "ip_address_host") for ev in all_evidence):
                primary_category = "phishing"
            elif any("scam" in ev.name for ev in all_evidence):
                primary_category = "scam"
            elif any("redirect" in ev.name for ev in all_evidence):
                primary_category = "suspicious_redirect"
            elif final_score >= 60:
                primary_category = "phishing"
            elif final_score >= 25:
                primary_category = "suspicious"
            else:
                primary_category = "benign"

        # 5. Risk Level Bucketing
        if final_score >= 85:
            risk_level = "critical"
        elif final_score >= 60:
            risk_level = "high"
        elif final_score >= 25:
            risk_level = "medium"
        else:
            risk_level = "low"

        # 6. Apply Protection Mode Navigation Policy
        # Mode options: balanced, strict, learning
        if mode == "strict":
            if risk_level in ("critical", "high"):
                action = "block"
            elif risk_level == "medium" or checks_failed:
                action = "warn"
            else:
                action = "allow"
        elif mode == "learning":
            # In learning mode, always present informative banner without hard blocking
            action = "warn" if risk_level in ("critical", "high", "medium") else "allow"
        else:
            # Balanced mode (Default)
            if risk_level == "critical":
                action = "block"
            elif risk_level in ("high", "medium"):
                action = "warn"
            else:
                action = "allow"

        return {
            "risk_score": final_score,
            "risk_level": risk_level,
            "predicted_category": primary_category,
            "evidence": all_evidence,
            "checks_completed": checks_completed,
            "checks_failed": checks_failed,
            "recommended_action": action
        }
