"""
Scan orchestration service for XGuard.
Runs all detection layers asynchronously, coordinates safe storage,
and formats responses strictly to the specification.
"""

import json
import time
import uuid
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy.orm import Session

from app.schemas.scan import ScanRequest, ScanResponse
from app.detection.lexical import LexicalAnalyzer
from app.detection.brands import BrandDetector
from app.detection.redirects import SafeRedirectResolver
from app.detection.intelligence import ThreatIntelligenceEngine
from app.detection.page_analyzer import PageSignalsAnalyzer
from app.detection.fusion import RiskFusionEngine
from app.models.adapter import ml_adapter
from app.database.models import ScanRecord, RedirectRecord
from app.core.security import sanitize_and_redact_url, validate_url_scheme
from app.core.logging import logger


class ScanService:
    def __init__(self):
        self.lexical_analyzer = LexicalAnalyzer()
        self.brand_detector = BrandDetector()
        self.redirect_resolver = SafeRedirectResolver()
        self.intel_engine = ThreatIntelligenceEngine()
        self.page_analyzer = PageSignalsAnalyzer()
        self.fusion_engine = RiskFusionEngine()

    async def execute_scan(self, req: ScanRequest, db: Optional[Session] = None) -> ScanResponse:
        start_time = time.perf_counter()
        scan_id = str(uuid.uuid4())
        raw_url = req.url.strip()
        options = req.options

        # Validate scheme
        if not validate_url_scheme(raw_url):
            raw_url = "http://" + raw_url

        display_url = sanitize_and_redact_url(raw_url)

        # 1. Layer A: Lexical Analysis
        lexical_ev, metadata, lexical_points = self.lexical_analyzer.analyze(raw_url)

        # 2. Brand Analysis
        brand_ev, brand_points = self.brand_detector.analyze(metadata)

        # 3. Layer B: Machine Learning
        ml_pred, ml_prob, ml_meta = ml_adapter.predict(raw_url)

        # 4. Layer C: Threat Intelligence
        privacy_mode = options.mode == "learning" # or explicitly flagged
        intel_matches, intel_ev = await self.intel_engine.query_feeds(raw_url, metadata, privacy_mode=False)

        # 5. Layer D: Safe Redirects (only if requested)
        redirect_hops = []
        redirect_ev = []
        if options.resolve_redirects:
            redirect_hops, redirect_ev, _ = await self.redirect_resolver.trace_redirects(raw_url)

        # 6. Layer E: Live Page Signals
        page_ev, page_points = self.page_analyzer.analyze(options.page_signals, metadata)

        # 7. Risk Fusion
        fusion = self.fusion_engine.fuse(
            url=raw_url,
            metadata=metadata,
            lexical_evidence=lexical_ev,
            lexical_points=lexical_points,
            brand_evidence=brand_ev,
            brand_points=brand_points,
            ml_prediction=ml_pred,
            ml_probability=ml_prob,
            ml_meta=ml_meta,
            intelligence_matches=intel_matches,
            intel_evidence=intel_ev,
            redirect_hops=redirect_hops,
            redirect_evidence=redirect_ev,
            page_evidence=page_ev,
            page_points=page_points,
            mode=options.mode
        )

        duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
        now_iso = datetime.now(timezone.utc).isoformat()

        response = ScanResponse(
            scan_id=scan_id,
            url=display_url,
            hostname=metadata["hostname"],
            registered_domain=metadata["registered_domain"],
            risk_score=fusion["risk_score"],
            risk_level=fusion["risk_level"],
            predicted_category=fusion["predicted_category"],
            model_probability=ml_prob if ml_meta.get("status") == "success" else None,
            model_version=ml_meta.get("model_version"),
            evidence=fusion["evidence"],
            redirect_chain=redirect_hops,
            intelligence_matches=intel_matches,
            checks_completed=fusion["checks_completed"],
            checks_failed=fusion["checks_failed"],
            recommended_action=fusion["recommended_action"],
            scan_timestamp=now_iso,
            scan_duration_ms=duration_ms,
            user_action="pending"
        )

        # Save to database if session provided
        if db:
            try:
                db_record = ScanRecord(
                    id=scan_id,
                    url=display_url,
                    hostname=metadata["hostname"],
                    registered_domain=metadata["registered_domain"],
                    risk_score=fusion["risk_score"],
                    risk_level=fusion["risk_level"],
                    predicted_category=fusion["predicted_category"],
                    model_probability=ml_prob if ml_meta.get("status") == "success" else None,
                    model_version=ml_meta.get("model_version"),
                    evidence_json=json.dumps([e.model_dump() for e in fusion["evidence"]]),
                    intelligence_json=json.dumps([m.model_dump() for m in intel_matches]),
                    checks_completed_json=json.dumps(fusion["checks_completed"]),
                    checks_failed_json=json.dumps(fusion["checks_failed"]),
                    recommended_action=fusion["recommended_action"],
                    scan_duration_ms=duration_ms,
                    user_action="pending"
                )
                db.add(db_record)

                for hop in redirect_hops:
                    r_rec = RedirectRecord(
                        scan_id=scan_id,
                        hop_order=hop.order,
                        url=hop.url,
                        domain=hop.domain,
                        status_code=hop.status_code,
                        is_cross_domain=hop.is_cross_domain,
                        resolved_ip=hop.resolved_ip
                    )
                    db.add(r_rec)

                db.commit()
            except Exception as e:
                logger.error(f"Failed to persist scan record {scan_id}: {e}")
                db.rollback()

        return response


scan_service = ScanService()
