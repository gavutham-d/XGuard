"""
Scan and history API endpoints for XGuard.
"""

import json
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.schemas.scan import ScanRequest, ScanResponse, EvidenceItem, RedirectHop, IntelligenceMatch
from app.services.scan_service import scan_service
from app.database.session import get_db
from app.database.models import ScanRecord, RedirectRecord

router = APIRouter(prefix="/scan", tags=["Scan"])


@router.post("", response_model=ScanResponse)
async def scan_url(req: ScanRequest, db: Session = Depends(get_db)):
    """Evaluate target URL across ML, lexical, redirect, and intelligence layers."""
    try:
        response = await scan_service.execute_scan(req, db)
        return response
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan execution failed: {str(e)}")


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    """Retrieve historical scan assessment by ID."""
    rec = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
    if not rec:
        raise HTTPException(status_code=404, detail="Scan record not found")

    # Load redirect hops
    hops = db.query(RedirectRecord).filter(RedirectRecord.scan_id == scan_id).order_by(RedirectRecord.hop_order).all()
    redirect_hops = [
        RedirectHop(
            order=h.hop_order,
            url=h.url,
            domain=h.domain or "",
            status_code=h.status_code,
            is_cross_domain=h.is_cross_domain,
            resolved_ip=h.resolved_ip
        )
        for h in hops
    ]

    evidence_data = [EvidenceItem(**item) for item in json.loads(rec.evidence_json or "[]")]
    intel_data = [IntelligenceMatch(**item) for item in json.loads(rec.intelligence_json or "[]")]

    return ScanResponse(
        scan_id=rec.id,
        url=rec.url,
        hostname=rec.hostname or "",
        registered_domain=rec.registered_domain or "",
        risk_score=rec.risk_score,
        risk_level=rec.risk_level,
        predicted_category=rec.predicted_category,
        model_probability=rec.model_probability,
        model_version=rec.model_version,
        evidence=evidence_data,
        redirect_chain=redirect_hops,
        intelligence_matches=intel_data,
        checks_completed=json.loads(rec.checks_completed_json or "[]"),
        checks_failed=json.loads(rec.checks_failed_json or "[]"),
        recommended_action=rec.recommended_action,
        scan_timestamp=rec.timestamp.isoformat() if rec.timestamp else "",
        scan_duration_ms=rec.scan_duration_ms or 0.0,
        user_action=rec.user_action
    )


@router.post("/{scan_id}/override")
def record_override(scan_id: str, db: Session = Depends(get_db)):
    """Record an explicit user navigation override decision on a risky link."""
    rec = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
    if not rec:
        raise HTTPException(status_code=404, detail="Scan record not found")
    rec.user_action = "overridden"
    db.commit()
    return {"status": "success", "message": "Override logged for security audit"}


# History endpoints
history_router = APIRouter(prefix="/history", tags=["History"])


@history_router.get("")
def list_history(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    risk_level: Optional[str] = None,
    q: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Return paginated local scan history with search and filter capabilities."""
    query = db.query(ScanRecord)
    if risk_level:
        query = query.filter(ScanRecord.risk_level == risk_level.lower())
    if q:
        query = query.filter(ScanRecord.url.contains(q) | ScanRecord.registered_domain.contains(q))

    total = query.count()
    records = query.order_by(desc(ScanRecord.timestamp)).offset(skip).limit(limit).all()

    items = []
    for r in records:
        items.append({
            "scan_id": r.id,
            "timestamp": r.timestamp.isoformat() if r.timestamp else "",
            "url": r.url,
            "hostname": r.hostname,
            "registered_domain": r.registered_domain,
            "risk_score": r.risk_score,
            "risk_level": r.risk_level,
            "predicted_category": r.predicted_category,
            "model_version": r.model_version,
            "recommended_action": r.recommended_action,
            "user_action": r.user_action,
            "scan_duration_ms": r.scan_duration_ms
        })

    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "items": items
    }


@history_router.delete("")
def clear_history(scan_id: Optional[str] = None, db: Session = Depends(get_db)):
    """Delete a specific scan entry or clear entire history."""
    if scan_id:
        db.query(RedirectRecord).filter(RedirectRecord.scan_id == scan_id).delete()
        db.query(ScanRecord).filter(ScanRecord.id == scan_id).delete()
        db.commit()
        return {"status": "success", "message": f"Deleted scan {scan_id}"}
    else:
        db.query(RedirectRecord).delete()
        db.query(ScanRecord).delete()
        db.commit()
        return {"status": "success", "message": "All history cleared"}
