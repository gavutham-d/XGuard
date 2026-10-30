"""
User Feedback and False Positive Reporting API endpoints for XGuard.
"""

import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.schemas.feedback import FeedbackRequest, FeedbackResponse
from app.database.session import get_db
from app.database.models import FeedbackRecord

router = APIRouter(prefix="/feedback", tags=["Feedback"])


@router.post("", response_model=FeedbackResponse)
def submit_feedback(req: FeedbackRequest, db: Session = Depends(get_db)):
    """Submit a verified false positive or missed threat report with user consent."""
    if not req.user_consent:
        raise HTTPException(
            status_code=400,
            detail="Explicit user consent is strictly required to submit telemetry feedback."
        )

    feedback_id = str(uuid.uuid4())
    now_iso = datetime.now(timezone.utc).isoformat()

    rec = FeedbackRecord(
        id=feedback_id,
        scan_id=req.scan_id,
        url=req.url,
        feedback_type=req.feedback_type,
        user_comment=req.user_comment,
        consent_status=req.user_consent
    )
    db.add(rec)
    db.commit()

    return FeedbackResponse(
        feedback_id=feedback_id,
        status="success",
        message="Feedback logged successfully. Thank you for contributing to threat intelligence accuracy.",
        recorded_at=now_iso
    )
