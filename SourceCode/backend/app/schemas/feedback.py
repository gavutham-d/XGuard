"""
Pydantic schemas for user feedback and false positive / negative reports.
"""

from typing import Optional
from pydantic import BaseModel, Field


class FeedbackRequest(BaseModel):
    scan_id: Optional[str] = None
    url: str
    feedback_type: str = Field(..., description="false_positive | false_negative | general_comment")
    user_comment: Optional[str] = None
    user_consent: bool = Field(..., description="Explicit user consent to submit feedback")


class FeedbackResponse(BaseModel):
    feedback_id: str
    status: str
    message: str
    recorded_at: str
