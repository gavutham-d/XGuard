"""
Pydantic schemas for scanning requests and responses in XGuard.
Strictly adheres to the Master Specification result object contract.
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class EvidenceItem(BaseModel):
    name: str = Field(..., description="Short identifier for the observed signal")
    category: str = Field(..., description="Signal category: lexical, brand, redirect, intel, page, model")
    description: str = Field(..., description="Human-readable explanation of why this is suspicious")
    severity: str = Field(..., description="low, medium, high, critical, or info")
    source: str = Field(..., description="Component that produced this evidence")


class RedirectHop(BaseModel):
    order: int
    url: str
    domain: str
    status_code: Optional[int] = None
    is_cross_domain: bool = False
    resolved_ip: Optional[str] = None
    note: Optional[str] = None


class IntelligenceMatch(BaseModel):
    source: str = Field(..., description="Provider name (e.g. URLhaus, LocalFeed)")
    matched: bool = Field(..., description="True if threat match was found")
    threat_category: Optional[str] = None
    confidence: Optional[str] = None
    last_checked: str
    error: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


class PageSignalsInput(BaseModel):
    has_password_field: bool = False
    has_card_field: bool = False
    form_actions: List[str] = []
    has_cross_domain_form: bool = False
    iframe_count: int = 0
    page_title: Optional[str] = None
    link_text_mismatch: bool = False


class ScanOptions(BaseModel):
    mode: str = "balanced"  # balanced, strict, learning
    resolve_redirects: bool = True
    page_signals: Optional[PageSignalsInput] = None


class ScanRequest(BaseModel):
    url: str = Field(..., description="Destination URL to evaluate")
    options: Optional[ScanOptions] = Field(default_factory=ScanOptions)


class ScanResponse(BaseModel):
    scan_id: str
    url: str
    hostname: str
    registered_domain: str
    risk_score: int = Field(..., ge=0, le=100, description="Internal 0-100 risk score")
    risk_level: str = Field(..., description="low | medium | high | critical | unknown")
    predicted_category: str = Field(..., description="phishing | malware | scam | suspicious_redirect | unknown")
    model_probability: Optional[float] = None
    model_version: Optional[str] = None
    evidence: List[EvidenceItem] = []
    redirect_chain: List[RedirectHop] = []
    intelligence_matches: List[IntelligenceMatch] = []
    checks_completed: List[str] = []
    checks_failed: List[str] = []
    recommended_action: str = Field(..., description="allow | warn | block | retry")
    scan_timestamp: str
    scan_duration_ms: float
    user_action: Optional[str] = None
