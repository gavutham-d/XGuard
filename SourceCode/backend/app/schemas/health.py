"""
Pydantic schemas for health and model status endpoints.
"""

from typing import Dict, Any, Optional
from pydantic import BaseModel


class HealthResponse(BaseModel):
    status: str
    version: str
    database_connected: bool
    ml_model_loaded: bool
    threat_intel_available: bool
    active_mode: str
    environment: str


class ModelInfoResponse(BaseModel):
    model_name: str
    model_version: str
    features_count: int
    top_features: Dict[str, float]
    calibration_method: str
    val_metrics: Dict[str, Any]
