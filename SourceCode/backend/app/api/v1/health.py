"""
Health and telemetry diagnostics API endpoints for XGuard.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text

from app.schemas.health import HealthResponse, ModelInfoResponse
from app.database.session import get_db
from app.models.adapter import ml_adapter
from app.core.config import settings

router = APIRouter(tags=["Health"])


@router.get("/health", response_model=HealthResponse)
def get_health(db: Session = Depends(get_db)):
    """System health check verifying database, model engine, and service dependencies."""
    db_ok = True
    try:
        db.execute(text("SELECT 1"))
    except Exception:
        db_ok = False

    return HealthResponse(
        status="operational" if (db_ok and ml_adapter.is_loaded) else "degraded",
        version=settings.APP_VERSION,
        database_connected=db_ok,
        ml_model_loaded=ml_adapter.is_loaded,
        threat_intel_available=settings.URLHAUS_API_ENABLED,
        active_mode=settings.DEFAULT_PROTECTION_MODE,
        environment="development" if settings.DEBUG else "production"
    )


@router.get("/model-info", response_model=ModelInfoResponse)
def get_model_info():
    """Retrieve active ML model metadata, calibration method, and empirical evaluation metrics."""
    info = ml_adapter.get_info()
    return ModelInfoResponse(
        model_name=info.get("model_name", "XGuard-Ensemble"),
        model_version=info.get("model_version", "1.0.0"),
        features_count=info.get("features_count", 28),
        top_features=info.get("top_features", {}),
        calibration_method=info.get("calibration_method", "Platt / Sigmoid 3-Fold"),
        val_metrics=info.get("val_metrics", {})
    )
