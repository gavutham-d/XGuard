"""
Master API v1 router for XGuard.
"""

from fastapi import APIRouter
from app.api.v1.scan import router as scan_router, history_router
from app.api.v1.chat import router as chat_router
from app.api.v1.feedback import router as feedback_router
from app.api.v1.health import router as health_router
from app.api.v1.analytics import router as analytics_router

api_v1_router = APIRouter(prefix="/api/v1")

api_v1_router.include_router(scan_router)
api_v1_router.include_router(history_router)
api_v1_router.include_router(chat_router)
api_v1_router.include_router(feedback_router)
api_v1_router.include_router(health_router)
api_v1_router.include_router(analytics_router)
