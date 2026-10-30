"""
AI Chatbot API endpoints for XGuard.
"""

from fastapi import APIRouter, HTTPException
from app.schemas.chat import ChatRequest, ChatResponse
from app.services.chatbot_service import chatbot_service

router = APIRouter(prefix="/chat", tags=["AI Chatbot"])


@router.post("", response_model=ChatResponse)
async def chat_with_assistant(req: ChatRequest):
    """Ask XGuard Assistant about active scan evidence, security concepts, and threats."""
    try:
        response = await chatbot_service.answer_question(req)
        return response
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Assistant chat error: {str(e)}")
