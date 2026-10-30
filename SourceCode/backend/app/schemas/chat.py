"""
Pydantic schemas for the XGuard AI Assistant chatbot.
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class ChatMessage(BaseModel):
    role: str = Field(..., description="'user' or 'assistant' or 'system'")
    content: str


class ChatRequest(BaseModel):
    message: str = Field(..., description="User's cybersecurity question")
    scan_id: Optional[str] = None
    current_scan_context: Optional[Dict[str, Any]] = None
    conversation_history: List[ChatMessage] = []


class ChatResponse(BaseModel):
    answer: str
    grounded_evidence: List[str] = []
    suggested_followups: List[str] = []
    used_fallback: bool = False
    model_name: str
