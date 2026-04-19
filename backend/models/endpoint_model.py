from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ── Input field descriptor ─────────────────────────────────────────────────────

class InputField(BaseModel):
    name: str = Field(..., description="Field name used as key in request body")
    label: str = Field(..., description="Human-readable label")
    type: str = Field(default="string", description="Data type: string, number, array, boolean")
    required: bool = Field(default=True)
    description: Optional[str] = None


# ── Endpoint config (stored & returned) ───────────────────────────────────────

class EndpointConfig(BaseModel):
    endpoint_name: str
    username: str
    input_fields: List[InputField]
    output_schema: Dict[str, Any] = Field(
        ...,
        description="A JSON Schema object describing the expected AI output structure.",
    )
    ai_prompt: str
    description: Optional[str] = None
    gemini_api_key: str = Field(..., description="Gemini API key for this user")
    created_at: datetime = Field(default_factory=datetime.utcnow)


class EndpointConfigCreate(BaseModel):
    endpoint_name: str
    username: str
    input_fields: List[InputField]
    output_schema: Dict[str, Any] = Field(
        ...,
        description="JSON Schema object for the desired AI output.",
    )
    ai_prompt: str
    description: Optional[str] = None
    gemini_api_key: Optional[str] = Field(
        default=None,
        description=(
            "Gemini API key. If omitted, the key previously stored for this username is used."
        ),
    )


class EndpointConfigUpdate(BaseModel):
    """All fields are optional — only provided fields are updated."""
    input_fields: Optional[List[InputField]] = None
    output_schema: Optional[Dict[str, Any]] = None
    ai_prompt: Optional[str] = None
    description: Optional[str] = None
    gemini_api_key: Optional[str] = None


# ── Request / Response ─────────────────────────────────────────────────────────

class DynamicRequest(BaseModel):
    inputs: Dict[str, Any] = Field(
        ..., description="Key-value pairs matching the endpoint's input_fields"
    )


class DynamicResponse(BaseModel):
    endpoint: str
    username: str
    result: Dict[str, Any]
    success: bool = True


# ── List item (no secrets exposed) ────────────────────────────────────────────

class EndpointListItem(BaseModel):
    endpoint_name: str
    username: str
    description: Optional[str]
    input_fields: List[str]
    output_schema: Dict[str, Any]
    created_at: datetime


# ── User management ────────────────────────────────────────────────────────────

class UserRegisterPayload(BaseModel):
    username: str
    password: str = Field(..., min_length=8, description="Minimum 8 characters")
    gemini_api_key: Optional[str] = None


class UserLoginPayload(BaseModel):
    username: str
    password: str


class UserLoginResponse(BaseModel):
    username: str
    token: str
    message: str = "Login successful"


class UserApiKeyPayload(BaseModel):
    username: str
    password: str = Field(..., description="Required to authenticate the key update")
    gemini_api_key: str