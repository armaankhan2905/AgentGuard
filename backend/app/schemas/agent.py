from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ChatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    session_id: UUID | None = None
    message: str = Field(min_length=1, max_length=4000)

    @field_validator("session_id", mode="before")
    @classmethod
    def parse_session_id(cls, value: Any) -> UUID | None:
        # JSON has no native UUID type; retain strict validation of the other fields.
        if isinstance(value, str):
            return UUID(value)
        return value

    @field_validator("message")
    @classmethod
    def trim_message(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Message cannot be blank.")
        return value.strip()


class ToolExecutionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    tool_name: str
    arguments: dict[str, Any]
    status: str
    result: dict[str, Any] | None
    created_at: datetime


class ChatResponse(BaseModel):
    session_id: UUID
    response: str
    tool_calls: list[ToolExecutionResponse]


class SessionSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    name: str | None
    status: str
    created_at: datetime


class MessageResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    role: str
    content: str
    tool_calls: list[dict[str, Any]] | None
    tool_call_id: str | None
    created_at: datetime


class EmailResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    to: str
    subject: str
    body: str
    status: str
    created_at: datetime


class SessionDetail(SessionSummary):
    messages: list[MessageResponse]
    tool_executions: list[ToolExecutionResponse]
    simulated_emails: list[EmailResponse]
