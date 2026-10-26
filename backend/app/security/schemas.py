"""Fixed, serializable firewall decisions; no caller-supplied identity or roles."""

from datetime import datetime, timezone
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

Risk = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
Effect = Literal["ALLOW", "DENY"]


class FirewallDecision(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    decision_id: UUID = Field(default_factory=uuid4)
    session_id: UUID
    tool_name: str
    decision: Effect
    risk_level: Risk
    policy_id: str
    reason: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    arguments_summary: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)


class EvaluateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    session_id: UUID | None = None
    tool_name: str = Field(min_length=1, max_length=64)
    arguments: dict[str, Any]
