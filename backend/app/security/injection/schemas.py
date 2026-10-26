from datetime import datetime, timezone
from typing import Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from app.security.schemas import Risk

Action = Literal["ALLOW", "FLAG", "REDACT", "BLOCK"]
Category = Literal["INSTRUCTION_OVERRIDE", "AUTHORITY_SPOOFING", "ROLE_SPOOFING",
                   "DATA_EXFILTRATION", "TOOL_MANIPULATION", "SECURITY_BYPASS",
                   "HIDDEN_INSTRUCTIONS", "OBFUSCATED_PAYLOAD", "CONTEXT_MANIPULATION"]
Source = Literal["read_document", "search_database", "manual_test", "tool_history", "external_content"]


class Indicator(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    rule_id: str
    category: Category
    severity: Risk
    description: str
    view: str
    start: int
    end: int
    evidence_hash: str
    match_strength: float = Field(ge=0, le=1)
    recommended_action: Action
    weight: int = Field(ge=0, le=100)
    educational_quote: bool = False


class ScanResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scan_id: UUID = Field(default_factory=uuid4)
    session_id: UUID
    source_tool: Source
    source_identifier: str
    detected: bool = False
    classification: Literal["SAFE", "SUSPICIOUS", "PROMPT_INJECTION", "SCAN_ERROR"] = "SAFE"
    risk_score: int = Field(default=0, ge=0, le=100)
    risk_level: Risk = "LOW"
    confidence: float = Field(default=0, ge=0, le=1)
    confidence_description: str = "Heuristic match strength, not a calibrated probability."
    action: Action = "ALLOW"
    categories: list[Category] = Field(default_factory=list)
    indicators: list[Indicator] = Field(default_factory=list)
    normalization_steps: list[str] = Field(default_factory=list)
    content_hash: str
    content_length: int
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    firewall_decision_id: UUID | None = None
    tool_execution_id: UUID | None = None
    detector_version: str = "1"
    explanation: str = "No supported instruction-control pattern matched."
    classifier_status: str = "disabled"


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    content: str = Field(min_length=1, max_length=16000)
    source: Literal["manual_test"] = "manual_test"
