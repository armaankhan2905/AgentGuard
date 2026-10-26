"""Local-only scan diagnostics and persisted detection monitoring."""

from dataclasses import asdict
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select

from app.models import AgentSession, SecurityEvent
from app.routers.security import DatabaseSession, Gateway, require_local_development
from app.security.injection.audit import EVENT_TYPE
from app.security.injection.rules import RULES
from app.security.injection.schemas import Action, ScanRequest, ScanResult, Source
from app.security.schemas import Risk

router = APIRouter(prefix="/api/security/injection", tags=["injection (local development)"],
                   dependencies=[Depends(require_local_development)])


@router.post("/scan", response_model=ScanResult)
def scan(payload: ScanRequest, db: DatabaseSession, gateway: Gateway) -> ScanResult:
    config = gateway.results.detector.config
    if config and len(payload.content) > config.max_chars:
        raise HTTPException(413)
    session = AgentSession(name="Local injection scan", status="active")
    db.add(session)
    db.commit()
    _, result = gateway.results.inspect(db, payload.content, "manual_test", session.id, identifier="manual_test")
    db.commit()
    return result


@router.get("/events", response_model=list[ScanResult])
def events(db: DatabaseSession, action: Action | None = None, risk_level: Risk | None = None,
           source: Source | None = None, session_id: UUID | None = None, detected: bool | None = None,
           sort: Literal["asc", "desc"] = "desc", limit: Annotated[int, Query(ge=1, le=100)] = 50,
           offset: Annotated[int, Query(ge=0)] = 0) -> list[dict]:
    statement = select(SecurityEvent).where(SecurityEvent.event_type == EVENT_TYPE)
    for key, value in (("action", action), ("risk_level", risk_level), ("source_tool", source)):
        if value is not None:
            statement = statement.where(SecurityEvent.details[key].as_string() == value)
    if session_id:
        statement = statement.where(SecurityEvent.session_id == session_id)
    if detected is not None:
        statement = statement.where(SecurityEvent.details["detected"].as_boolean() == detected)
    order = (SecurityEvent.created_at.asc(), SecurityEvent.id.asc()) if sort == "asc" else (
        SecurityEvent.created_at.desc(), SecurityEvent.id.desc())
    return [row.details for row in db.scalars(statement.order_by(*order).offset(offset).limit(limit))]


@router.get("/events/{scan_id}", response_model=ScanResult)
def event_detail(scan_id: UUID, db: DatabaseSession) -> dict:
    row = db.scalar(select(SecurityEvent).where(SecurityEvent.event_type == EVENT_TYPE, SecurityEvent.id == scan_id))
    if row is None:
        raise HTTPException(404)
    return row.details


@router.get("/stats")
def stats(db: DatabaseSession) -> dict:
    groups = db.execute(select(SecurityEvent.details["action"].as_string(),
        SecurityEvent.details["detected"].as_boolean(), func.count()).where(
        SecurityEvent.event_type == EVENT_TYPE).group_by(SecurityEvent.details["action"].as_string(),
                                                         SecurityEvent.details["detected"].as_boolean())).all()
    average = db.scalar(select(func.avg(SecurityEvent.details["risk_score"].as_integer())).where(
        SecurityEvent.event_type == EVENT_TYPE))
    return {"total_scans": sum(n for _, _, n in groups),
            "detected_threats": sum(n for _, detected, n in groups if detected),
            "blocked_threats": sum(n for action, detected, n in groups if detected and action == "BLOCK"),
            "flagged_threats": sum(n for action, detected, n in groups if detected and action == "FLAG"),
            "redacted_threats": sum(n for action, detected, n in groups if detected and action == "REDACT"),
            "average_risk_score": round(float(average or 0), 2)}


@router.get("/rules")
def rules(gateway: Gateway) -> dict:
    config = gateway.results.detector.config
    return {"detector_version": "1", "configuration_valid": config is not None,
            "configuration": config.model_dump() if config else None,
            "rules": [asdict(rule) for rule in RULES],
            "scoring": "Maximum weight per category; sum capped at 100; behavioral combination floors of 90.",
            "ai_classifier_enabled": gateway.results.detector.classifier.enabled,
            "confidence": "Heuristic match strength; not a calibrated probability."}
