"""Opt-in local development monitoring. Never an alternate tool execution path."""

import ipaddress
import json
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models import AgentSession, SecurityEvent
from app.routers.agent import get_gateway
from app.security.audit_service import EVENT_TYPE
from app.security.schemas import Effect, EvaluateRequest, FirewallDecision, Risk
from app.tools.gateway import ToolGateway


def require_local_development(request: Request) -> None:
    config = request.app.state.settings
    if config.app_environment != "local" or not config.security_dev_endpoints:
        raise HTTPException(404)
    try:
        local_peer = request.client is not None and ipaddress.ip_address(request.client.host).is_loopback
        local_host = request.url.hostname in {"127.0.0.1", "localhost", "::1"}
        origin = request.headers.get("origin")
        same_origin = origin is None or origin.rstrip("/") == str(request.base_url).rstrip("/")
        if not local_peer or not local_host or not same_origin:
            raise HTTPException(403)
    except ValueError:
        raise HTTPException(403) from None


router = APIRouter(prefix="/api/security", tags=["security (local development)"],
                   dependencies=[Depends(require_local_development)])
DatabaseSession = Annotated[Session, Depends(get_db)]
Gateway = Annotated[ToolGateway, Depends(get_gateway)]


def _events() -> Select[tuple[SecurityEvent]]:
    return select(SecurityEvent).where(SecurityEvent.event_type == EVENT_TYPE)


@router.get("/events", response_model=list[FirewallDecision])
def events(db: DatabaseSession, decision: Effect | None = None, risk_level: Risk | None = None,
           tool: Annotated[str | None, Query(max_length=64)] = None,
           session_id: UUID | None = None, sort: Literal["asc", "desc"] = "desc",
           limit: Annotated[int, Query(ge=1, le=100)] = 50,
           offset: Annotated[int, Query(ge=0)] = 0) -> list[dict]:
    statement = _events()
    for key, value in (("decision", decision), ("risk_level", risk_level), ("tool_name", tool)):
        if value is not None:
            statement = statement.where(SecurityEvent.details[key].as_string() == value)
    if session_id is not None:
        statement = statement.where(SecurityEvent.session_id == session_id)
    order = (SecurityEvent.created_at.asc(), SecurityEvent.id.asc()) if sort == "asc" else (
        SecurityEvent.created_at.desc(), SecurityEvent.id.desc())
    return [row.details for row in db.scalars(statement.order_by(*order).offset(offset).limit(limit))]


@router.get("/events/{event_id}", response_model=FirewallDecision)
def event_detail(event_id: UUID, db: DatabaseSession) -> dict:
    event = db.scalar(_events().where(SecurityEvent.id == event_id))
    if event is None:
        raise HTTPException(404)
    return event.details


@router.get("/stats")
def stats(db: DatabaseSession) -> dict[str, int]:
    groups = db.execute(select(SecurityEvent.details["decision"].as_string(),
                               SecurityEvent.severity, func.count()).where(
        SecurityEvent.event_type == EVENT_TYPE
    ).group_by(SecurityEvent.details["decision"].as_string(), SecurityEvent.severity)).all()
    return {
        "total_evaluations": sum(n for _, _, n in groups),
        "allowed_actions": sum(n for decision, _, n in groups if decision == "ALLOW"),
        "blocked_actions": sum(n for decision, _, n in groups if decision == "DENY"),
        "high_risk_events": sum(n for _, severity, n in groups if severity == "high"),
        "critical_risk_events": sum(n for _, severity, n in groups if severity == "critical"),
    }


@router.get("/policies")
def policies(gateway: Gateway) -> dict:
    config = gateway.firewall.policies
    return {"valid": config is not None, "default_decision": "DENY", "deny_overrides_allow": True,
            "rules": [rule.model_dump() for rule in config.rules] if config else [],
            "baseline_guards": ["strict_arguments", "public_document_catalog", "filesystem_confinement",
                                "approved_database_categories", "no_sql_operations", "email_recipient_allowlist",
                                "email_content_restrictions", "simulation_only", "durable_audit_required"]}


@router.post("/evaluate", response_model=FirewallDecision)
def evaluate(payload: EvaluateRequest, db: DatabaseSession, gateway: Gateway) -> FirewallDecision:
    # No roles, permission claims or caller context are accepted; no gateway.execute.
    if payload.session_id is None:
        session = AgentSession(name="Local firewall evaluation", status="active")
        db.add(session)
        db.commit()
    else:
        session = db.get(AgentSession, payload.session_id)
        if session is None:
            raise HTTPException(404)
    result = gateway.firewall.evaluate(session.id, payload.tool_name, json.dumps(payload.arguments),
                                       source="development_test")
    gateway.audit.record(db, result.decision)
    return result.decision
