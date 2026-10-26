from typing import Annotated, Any
from pathlib import Path
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.agent.errors import AgentError
from app.agent.provider import LLMProvider, OpenAICompatibleProvider
from app.agent.service import AgentService
from app.core.redaction import SecretRedactor
from app.core.config import BACKEND_DIR
from app.database.session import get_db
from app.models import AgentSession, ChatMessage, SimulatedEmail, ToolExecution
from app.schemas.agent import ChatRequest, ChatResponse, SessionDetail, SessionSummary
from app.tools.gateway import ToolGateway

router = APIRouter(prefix="/api/agent", tags=["agent"])
DatabaseSession = Annotated[Session, Depends(get_db)]


def get_provider(request: Request) -> LLMProvider:
    return OpenAICompatibleProvider(request.app.state.settings)


def get_gateway(request: Request) -> ToolGateway:
    settings = request.app.state.settings
    policy_path = Path(settings.security_policy_file)
    if not policy_path.is_absolute():
        policy_path = BACKEND_DIR / policy_path
    return ToolGateway(SecretRedactor(settings), policy_path=policy_path, settings=settings)


@router.post("/chat", response_model=ChatResponse)
def chat(request: Request, payload: ChatRequest, db: DatabaseSession,
         provider: Annotated[LLMProvider, Depends(get_provider)],
         gateway: Annotated[ToolGateway, Depends(get_gateway)]) -> ChatResponse:
    settings = request.app.state.settings
    return AgentService(settings, provider, gateway, SecretRedactor(settings)).chat(db, payload)


@router.get("/sessions", response_model=list[SessionSummary])
def list_sessions(request: Request, db: DatabaseSession,
                  limit: Annotated[int, Query(ge=1, le=100)] = 50,
                  offset: Annotated[int, Query(ge=0)] = 0) -> list[dict[str, Any]]:
    sessions = db.scalars(select(AgentSession).order_by(
        AgentSession.created_at.desc(), AgentSession.id.desc()).offset(offset).limit(limit)).all()
    redactor = SecretRedactor(request.app.state.settings)
    return [redactor.clean(SessionSummary.model_validate(row).model_dump()) for row in sessions]


@router.get("/sessions/{session_id}", response_model=SessionDetail)
def session_detail(request: Request, session_id: UUID, db: DatabaseSession,
                   limit: Annotated[int, Query(ge=1, le=500)] = 100,
                   offset: Annotated[int, Query(ge=0)] = 0) -> dict[str, Any]:
    session = db.get(AgentSession, session_id)
    if session is None:
        raise AgentError("session_not_found", "The requested session does not exist.", 404)
    messages = db.scalars(select(ChatMessage).where(ChatMessage.session_id == session_id)
                          .order_by(ChatMessage.created_at, ChatMessage.id)
                          .offset(offset).limit(limit)).all()
    executions = db.scalars(select(ToolExecution).where(ToolExecution.session_id == session_id)
                            .order_by(ToolExecution.created_at, ToolExecution.id)
                            .offset(offset).limit(limit)).all()
    emails = db.scalars(select(SimulatedEmail).where(SimulatedEmail.session_id == session_id)
                        .order_by(SimulatedEmail.created_at, SimulatedEmail.id)
                        .offset(offset).limit(limit)).all()
    result = SessionDetail(**SessionSummary.model_validate(session).model_dump(),
                           messages=messages, tool_executions=executions, simulated_emails=emails)
    return SecretRedactor(request.app.state.settings).clean(result.model_dump())
