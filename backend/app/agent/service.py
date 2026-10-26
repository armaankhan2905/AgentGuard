"""Bounded agent loop. The gateway is its only path to tool execution."""

import json
from typing import Any

from sqlalchemy import update
from sqlalchemy.orm import Session

from app.agent.errors import AgentError
from app.agent.history import bound_context, load_context, save_message
from app.agent.provider import LLMProvider
from app.core.config import Settings
from app.core.redaction import SecretRedactor
from app.models import AgentSession
from app.schemas.agent import ChatRequest, ChatResponse, ToolExecutionResponse
from app.tools.gateway import ToolGateway
from app.security.summaries import history_arguments


class AgentService:
    def __init__(self, settings: Settings, provider: LLMProvider,
                 gateway: ToolGateway, redactor: SecretRedactor) -> None:
        self.settings = settings
        self.provider = provider
        self.gateway = gateway
        self.redactor = redactor

    def chat(self, db: Session, request: ChatRequest) -> ChatResponse:
        text = self.redactor.text(request.message)
        if request.session_id:
            session = db.get(AgentSession, request.session_id)
            if session is None:
                raise AgentError("session_not_found", "The requested session does not exist.", 404)
        else:
            session = AgentSession(name=text[:80])
            db.add(session)
            db.commit()
        session_id = session.id
        acquired = db.execute(update(AgentSession).where(
            AgentSession.id == session_id, AgentSession.status != "processing"
        ).values(status="processing")).rowcount
        db.commit()
        if acquired != 1:
            error = AgentError("session_busy", "This session is processing another message.", 409)
            error.session_id = session_id
            raise error
        executions: list[ToolExecutionResponse] = []
        try:
            save_message(db, session_id, "user", text)
            messages = load_context(db, session_id, self.settings)
            db.commit()  # Release the read transaction before waiting for the provider.
            definitions = self.gateway.definitions()
            seen_ids: set[str] = set()
            for iteration in range(self.settings.agent_max_tool_iterations + 1):
                messages = bound_context(messages, self.settings, definitions)
                allow_tools = iteration < self.settings.agent_max_tool_iterations
                reply = self.provider.complete(messages, definitions, allow_tools=allow_tools)
                if not reply.tool_calls:
                    final = self.redactor.text(reply.content or "")
                    break
                if not allow_tools:
                    final = "The tool execution limit was reached. No further tools were executed."
                    break
                if any(call.id in seen_ids for call in reply.tool_calls):
                    raise AgentError("invalid_ai_response", "The AI provider repeated a tool call identifier.")
                seen_ids.update(call.id for call in reply.tool_calls)
                calls = []
                for call in reply.tool_calls:
                    safe_call = self.redactor.clean(call.model_dump())
                    safe_call["function"]["arguments"] = history_arguments(
                        call.function.name, call.function.arguments, self.redactor)
                    calls.append(safe_call)
                content = self.redactor.text(reply.content or "")
                save_message(db, session_id, "assistant", content, tool_calls=calls)
                messages.append({"role": "assistant", "content": content, "tool_calls": calls})
                for call in reply.tool_calls:
                    safe_call_id = self.redactor.text(call.id)
                    execution = self.gateway.execute(
                        db, session_id, call.function.name, call.function.arguments
                    )
                    executions.append(ToolExecutionResponse.model_validate(execution))
                    result = json.dumps(execution.result, ensure_ascii=True)
                    save_message(db, session_id, "tool", result, tool_call_id=safe_call_id)
                    messages.append({"role": "tool", "content": result, "tool_call_id": safe_call_id})
            save_message(db, session_id, "assistant", final)
            return ChatResponse(session_id=session_id, response=final, tool_calls=executions)
        except AgentError as exc:
            exc.session_id = session_id
            # Retain completed tool effects and make the interrupted turn visible.
            save_message(db, session_id, "assistant", f"Request stopped: {exc.message}")
            raise
        finally:
            db.rollback()
            db.execute(update(AgentSession).where(AgentSession.id == session_id).values(status="active"))
            db.commit()
