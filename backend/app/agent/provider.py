"""Validated OpenAI-compatible Chat Completions adapter, with no tool execution."""

import logging
from typing import Any, Literal, Protocol
from urllib.parse import urlsplit

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from app.agent.errors import AgentError
from app.agent.provider_errors import (
    FailureKind, ProviderDiagnostic, ProviderError, classify_http_failure,
)
from app.core.config import Settings

logger = logging.getLogger("agentguard.provider")


def _report_failure(error: ProviderError) -> ProviderError:
    logger.warning("AI provider request failed.", extra={"provider_diagnostic": error.diagnostic})
    return error


class FunctionCall(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    name: str = Field(min_length=1, max_length=64, pattern=r"^[a-zA-Z0-9_-]+$")
    arguments: str = Field(max_length=12000)


class ToolCall(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    id: str = Field(min_length=1, max_length=128, pattern=r"^[a-zA-Z0-9_-]+$")
    type: Literal["function"]
    function: FunctionCall


class AssistantReply(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)
    role: Literal["assistant"]
    content: str | None = Field(default=None, max_length=8000)
    tool_calls: list[ToolCall] = Field(default_factory=list, max_length=4)

    @model_validator(mode="after")
    def validate_reply(self) -> "AssistantReply":
        if not self.tool_calls and not (self.content and self.content.strip()):
            raise ValueError("A reply must contain text or structured tool calls.")
        if len({call.id for call in self.tool_calls}) != len(self.tool_calls):
            raise ValueError("Tool call IDs must be unique.")
        return self


class LLMProvider(Protocol):
    def complete(
        self, messages: list[dict[str, Any]], tools: list[dict[str, Any]],
        *, allow_tools: bool = True,
    ) -> AssistantReply: ...


class OpenAICompatibleProvider:
    def __init__(self, settings: Settings, transport: httpx.BaseTransport | None = None) -> None:
        self.settings = settings
        self.transport = transport

    def complete(
        self, messages: list[dict[str, Any]], tools: list[dict[str, Any]],
        *, allow_tools: bool = True,
    ) -> AssistantReply:
        config = self.settings
        if not config.ai_configured:
            raise AgentError("ai_not_configured", "Configure AI_PROVIDER, AI_MODEL, and AI_API_KEY.", 503)
        if config.ai_provider not in {"openai", "openai-compatible"}:
            raise AgentError("unsupported_provider", "The configured AI provider is not supported.", 503)
        base_url = config.ai_base_url or (
            "https://api.openai.com/v1" if config.ai_provider == "openai" else ""
        )
        try:
            parsed = urlsplit(base_url)
        except ValueError:
            raise AgentError("invalid_provider_url", "Configure a valid AI_BASE_URL.", 503) from None
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname
                or parsed.username or parsed.password or parsed.query or parsed.fragment
                or (parsed.scheme == "http" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"})):
            raise AgentError("invalid_provider_url", "Configure a valid HTTPS AI_BASE_URL (HTTP is allowed for loopback only).", 503)
        payload: dict[str, Any] = {
            "model": config.ai_model, "messages": messages, "stream": False,
            "max_completion_tokens": 2000,
        }
        if tools:
            payload.update(tools=tools, tool_choice="auto" if allow_tools else "none",
                           parallel_tool_calls=False)
        try:
            # Redirects and environment proxy inheritance are disabled so the key is
            # sent only to the explicitly configured endpoint. No automatic retries.
            with httpx.Client(timeout=config.ai_timeout_seconds, follow_redirects=False,
                              trust_env=False, transport=self.transport) as client:
                response = client.post(
                    base_url.rstrip("/") + "/chat/completions", json=payload,
                    headers={"Authorization": f"Bearer {config.ai_api_key}"},
                )
            response.raise_for_status()
        except httpx.TimeoutException:
            raise _report_failure(ProviderError(ProviderDiagnostic(FailureKind.TIMEOUT))) from None
        except httpx.HTTPStatusError as exc:
            raise _report_failure(classify_http_failure(exc.response)) from None
        except httpx.RequestError:
            raise _report_failure(ProviderError(ProviderDiagnostic(FailureKind.NETWORK))) from None
        try:
            data = response.json()
            choice = data["choices"][0]
            if choice["finish_reason"] not in {"stop", "tool_calls"}:
                raise ValueError("Incomplete provider reply.")
            message = choice["message"]
            if message.get("tool_calls") is None:
                message = {**message, "tool_calls": []}
            return AssistantReply.model_validate(message)
        except (ValueError, TypeError, KeyError, IndexError, AttributeError, ValidationError):
            raise _report_failure(ProviderError(ProviderDiagnostic(
                FailureKind.INVALID_RESPONSE, response.status_code
            ))) from None
