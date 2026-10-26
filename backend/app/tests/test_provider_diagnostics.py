import json
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.agent.provider import OpenAICompatibleProvider
from app.agent.provider_errors import FailureKind, ProviderDiagnostic, ProviderError
from app.core.config import Settings
from app.core.logging import JsonFormatter, configure_logging
from app.models import ChatMessage, ToolExecution
from app.routers.agent import get_provider


@pytest.mark.parametrize(("status", "code", "error_type", "category", "public_code", "public_status"), [
    (401, "invalid_api_key", "invalid_request_error", "authentication", "ai_authentication_failed", 503),
    (429, "insufficient_quota", "insufficient_quota", "billing", "ai_billing_error", 503),
    (429, "credit_balance_exhausted", "insufficient_quota", "billing", "ai_billing_error", 503),
    (429, "organization_spend_limit_exceeded", "insufficient_quota", "billing", "ai_billing_error", 503),
    (429, "project_spend_limit_exceeded", "insufficient_quota", "billing", "ai_billing_error", 503),
    (429, "organization_usage_limit_exceeded", "insufficient_quota", "billing", "ai_billing_error", 503),
    (429, "unrecognized-code", "insufficient_quota", "billing", "ai_billing_error", 503),
    (402, None, None, "billing", "ai_billing_error", 503),
    (404, "model_not_found", "invalid_request_error", "model", "ai_model_unavailable", 503),
    (400, "unsupported_model", "invalid_request_error", "model", "ai_model_unavailable", 503),
    (403, "model_not_found", "invalid_request_error", "model", "ai_model_unavailable", 503),
    (403, "permission_denied", None, "permission", "ai_permission_denied", 503),
    (429, "rate_limit_exceeded", "rate_limit_error", "rate_limit", "ai_rate_limited", 429),
    (429, "slow_down", "rate_limit_error", "rate_limit", "ai_rate_limited", 429),
    (500, "server_error", None, "service", "ai_provider_error", 502),
    (503, "server_is_overloaded", "service_unavailable_error", "service", "ai_provider_error", 502),
    (504, None, None, "timeout", "ai_timeout", 504),
    (400, "unsupported_parameter", "invalid_request_error", "invalid_request", "ai_invalid_request", 502),
    (422, None, "invalid_request_error", "invalid_request", "ai_invalid_request", 502),
    (404, None, None, "invalid_request", "ai_invalid_request", 502),
])
def test_error_categories_are_safe_and_do_not_retry_or_switch_models(
    status: int, code: str | None, error_type: str | None, category: str,
    public_code: str, public_status: int, capsys: pytest.CaptureFixture[str],
) -> None:
    config = Settings(ai_provider="openai", ai_model="configured-model", ai_api_key="private-diagnostic-key")
    configure_logging(config)
    calls: list[dict[str, Any]] = []

    def handle(request: httpx.Request) -> httpx.Response:
        calls.append(json.loads(request.content))
        return httpx.Response(status, json={"error": {
            "code": code, "type": error_type,
            "message": "private-diagnostic-key sensitive-provider-details",
            "param": "sensitive-provider-details",
        }}, headers={"x-request-id": "sensitive-provider-details"})

    provider = OpenAICompatibleProvider(config, httpx.MockTransport(handle))
    with pytest.raises(ProviderError) as caught:
        provider.complete([{"role": "user", "content": "Hello"}], [])
    failure = caught.value
    assert failure.code == public_code
    assert failure.status_code == public_status
    assert failure.diagnostic.category.value == category
    assert failure.diagnostic.upstream_status == status
    assert len(calls) == 1
    assert calls[0]["model"] == "configured-model"
    output = capsys.readouterr()
    log = json.loads(output.err)
    assert log["provider_diagnostic"]["category"] == category
    assert log["provider_diagnostic"]["upstream_status"] == status
    if category == "billing":
        assert log["provider_diagnostic"]["retryable"] is False
    if code == "unrecognized-code":
        assert log["provider_diagnostic"]["provider_code"] is None
    for secret in ("private-diagnostic-key", "sensitive-provider-details"):
        assert secret not in output.err + output.out + repr(failure) + repr(failure.diagnostic)


def test_billing_error_is_safe_in_http_response_history_and_logs(
    application: FastAPI, client: TestClient, capsys: pytest.CaptureFixture[str]
) -> None:
    config = Settings(ai_provider="openai", ai_model="configured-model", ai_api_key="test-provider-key")
    configure_logging(config)
    provider = OpenAICompatibleProvider(config, httpx.MockTransport(lambda request: httpx.Response(
        429, json={"error": {"code": "credit_balance_exhausted", "type": "insufficient_quota",
                             "message": "sensitive-provider-details test-provider-key"}}
    )))
    application.dependency_overrides[get_provider] = lambda: provider
    response = client.post("/api/agent/chat", json={"message": "Hello"})
    assert response.status_code == 503
    error = response.json()["error"]
    assert error["code"] == "ai_billing_error"
    assert set(error) == {"code", "message", "session_id"}
    assert client.get(f"/api/agent/sessions/{error['session_id']}").json()["status"] == "active"
    with application.state.database.session() as db:
        assert db.scalar(select(func.count()).select_from(ToolExecution)) == 0
        stored = " ".join(db.scalars(select(ChatMessage.content)).all())
    output = capsys.readouterr()
    for secret in ("sensitive-provider-details", "test-provider-key"):
        assert secret not in response.text + stored + output.err + output.out
    assert "credit_balance_exhausted" not in response.text  # Internal subtype stays internal.


@pytest.mark.parametrize("body", [
    {"error": {"code": "private-key-in-code", "type": "private-key-in-type", "message": "raw-private-message"}},
    {"error": "raw-private-message"}, ["raw-private-message"], None,
])
def test_unknown_provider_fields_cannot_enter_diagnostics(body: Any, capsys: pytest.CaptureFixture[str]) -> None:
    config = Settings(ai_provider="openai", ai_model="configured-model", ai_api_key="test-provider-key")
    configure_logging(config)
    provider = OpenAICompatibleProvider(config, httpx.MockTransport(lambda request: httpx.Response(400, json=body)))
    with pytest.raises(ProviderError) as caught:
        provider.complete([], [])
    assert caught.value.code == "ai_invalid_request"
    assert caught.value.diagnostic.provider_code is None
    assert caught.value.diagnostic.provider_type is None
    output = capsys.readouterr()
    assert "private" not in output.err + output.out + repr(caught.value.diagnostic)


def test_only_typed_allowlisted_diagnostics_are_logged() -> None:
    import logging

    record = logging.LogRecord("agentguard.provider", logging.WARNING, __file__, 1,
                               "AI provider request failed.", (), None)
    record.provider_diagnostic = {"category": "raw-private-message"}
    assert "provider_diagnostic" not in json.loads(JsonFormatter().format(record))
    record.provider_diagnostic = ProviderDiagnostic(FailureKind.BILLING, 429,
                                                    "raw-private-message", "insufficient_quota")
    formatted = JsonFormatter(("insufficient_quota",)).format(record)
    assert "raw-private-message" not in formatted
    assert "insufficient_quota" not in formatted
    assert json.loads(formatted)["provider_diagnostic"]["provider_type"] == "[REDACTED]"
