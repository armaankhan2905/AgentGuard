import json

import httpx
import pytest

from app.agent.errors import AgentError
from app.agent.provider import OpenAICompatibleProvider
from app.core.config import Settings
from app.tools.gateway import ToolGateway


def settings(**changes: object) -> Settings:
    return Settings(**{  # type: ignore[arg-type]
        "ai_provider": "openai", "ai_model": "test-tool-calling-model",
        "ai_api_key": "private-provider-key", **changes,
    })


def completion(message: object, finish_reason: str = "stop") -> dict:
    return {"choices": [{"message": message, "finish_reason": finish_reason}]}


def test_adapter_sends_model_credentials_and_structured_tools() -> None:
    received: list[httpx.Request] = []

    def handle(request: httpx.Request) -> httpx.Response:
        received.append(request)
        return httpx.Response(200, json=completion({
            "role": "assistant", "content": None, "tool_calls": [{
                "id": "call_one", "type": "function", "function": {
                    "name": "read_document", "arguments": '{"filename":"project_report.txt"}'
                }
            }]
        }, "tool_calls"))

    provider = OpenAICompatibleProvider(settings(), httpx.MockTransport(handle))
    reply = provider.complete([{"role": "user", "content": "Read the report"}], ToolGateway.definitions())
    assert reply.tool_calls[0].function.name == "read_document"
    assert len(received) == 1
    request = received[0]
    assert str(request.url) == "https://api.openai.com/v1/chat/completions"
    assert request.headers["authorization"] == "Bearer private-provider-key"
    body = json.loads(request.content)
    assert body["model"] == "test-tool-calling-model"
    assert {tool["function"]["name"] for tool in body["tools"]} == {
        "read_document", "search_database", "send_email"
    }
    assert body["parallel_tool_calls"] is False
    assert "private-provider-key" not in request.content.decode()
    assert request.extensions["timeout"]["read"] == 30


@pytest.mark.parametrize(("status_code", "public_status", "public_code"), [
    (301, 502, "ai_invalid_request"), (401, 503, "ai_authentication_failed"),
    (429, 429, "ai_rate_limited"), (500, 502, "ai_provider_error"),
    (503, 502, "ai_provider_error"),
])
def test_provider_http_failures_do_not_expose_body(status_code: int, public_status: int, public_code: str) -> None:
    calls: list[str] = []

    def handle(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(status_code, text="private-provider-key private-error-payload",
                              headers={"Location": "https://untrusted.example/steal"})

    provider = OpenAICompatibleProvider(settings(), httpx.MockTransport(handle))
    with pytest.raises(AgentError) as error:
        provider.complete([], [])
    assert error.value.status_code == public_status
    assert error.value.code == public_code
    assert "private" not in str(error.value)
    assert len(calls) == 1  # No retries or credential-carrying redirects.


@pytest.mark.parametrize(("exception", "status", "code"), [
    (httpx.ReadTimeout, 504, "ai_timeout"),
    (httpx.ConnectError, 502, "ai_network_error"),
])
def test_timeout_and_network_failures_are_sanitized(exception: type, status: int, code: str) -> None:
    def handle(request: httpx.Request) -> httpx.Response:
        raise exception("private-provider-key", request=request)

    with pytest.raises(AgentError) as error:
        OpenAICompatibleProvider(settings(), httpx.MockTransport(handle)).complete([], [])
    assert error.value.status_code == status
    assert error.value.code == code
    assert "private-provider-key" not in str(error.value)


@pytest.mark.parametrize("body", [
    {}, {"choices": []}, {"choices": "invalid"},
    completion("not-a-message"), completion({"role": "user", "content": "invalid role"}),
    completion({"role": "assistant", "content": "truncated"}, "length"),
    completion({"role": "assistant", "content": None}),
    completion({"role": "assistant", "tool_calls": [{
        "id": "call", "type": "function", "function": {"name": "read_document", "arguments": {}}
    }]}),
    completion({"role": "assistant", "tool_calls": [{
        "id": "same_id", "type": "function", "function": {"name": "read_document", "arguments": "{}"}
    }] * 2}),
    completion({"role": "assistant", "tool_calls": [{
        "id": f"call_{i}", "type": "function", "function": {"name": "read_document", "arguments": "{}"}
    } for i in range(5)]}),
])
def test_malformed_or_unbounded_provider_output_is_rejected(body: object) -> None:
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json=body))
    with pytest.raises(AgentError) as error:
        OpenAICompatibleProvider(settings(), transport).complete([], [])
    assert error.value.code == "invalid_ai_response"


@pytest.mark.parametrize("changes", [
    {"ai_api_key": ""}, {"ai_provider": "unsupported"},
    {"ai_provider": "openai-compatible", "ai_base_url": ""},
    {"ai_base_url": "http://remote.example/v1"},
    {"ai_base_url": "https://user:secret@remote.example/v1"},
    {"ai_base_url": "https://remote.example/v1?key=private"},
    {"ai_base_url": "https://[invalid"},
])
def test_bad_configuration_fails_before_network(changes: dict) -> None:
    def forbidden_network(request: httpx.Request) -> httpx.Response:
        pytest.fail("Invalid configuration must not send a request.")

    with pytest.raises(AgentError) as error:
        OpenAICompatibleProvider(settings(**changes), httpx.MockTransport(forbidden_network)).complete([], [])
    assert error.value.status_code == 503


def test_compatible_local_endpoint_and_disabled_tools() -> None:
    def handle(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == "http://127.0.0.1:9123/v1/chat/completions"
        assert json.loads(request.content)["tool_choice"] == "none"
        return httpx.Response(200, json=completion({"role": "assistant", "content": "Finished.", "tool_calls": None}))

    provider = OpenAICompatibleProvider(settings(ai_provider="openai-compatible", ai_base_url="http://127.0.0.1:9123/v1"),
                                         httpx.MockTransport(handle))
    assert provider.complete([], ToolGateway.definitions(), allow_tools=False).content == "Finished."
