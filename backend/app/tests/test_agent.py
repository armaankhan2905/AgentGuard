import copy
import json
from pathlib import Path
from typing import Any
from unittest.mock import patch
from uuid import uuid4

import pytest
import httpx
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.agent.errors import AgentError
from app.agent.provider import AssistantReply, OpenAICompatibleProvider
from app.core.config import Settings
from app.main import create_app
from app.models import AgentSession, ChatMessage, SimulatedEmail, ToolExecution
from app.routers.agent import get_provider
from app.tools.gateway import ToolGateway


def tool_reply(name: str, arguments: Any, call_id: str = "call_1") -> AssistantReply:
    return AssistantReply.model_validate({"role": "assistant", "tool_calls": [{
        "id": call_id, "type": "function", "function": {
            "name": name, "arguments": arguments if isinstance(arguments, str) else json.dumps(arguments)
        }
    }]})


def text_reply(content: str) -> AssistantReply:
    return AssistantReply(role="assistant", content=content)


class SequenceProvider:
    def __init__(self, *replies: AssistantReply | AgentError) -> None:
        self.replies = list(replies)
        self.requests: list[list[dict[str, Any]]] = []
        self.allow_tools: list[bool] = []

    def complete(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]],
                 *, allow_tools: bool = True) -> AssistantReply:
        self.requests.append(copy.deepcopy(messages))
        self.allow_tools.append(allow_tools)
        result = self.replies.pop(0)
        if isinstance(result, AgentError):
            raise result
        return result


def use_provider(application: FastAPI, *replies: AssistantReply | AgentError) -> SequenceProvider:
    provider = SequenceProvider(*replies)
    application.dependency_overrides[get_provider] = lambda: provider
    return provider


def test_normal_conversation_and_sessions(application: FastAPI, client: TestClient) -> None:
    use_provider(application, text_reply("Hello! I can help with the fictional demo."))
    response = client.post("/api/agent/chat", json={"message": "Hello"})
    assert response.status_code == 200
    data = response.json()
    assert data["tool_calls"] == []
    detail = client.get(f"/api/agent/sessions/{data['session_id']}").json()
    assert [message["role"] for message in detail["messages"]] == ["user", "assistant"]
    assert detail["status"] == "active"
    assert client.get("/api/agent/sessions").json()[0]["id"] == data["session_id"]


def test_document_summary_uses_gateway_and_returns_tool_results(
    application: FastAPI, client: TestClient
) -> None:
    provider = use_provider(application, tool_reply("read_document", {"filename": "project_report.txt"}),
                            text_reply("Aurora is 80 percent complete; documentation review remains."))
    original_execute = ToolGateway.execute
    with patch.object(ToolGateway, "execute", autospec=True, side_effect=original_execute) as gateway:
        response = client.post("/api/agent/chat", json={"message": "Summarize project_report.txt"})
    assert response.status_code == 200
    assert gateway.call_count == 1
    execution = response.json()["tool_calls"][0]
    assert execution["status"] == "succeeded"
    assert "80 percent" in execution["result"]["data"]["content"]
    assert provider.requests[1][-1]["role"] == "tool"
    assert provider.requests[1][-1]["tool_call_id"] == "call_1"
    detail = client.get(f"/api/agent/sessions/{response.json()['session_id']}").json()
    assert [message["role"] for message in detail["messages"]] == ["user", "assistant", "tool", "assistant"]
    assert detail["tool_executions"][0]["id"] == execution["id"]


def test_search_synthetic_database(application: FastAPI, client: TestClient) -> None:
    use_provider(application, tool_reply("search_database", {"query": "Aurora", "category": "project"}),
                 text_reply("The fictional Aurora project has a documentation review pending."))
    response = client.post("/api/agent/chat", json={"message": "Find the Aurora project"})
    data = response.json()["tool_calls"][0]["result"]["data"]
    assert response.status_code == 200
    assert data["synthetic"] is True
    assert [row["code"] for row in data["records"]] == ["PRJ-001"]


def test_email_is_persisted_and_never_delivered(application: FastAPI, client: TestClient) -> None:
    use_provider(application, tool_reply("send_email", {
        "to": "mira@example.test", "subject": "Demo update", "body": "Aurora is ready for review."
    }), text_reply("I saved a simulated email; nothing was delivered."))
    response = client.post("/api/agent/chat", json={"message": "Email the demo update to Mira"})
    assert response.status_code == 200
    data = response.json()
    assert data["tool_calls"][0]["result"]["data"]["delivered"] is False
    with application.state.database.session() as db:
        email = db.scalar(select(SimulatedEmail))
        assert email is not None
        assert email.status == "simulated"
        assert email.to == "mira@example.test"
        assert str(email.tool_execution_id) == data["tool_calls"][0]["id"]
    detail = client.get(f"/api/agent/sessions/{data['session_id']}").json()
    assert detail["simulated_emails"][0]["status"] == "simulated"


@pytest.mark.parametrize(("name", "arguments", "error"), [
    ("run_python", {"code": "print('never executed')"}, "unknown_tool"),
    ("read_document", {"filename": "../confidential/payroll_demo.txt"}, "restricted_document"),
    ("read_document", {"filename": "credentials_demo.txt"}, "restricted_document"),
    ("read_document", {"filename": "C:\\Windows\\win.ini"}, "restricted_document"),
    ("search_database", {"query": "Aurora", "sql": "DELETE FROM chat_messages"}, "invalid_arguments"),
    ("search_database", {"query": "Aurora", "limit": "5"}, "invalid_arguments"),
    ("send_email", {"to": "not-an-email", "subject": "Demo", "body": "Demo"}, "invalid_arguments"),
    ("read_document", "{broken-json}", "invalid_arguments"),
])
def test_rejected_model_calls_are_audited_and_returned_to_llm(
    application: FastAPI, client: TestClient, name: str, arguments: Any, error: str
) -> None:
    provider = use_provider(application, tool_reply(name, arguments), text_reply("That operation was rejected."))
    response = client.post("/api/agent/chat", json={"message": "Perform the demonstration operation"})
    assert response.status_code == 200
    execution = response.json()["tool_calls"][0]
    assert execution["status"] == "rejected"
    assert execution["result"]["error"]["code"] == error
    assert error in provider.requests[1][-1]["content"]


def test_multiturn_context_survives_application_restart(tmp_path: Path) -> None:
    settings = Settings(database_url=f"sqlite:///{(tmp_path / 'persistent.db').as_posix()}")
    app1 = create_app(settings)
    use_provider(app1, text_reply("Your fictional project is Aurora."))
    with TestClient(app1) as client:
        first = client.post("/api/agent/chat", json={"message": "My project is Aurora"}).json()
    app2 = create_app(settings)
    provider = use_provider(app2, text_reply("You said Aurora."))
    with TestClient(app2) as client:
        second = client.post("/api/agent/chat", json={
            "session_id": first["session_id"], "message": "What is my project?"
        })
        assert second.status_code == 200
        assert second.json()["session_id"] == first["session_id"]
        assert [message["content"] for message in provider.requests[0][1:]] == [
            "My project is Aurora", "Your fictional project is Aurora.", "What is my project?"
        ]
        assert len(client.get(f"/api/agent/sessions/{first['session_id']}").json()["messages"]) == 4


def test_provider_failure_retains_history_and_allows_recovery(application: FastAPI, client: TestClient) -> None:
    use_provider(application, AgentError("ai_unavailable", "The AI provider request failed."))
    failure = client.post("/api/agent/chat", json={"message": "Hello"})
    assert failure.status_code == 502
    session_id = failure.json()["error"]["session_id"]
    detail = client.get(f"/api/agent/sessions/{session_id}").json()
    assert detail["status"] == "active"
    assert detail["messages"][0]["content"] == "Hello"
    use_provider(application, text_reply("The provider has recovered."))
    assert client.post("/api/agent/chat", json={"session_id": session_id, "message": "Try again"}).status_code == 200


def test_completed_email_survives_followup_llm_failure(application: FastAPI, client: TestClient) -> None:
    use_provider(application, tool_reply("send_email", {
        "to": "mira@example.test", "subject": "Demo", "body": "Only one simulation."
    }), AgentError("ai_timeout", "The AI provider timed out.", 504))
    failure = client.post("/api/agent/chat", json={"message": "Simulate an email"})
    assert failure.status_code == 504
    with application.state.database.session() as db:
        assert db.scalar(select(func.count()).select_from(SimulatedEmail)) == 1
        assert db.scalar(select(ToolExecution.status)) == "succeeded"


def test_iteration_limit_stops_additional_execution(application: FastAPI, client: TestClient) -> None:
    maximum = application.state.settings.agent_max_tool_iterations
    provider = use_provider(application, *(tool_reply("search_database", {"query": "Aurora"}, f"call_{i}")
                                           for i in range(maximum + 1)))
    response = client.post("/api/agent/chat", json={"message": "Keep searching"})
    assert response.status_code == 200
    assert len(response.json()["tool_calls"]) == maximum
    assert "limit" in response.json()["response"]
    assert provider.allow_tools == [True] * maximum + [False]


def test_repeated_call_id_does_not_duplicate_effect(application: FastAPI, client: TestClient) -> None:
    call = tool_reply("send_email", {"to": "mira@example.test", "subject": "Demo", "body": "Once"})
    use_provider(application, call, call)
    response = client.post("/api/agent/chat", json={"message": "Simulate an email"})
    assert response.status_code == 502
    with application.state.database.session() as db:
        assert db.scalar(select(func.count()).select_from(SimulatedEmail)) == 1


def test_missing_configuration_and_unknown_sessions(client: TestClient) -> None:
    assert client.post("/api/agent/chat", json={"message": "Hello"}).status_code == 503
    assert client.get(f"/api/agent/sessions/{uuid4()}").status_code == 404
    assert client.post("/api/agent/chat", json={"message": "Hello", "session_id": str(uuid4())}).status_code == 404
    assert client.post("/api/agent/chat", json={"message": "   "}).status_code == 422
    assert client.post("/api/agent/chat", json={"message": "x" * 4001}).status_code == 422
    assert client.post("/api/agent/chat", json={"message": 42}).status_code == 422


def test_processing_session_rejects_concurrent_turn(application: FastAPI, client: TestClient) -> None:
    with application.state.database.session() as db:
        session = AgentSession(status="processing")
        db.add(session)
        db.commit()
        session_id = str(session.id)
    response = client.post("/api/agent/chat", json={"session_id": session_id, "message": "Hello"})
    assert response.status_code == 409
    with application.state.database.session() as db:
        assert db.scalar(select(func.count()).select_from(ChatMessage)) == 0


def test_agent_post_cors(client: TestClient) -> None:
    response = client.options("/api/agent/chat", headers={
        "Origin": "http://localhost:5173", "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "content-type",
    })
    assert response.status_code == 200


def test_actual_adapter_and_agent_complete_structured_tool_roundtrip(application: FastAPI, client: TestClient) -> None:
    requests: list[dict[str, Any]] = []

    def handle(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        requests.append(body)
        if len(requests) == 1:
            return httpx.Response(200, json={"choices": [{"finish_reason": "tool_calls", "message":
                tool_reply("read_document", {"filename": "project_report.txt"}).model_dump()}]})
        assert body["messages"][-1]["role"] == "tool"
        assert "80 percent" in body["messages"][-1]["content"]
        return httpx.Response(200, json={"choices": [{"finish_reason": "stop", "message": {
            "role": "assistant", "content": "Aurora is 80 percent complete."
        }}]})

    provider = OpenAICompatibleProvider(Settings(ai_provider="openai", ai_model="test-model", ai_api_key="mock-key"),
                                         httpx.MockTransport(handle))
    application.dependency_overrides[get_provider] = lambda: provider
    response = client.post("/api/agent/chat", json={"message": "Summarize the report"})
    assert response.status_code == 200
    assert len(requests) == 2
    assert response.json()["tool_calls"][0]["status"] == "succeeded"


def test_credentials_are_redacted_from_output_history_and_tool_arguments(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    key = "private-chat-key"
    app = create_app(Settings(database_url=f"sqlite:///{(tmp_path / 'redaction.db').as_posix()}", ai_api_key=key))
    escaped_key = "".join(f"\\u{ord(char):04x}" for char in key)
    use_provider(app, tool_reply("send_email",
        '{"to":"mira@example.test","subject":"Demo","body":"' + escaped_key + '"}'),
        text_reply(f"Simulated email. Key echo: {key}"))
    with TestClient(app) as client:
        response = client.post("/api/agent/chat", json={"message": f"Simulate an email: {key}"})
        assert response.status_code == 200
        assert key not in response.text
        session_id = response.json()["session_id"]
        detail = client.get(f"/api/agent/sessions/{session_id}")
        assert key not in detail.text
        assert detail.json()["simulated_emails"][0]["body"] == "[REDACTED]"
        assistant_call = detail.json()["messages"][1]["tool_calls"][0]
        assert json.loads(assistant_call["function"]["arguments"])["body"] == "[REDACTED]"
        with app.state.database.session() as db:
            assert all(key not in row.content for row in db.scalars(select(ChatMessage)))
    output = capsys.readouterr()
    assert key not in output.err + output.out


def test_multiturn_restores_complete_tool_protocol(application: FastAPI, client: TestClient) -> None:
    provider = use_provider(application, tool_reply("read_document", {"filename": "meeting_notes.txt"}),
                            text_reply("Mira reviews documentation."), text_reply("Mira is responsible."))
    first = client.post("/api/agent/chat", json={"message": "Who reviews documentation?"}).json()
    second = client.post("/api/agent/chat", json={"session_id": first["session_id"], "message": "Remind me who?"})
    assert second.status_code == 200
    context = provider.requests[2]
    assert [message["role"] for message in context] == ["system", "user", "assistant", "tool", "assistant", "user"]
    assert context[2]["tool_calls"][0]["id"] == context[3]["tool_call_id"]


def test_plain_text_code_is_never_executed(application: FastAPI, client: TestClient) -> None:
    use_provider(application, text_reply("Suggested code: print('displayed only')"))
    with patch.object(ToolGateway, "execute", side_effect=AssertionError("No structured tool call")):
        response = client.post("/api/agent/chat", json={"message": "Show a Python example"})
    assert response.status_code == 200
    assert response.json()["tool_calls"] == []
