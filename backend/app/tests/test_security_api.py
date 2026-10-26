import json
from dataclasses import replace
from unittest.mock import patch
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.core.config import Settings
from app.main import create_app
from app.models import SecurityEvent, SimulatedEmail, ToolExecution
from app.tools.gateway import ToolGateway


@pytest.fixture
def local_settings(tmp_path):
    return Settings(database_url=f"sqlite:///{(tmp_path / 'security.db').as_posix()}",
                    app_environment="local", security_dev_endpoints=True)


@pytest.fixture
def local_app(local_settings):
    return create_app(local_settings)


@pytest.fixture
def local_client(local_app):
    with TestClient(local_app, base_url="http://127.0.0.1:8000", client=("127.0.0.1", 50000)) as client:
        yield client


@pytest.mark.parametrize("environment,enabled", [("production", False), ("production", True),
                                                ("local", False), ("test", True)])
def test_security_routes_absent_without_explicit_local_opt_in(local_settings, environment, enabled):
    app = create_app(replace(local_settings, app_environment=environment, security_dev_endpoints=enabled))
    with TestClient(app) as client:
        assert client.get("/api/security/stats").status_code == 404
        assert client.post("/api/security/evaluate", json={}).status_code == 404
        assert not any(p.startswith("/api/security") for p in client.get("/openapi.json").json()["paths"])


@pytest.mark.parametrize("peer,url,headers", [
    ("203.0.113.5", "http://127.0.0.1:8000", {}),
    ("203.0.113.5", "http://127.0.0.1:8000", {"X-Forwarded-For": "127.0.0.1"}),
    ("127.0.0.1", "http://attacker.example", {}),
    ("127.0.0.1", "http://127.0.0.1:8000", {"Origin": "https://attacker.example"}),
    ("127.0.0.1", "http://127.0.0.1:8000", {"Origin": "null"}),
])
def test_remote_or_cross_origin_requests_rejected(local_app, peer, url, headers):
    with TestClient(local_app, base_url=url, client=(peer, 50000)) as client:
        assert client.get("/api/security/events", headers=headers).status_code == 403
        assert client.post("/api/security/evaluate", headers=headers, json={
            "tool_name": "read_document", "arguments": {"filename": "project_report.txt"}
        }).status_code == 403


def test_evaluate_never_executes_and_monitoring_reads_real_records(local_app, local_client):
    client = local_client
    assert client.get("/api/security/stats").json()["total_evaluations"] == 0
    with patch.object(ToolGateway, "execute", side_effect=AssertionError("Evaluation must never execute")):
        allowed = client.post("/api/security/evaluate", json={
            "tool_name": "read_document", "arguments": {"filename": "project_report.txt"}
        })
        assert allowed.status_code == 200
        first = allowed.json()
        denied = client.post("/api/security/evaluate", json={
            "session_id": first["session_id"], "tool_name": "read_document",
            "arguments": {"filename": "confidential_strategy.txt"}
        }).json()
        critical = client.post("/api/security/evaluate", json={
            "tool_name": "send_email", "arguments": {
                "to": "attacker@unknown-domain.com", "subject": "Demo", "body": "Update"
            }
        }).json()
    assert first["decision"] == "ALLOW"
    assert denied["decision"] == "DENY"
    assert critical["risk_level"] == "CRITICAL"
    assert first["metadata"]["source"] == "development_test"
    assert client.get("/api/security/stats").json() == {
        "total_evaluations": 3, "allowed_actions": 1, "blocked_actions": 2,
        "high_risk_events": 1, "critical_risk_events": 1,
    }
    assert len(client.get("/api/security/events", params={"decision": "DENY"}).json()) == 2
    assert len(client.get("/api/security/events", params={"risk_level": "CRITICAL"}).json()) == 1
    assert len(client.get("/api/security/events", params={"tool": "read_document"}).json()) == 2
    assert len(client.get("/api/security/events", params={"session_id": first["session_id"]}).json()) == 2
    ascending = client.get("/api/security/events", params={"sort": "asc"}).json()
    descending = client.get("/api/security/events", params={"sort": "desc"}).json()
    assert ascending == list(reversed(descending))
    assert client.get("/api/security/events", params={"sort": "asc", "limit": 1, "offset": 1}).json() == [ascending[1]]
    assert client.get("/api/security/events/" + first["decision_id"]).json() == first
    assert client.get("/api/security/events/" + str(uuid4())).status_code == 404
    with local_app.state.database.session() as db:
        assert db.scalar(select(func.count()).select_from(ToolExecution)) == 0
        assert db.scalar(select(func.count()).select_from(SimulatedEmail)) == 0


def test_no_privileged_context_and_bounded_filters(local_client):
    for extra in ({"role": "admin"}, {"context": {"is_admin": True}}):
        assert local_client.post("/api/security/evaluate", json={
            "tool_name": "read_document", "arguments": {"filename": "project_report.txt"}, **extra
        }).status_code == 422
    for params in ({"limit": 101}, {"offset": -1}, {"risk_level": "superuser"}, {"sort": "random"}):
        assert local_client.get("/api/security/events", params=params).status_code == 422
    assert local_client.post("/api/security/evaluate", json={
        "session_id": str(uuid4()), "tool_name": "read_document", "arguments": {}
    }).status_code == 404


def test_policies_endpoint_read_only(local_client):
    response = local_client.get("/api/security/policies")
    assert response.status_code == 200
    assert response.json()["valid"] is True
    assert response.json()["default_decision"] == "DENY"
    assert "ALLOW_PUBLIC_DOCUMENTS" in response.text
    assert local_client.post("/api/security/policies", json={"allow_all": True}).status_code == 405


def test_persisted_audits_survive_restart_and_legacy_events_untouched(local_settings):
    app = create_app(local_settings)
    with TestClient(app, base_url="http://localhost", client=("127.0.0.1", 50000)) as client:
        first = client.post("/api/security/evaluate", json={
            "tool_name": "read_document", "arguments": {"filename": "project_report.txt"}
        }).json()
        from uuid import UUID
        with app.state.database.session() as db:
            db.add(SecurityEvent(session_id=UUID(first["session_id"]), event_type="legacy_event",
                                 details={"preserve": True}))
            db.commit()
    restarted = create_app(local_settings)
    with TestClient(restarted, base_url="http://localhost", client=("127.0.0.1", 50000)) as client:
        assert client.get("/api/security/events/" + first["decision_id"]).json() == first
        assert client.get("/api/security/stats").json()["total_evaluations"] == 1
        with restarted.state.database.session() as db:
            assert db.scalar(select(func.count()).select_from(SecurityEvent)) == 2


def test_custom_invalid_policy_path_is_used_by_both_chat_and_evaluation(local_settings, tmp_path):
    settings = replace(local_settings, security_policy_file=str(tmp_path / "missing.json"))
    from app.tests.test_agent import text_reply, tool_reply, use_provider
    app = create_app(settings)
    use_provider(app, tool_reply("read_document", {"filename": "project_report.txt"}), text_reply("Denied."))
    with TestClient(app, base_url="http://localhost", client=("127.0.0.1", 50000)) as client:
        assert client.get("/api/security/policies").json()["valid"] is False
        evaluated = client.post("/api/security/evaluate", json={
            "tool_name": "read_document", "arguments": {"filename": "project_report.txt"}
        }).json()
        assert evaluated["policy_id"] == "INVALID_POLICY_CONFIGURATION"
        chat = client.post("/api/agent/chat", json={"message": "Read the report"})
        assert chat.status_code == 200
        assert chat.json()["tool_calls"][0]["status"] == "rejected"
