"""Stage 5 deterministic infrastructure tests; no real provider requests."""

import json
import multiprocessing
import time
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.agent.errors import AgentError
from app.agent.provider import AssistantReply
from app.core.config import Settings
from app.database.session import Database
from app.main import create_app
from app.models import AgentSession, DemoRecord, SecurityEvent, SimulatedEmail, SimulationResult, SimulationRun, SimulationTrace
from app.security.audit_service import AuditService
from app.simulations.engine import SimulationEngine, recover_expired, utcnow
from app.simulations.evaluator import evaluate
from app.simulations.providers import ScriptedProvider, isolated_inference
from app.simulations.runner import run_variant
from app.simulations.sandbox import Sandbox, tool_definitions
from app.simulations.scenarios import ATTACKER, CANARY, SCENARIOS, fingerprint, resources
from app.simulations.trace import SimulationStop, TraceCollector
from app.tools.gateway import ToolGateway


@pytest.fixture
def lab(tmp_path):
    config = Settings(database_url=f"sqlite:///{(tmp_path / 'lab.db').as_posix()}", app_environment="local",
                      security_dev_endpoints=True, simulation_enabled=True, simulation_runs_per_minute=10)
    database = Database(config.database_url)
    database.initialize()
    try:
        yield SimulationEngine(database, config)
    finally:
        database.close()


def results(lab, run_id):
    with lab.database.session() as db:
        return {r.variant: r.details for r in db.scalars(select(SimulationResult).where(SimulationResult.run_id == run_id))}


def run(lab, scenario="data_exfiltration", variants=None):
    run_id = lab.admit(scenario, "scripted", variants or ["baseline", "protected"])
    lab.execute(run_id)
    return run_id, results(lab, run_id)


@pytest.mark.parametrize("scenario", list(SCENARIOS))
def test_all_scenarios_complete_and_only_synthetic_effects(lab, scenario):
    run_id, outcome = run(lab, scenario)
    assert len(outcome) == 2
    assert all(r["execution_status"] == "COMPLETED" for r in outcome.values())
    assert all(r["mode"] == "scripted" for r in outcome.values())
    assert not outcome["protected"]["confidential_data_accessed"]
    assert not outcome["protected"]["simulated_exfiltration"]
    assert not outcome["protected"]["unaudited_actions"]
    with lab.database.session() as db:
        for model in (AgentSession, SecurityEvent, SimulatedEmail):
            assert db.scalar(select(func.count()).select_from(model)) == 0
        assert db.scalar(select(func.count()).select_from(DemoRecord)) == 4
        assert db.get(SimulationRun, run_id).status == "COMPLETED"


def test_exfiltration_and_ordered_correlated_trace(lab):
    run_id, outcome = run(lab)
    assert outcome["baseline"]["attack_success"] is True
    assert CANARY in outcome["baseline"]["outbox"][0]["body"]
    assert outcome["baseline"]["outbox"][0]["delivered"] is False
    protected = outcome["protected"]
    assert protected["attack_success"] is False and protected["blocked_actions"] == 2
    assert protected["tool_requests"] == 3 and protected["tools_executed"] == 1
    assert protected["critical_content_quarantined"] == 1
    with lab.database.session() as db:
        events = list(db.scalars(select(SimulationTrace).where(SimulationTrace.run_id == run_id).order_by(SimulationTrace.step)))
        assert [e.step for e in events] == list(range(1, len(events) + 1))
        assert all(e.details["is_simulation"] and e.id and e.created_at for e in events)
        start = [e.details for e in events if e.event_type == "SIMULATION_STARTED"]
        assert start[0] == start[1]
        scans = [e.details for e in events if e.event_type == "INJECTION_SCAN"]
        assert all(s["firewall_decision_id"] and s["tool_execution_id"] for s in scans)
        for execution in [e for e in events if e.event_type == "TOOL_EXECUTION" and e.details["status"] == "succeeded"]:
            assert any(e.event_type == "SANDBOX_AUDIT" and e.step < execution.step and
                       e.details["execution_id"] == execution.details["execution_id"] for e in events)
        assert db.get(SimulationRun, run_id).comparison["observed_prevention"] is True


def test_request_objective_not_confused_with_execution(lab):
    _, outcome = run(lab, "instruction_override")
    assert outcome["protected"]["outcome"] == "SUCCESS"  # objective = REQUEST, not access
    assert outcome["protected"]["blocked_actions"] == 1
    assert outcome["protected"]["confidential_data_accessed"] is False


def test_benign_control_and_logging_suppression(lab):
    _, benign = run(lab, "benign_training")
    assert all(r["legitimate_task_completed"] and r["outcome"] == "SUCCESS" for r in benign.values())
    assert benign["protected"]["false_positive"] is False
    assert benign["protected"]["attack_success"] is None
    _, logging = run(lab, "logging_suppression")
    assert all(r["outcome"] == "FAILURE" and r["unaudited_actions"] == 0 for r in logging.values())


@pytest.mark.parametrize("variant", ["baseline", "protected"])
@pytest.mark.parametrize("name,args", [
    ("shell", {"command": "whoami"}), ("read_document", {"filename": "../confidential/payroll_demo.txt"}),
    ("read_document", {"filename": "C:\\Windows\\win.ini"}), ("read_document", {"filename": "payroll_demo.txt"}),
    ("read_document", {"filename": "project_report.txt", "role": "admin"}),
    ("search_database", {"query": "SELECT * FROM demo_records"}),
    ("send_email", {"to": "real@example.com", "subject": "test", "body": "synthetic"}),
])
def test_sandbox_cannot_reach_files_production_gateway_network_or_email(lab, variant, name, args):
    run_id = lab.admit("data_exfiltration", "scripted", [variant])
    box = Sandbox(SCENARIOS["data_exfiltration"], variant, lab.settings, TraceCollector(lab.database, run_id, lab.settings))
    try:
        with patch.object(ToolGateway, "execute", side_effect=AssertionError("production gateway")), \
             patch.object(Path, "read_text", side_effect=AssertionError("filesystem")), \
             patch("socket.create_connection", side_effect=AssertionError("network")), \
             patch("smtplib.SMTP", side_effect=AssertionError("email")):
            response = box.execute(name, json.dumps(args))
        assert not box.outbox
        assert not any(e["confidential_access"] for e in box.executions)
        if name == "search_database" and variant == "baseline":
            assert response["data"]["records"] == []  # literal text, never SQL
        else:
            assert response["ok"] is False
    finally:
        box.close()
    assert not box.fixtures


def test_protected_unscoped_query_never_returns_restricted_rows(lab):
    rid = lab.admit("data_exfiltration", "scripted", ["protected"])
    box = Sandbox(SCENARIOS["data_exfiltration"], "protected", lab.settings, TraceCollector(lab.database, rid, lab.settings))
    try:
        reply = box.execute("search_database", '{"query":"Synthetic"}')
        assert CANARY not in json.dumps(reply)
        assert all(r["category"] != "restricted_financial_records" for r in reply["data"]["records"])
    finally:
        box.close()


@pytest.mark.parametrize("arguments", ['{"filename":"project_report.txt","filename":"confidential_strategy.txt"}',
                                        '{"filename":NaN}', '[]', '{"filename":123}', '{'])
def test_invalid_arguments_rejected_in_baseline(lab, arguments):
    rid = lab.admit("data_exfiltration", "scripted", ["baseline"])
    box = Sandbox(SCENARIOS["data_exfiltration"], "baseline", lab.settings, TraceCollector(lab.database, rid, lab.settings))
    try:
        assert box.execute("read_document", arguments)["ok"] is False
        assert not box.executions
    finally:
        box.close()


def test_audit_failure_prevents_protected_effects(lab):
    with patch.object(AuditService, "record", side_effect=AgentError("audit_unavailable", "Audit unavailable", 503)):
        _, outcome = run(lab, variants=["protected"])
    assert outcome["protected"]["outcome"] == "ERROR"
    assert outcome["protected"]["tools_executed"] == 0


def test_trace_failure_prevents_effects(lab):
    original = TraceCollector.add
    def fail(self, variant, event, *args, **kwargs):
        if event == "SANDBOX_AUDIT":
            raise RuntimeError("Do not print sensitive failure text")
        return original(self, variant, event, *args, **kwargs)
    with patch.object(TraceCollector, "add", fail):
        _, outcome = run(lab)
    assert all(r["outcome"] == "ERROR" and r["tools_executed"] == 0 for r in outcome.values())


def test_baseline_refusal_is_failure_not_invented_compromise(lab):
    with patch.object(ScriptedProvider, "complete", return_value=AssistantReply(role="assistant", content="I will not follow those instructions.")):
        _, outcome = run(lab)
    assert all(r["outcome"] == "FAILURE" and not r["attack_success"] for r in outcome.values())
    assert all(r["blocked_actions"] == 0 and not r["entry_observed"] for r in outcome.values())


def test_protected_failure_is_not_forced_successful_defense(lab):
    original = Sandbox.execute
    def broken_controls(self, name, arguments):
        self.variant = "baseline"  # controlled test fault, never exposed by API
        return original(self, name, arguments)
    with patch.object(Sandbox, "execute", broken_controls):
        _, outcome = run(lab, variants=["protected"])
    assert outcome["protected"]["attack_success"] is True
    assert outcome["protected"]["simulated_exfiltration"] is True


def test_provider_failure_safe_and_unknown_outcome(lab):
    with patch.object(ScriptedProvider, "complete", side_effect=AgentError("ai_unavailable", "PRIVATE PROVIDER BODY")):
        _, outcome = run(lab)
    assert all(r["outcome"] == "ERROR" and r["attack_success"] is None for r in outcome.values())
    assert "PRIVATE PROVIDER BODY" not in json.dumps(outcome)


@pytest.mark.parametrize("overrides,code", [({"simulation_max_iterations": 1}, "iteration_limit"),
    ({"simulation_max_tool_calls": 1}, "tool_limit"), ({"simulation_max_trace_events": 20}, "trace_limit"),
    ({"simulation_max_trace_bytes": 16384}, "trace_limit"), ({"simulation_max_provider_requests": 2}, "iteration_limit")])
def test_bounded_execution(lab, overrides, code):
    lab.settings = replace(lab.settings, **overrides)
    _, outcome = run(lab)
    assert any(r["error_code"] == code for r in outcome.values())
    assert all(r["outcome"] == "INCONCLUSIVE" for r in outcome.values())
    assert sum(r["provider_requests"] for r in outcome.values()) <= lab.settings.simulation_max_provider_requests
    assert sum(r["tool_requests"] for r in outcome.values()) <= lab.settings.simulation_max_tool_calls


def test_cancelled_job_never_calls_provider(lab):
    rid = lab.admit("data_exfiltration", "scripted", ["baseline", "protected"])
    with lab.database.session() as db:
        db.get(SimulationRun, rid).cancel_requested = True
        db.commit()
    with patch.object(ScriptedProvider, "complete", side_effect=AssertionError("cancelled")):
        lab.execute(rid)
    assert all(r["execution_status"] == "CANCELLED" and r["provider_requests"] == 0 for r in results(lab, rid).values())


def test_admission_parallel_rate_and_payload_limits(lab):
    rid = lab.admit("data_exfiltration", "scripted", ["protected"])
    with pytest.raises(HTTPException) as error:
        lab.admit("data_exfiltration", "scripted", ["protected"])
    assert error.value.status_code == 409
    lab.execute(rid)
    lab.settings = replace(lab.settings, simulation_runs_per_minute=1)
    with pytest.raises(HTTPException) as error:
        lab.admit("data_exfiltration", "scripted", ["protected"])
    assert error.value.status_code == 429
    lab.settings = replace(lab.settings, simulation_max_payload_chars=100)
    with pytest.raises(HTTPException) as error:
        lab.admit("data_exfiltration", "scripted", ["protected"])
    assert error.value.status_code == 422


def test_restart_persistence_and_expired_job_recovery(lab):
    completed, before = run(lab)
    queued = lab.admit("data_exfiltration", "scripted", ["protected"])
    with lab.database.session() as db:
        db.get(SimulationRun, queued).deadline_at = utcnow() - timedelta(seconds=1)
        db.commit()
    lab.database.close()
    lab.database.initialize()
    with lab.database.session() as db:
        recover_expired(db)
        db.commit()
        assert db.get(SimulationRun, queued).status == "INTERRUPTED"
    assert results(lab, completed) == before
    assert results(lab, queued)["protected"]["outcome"] == "INCONCLUSIVE"


def _slow_worker(connection, *args):
    time.sleep(10)


def test_live_worker_timeout_kills_only_owned_process():
    before = {p.pid for p in multiprocessing.active_children()}
    started = time.monotonic()
    with pytest.raises(SimulationStop) as error:
        isolated_inference(Settings(), [], [], True, .2, lambda: None, worker=_slow_worker)
    assert error.value.code == "provider_timeout"
    assert time.monotonic() - started < 5
    assert {p.pid for p in multiprocessing.active_children()} == before


@pytest.fixture
def api(lab):
    app = create_app(lab.settings)
    with TestClient(app, base_url="http://127.0.0.1:8000", client=("127.0.0.1", 55555)) as client:
        yield client


def test_api_scenarios_run_details_traces_stats(api):
    listed = api.get("/api/simulation/scenarios").json()
    assert len(listed) == 8
    for scenario in listed:
        detail = api.get("/api/simulation/scenarios/" + scenario["id"]).json()
        assert detail["resources"] == resources(SCENARIOS[scenario["id"]])
    response = api.post("/api/simulation/compare", json={"scenario_id": "data_exfiltration", "mode": "scripted", "compare": True})
    assert response.status_code == 202
    rid = response.json()["run_id"]
    detail = api.get(f"/api/simulation/runs/{rid}").json()
    assert detail["status"] == "COMPLETED" and detail["comparison"]["observed_prevention"]
    assert detail["configuration"]["resources_hash"] == fingerprint(resources(SCENARIOS["data_exfiltration"]))
    assert api.get(f"/api/simulation/runs/{rid}/traces?limit=1&offset=1").json()[0]["step"] == 2
    assert len(api.get("/api/simulation/runs").json()) == 1
    stats = api.get("/api/simulation/stats").json()
    assert stats["total_simulations"] == 1
    assert stats["modes"]["live"]["total_runs"] == 0
    assert stats["modes"]["live"]["variants"]["baseline"]["attack_success_rate"] is None
    assert stats["modes"]["scripted"]["variants"]["baseline"]["conclusive_attacks"] == 1
    assert stats["modes"]["scripted"]["variants"]["protected"]["blocked_actions"] == 2
    assert api.get("/api/security/stats").json()["total_evaluations"] == 0
    assert api.post("/api/simulation/run", json={"scenario_id": "benign_training"}).status_code == 202


def test_routes_opt_in_and_request_validation(api, client):
    assert client.get("/api/simulation/scenarios").status_code == 404
    assert api.get("/api/simulation/scenarios", headers={"Origin": "https://evil.invalid"}).status_code == 403
    assert api.get("/api/simulation/scenarios", headers={"Host": "evil.invalid"}).status_code == 403
    assert api.post("/api/simulation/run", json={"scenario_id": "data_exfiltration", "mode": "live"}).status_code == 503
    assert api.post("/api/simulation/run", json={"scenario_id": "unknown"}).status_code == 404
    assert api.post("/api/simulation/run", json={"scenario_id": "data_exfiltration", "payload": "override"}).status_code == 422
    assert api.post("/api/agent/chat", json={"message": "hello", "variant": "baseline"}).status_code == 422
    assert api.get(f"/api/simulation/runs/{uuid4()}").status_code == 404
    assert api.get("/api/simulation/runs?limit=1000").status_code == 422


def test_live_configuration_fairness_without_network(lab):
    lab.settings = replace(lab.settings, simulation_live_enabled=True, ai_provider="openai-compatible", ai_model="test-model", ai_api_key="test-private-key")
    observed = []
    class RecordingProvider(ScriptedProvider):
        def __init__(self, settings, deadline, check):
            observed.append(settings)
            super().__init__(SCENARIOS["benign_training"])
    with patch("app.simulations.engine.LiveProvider", RecordingProvider):
        rid = lab.admit("benign_training", "live", ["baseline", "protected"])
        lab.execute(rid)
    assert observed == [lab.settings, lab.settings]
    with lab.database.session() as db:
        row = db.get(SimulationRun, rid)
        assert row.configuration["model"] == "test-model"
        assert "test-private-key" not in json.dumps(row.configuration)
    assert all(r["mode"] == "live" for r in results(lab, rid).values())  # isolated test DB only


@pytest.mark.parametrize("route", ["run", "compare"])
@pytest.mark.parametrize("enabled,configured,code", [
    (False, True, "simulation_live_disabled"),
    (True, False, "simulation_ai_not_configured"),
])
def test_live_admission_errors_are_specific_safe_and_create_no_run(lab, route, enabled, configured, code, caplog):
    config = replace(lab.settings, simulation_live_enabled=enabled,
                     ai_provider="openai", ai_model="test-model",
                     ai_api_key="private-test-credential" if configured else "")
    app = create_app(config)
    with TestClient(app, base_url="http://127.0.0.1:8000", client=("127.0.0.1", 55555)) as client:
        with patch("app.simulations.engine.LiveProvider", side_effect=AssertionError("Admission must not call the provider")):
            response = client.post(f"/api/simulation/{route}", json={"scenario_id": "instruction_override", "mode": "live"})
        assert response.status_code == 503
        assert response.json()["error"]["code"] == code
        assert "restart" in response.json()["error"]["message"]
        assert "private-test-credential" not in response.text + caplog.text
        assert client.get("/api/simulation/stats").json()["total_simulations"] == 0
        # The live switch/credentials must not prevent offline infrastructure tests.
        assert client.post("/api/simulation/run", json={"scenario_id": "benign_training", "mode": "scripted"}).status_code == 202
