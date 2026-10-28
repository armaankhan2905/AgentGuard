"""Persisted admission lock, bounded background execution, and crash recovery."""

import logging
import time
from datetime import datetime, timedelta, timezone
from uuid import UUID

from fastapi import HTTPException
from sqlalchemy import func, select, text
from sqlalchemy.dialects.sqlite import insert

from app.agent.errors import AgentError
from app.agent.history import SYSTEM_PROMPT
from app.core.config import Settings
from app.core.redaction import SecretRedactor
from app.database.session import Database
from app.models import SimulationResult, SimulationRun, SimulationScenario
from app.simulations.evaluator import compare
from app.simulations.providers import LiveProvider, ScriptedProvider
from app.simulations.runner import run_variant
from app.simulations.sandbox import tool_definitions
from app.simulations.scenarios import SCENARIOS, fingerprint, resources
from app.simulations.trace import SimulationStop, TraceCollector

logger = logging.getLogger("agentguard.simulation")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def recover_expired(db) -> None:
    for row in db.scalars(select(SimulationRun).where(SimulationRun.status.in_(["QUEUED", "RUNNING"]),
                                                      SimulationRun.deadline_at < utcnow())):
        row.status, row.error_code, row.completed_at = "INTERRUPTED", "expired_execution_lease", utcnow()
        existing = set(db.scalars(select(SimulationResult.variant).where(SimulationResult.run_id == row.id)))
        for variant in row.configuration["variants"]:
            if variant not in existing:
                db.add(SimulationResult(run_id=row.id, variant=variant, outcome="INCONCLUSIVE", details={
                    "outcome": "INCONCLUSIVE", "attack_success": None, "execution_status": "INTERRUPTED",
                    "error_code": "expired_execution_lease", "is_simulation": True, "mode": row.mode}))


class SimulationEngine:
    def __init__(self, database: Database, settings: Settings) -> None:
        self.database, self.settings = database, settings

    def admit(self, scenario_id: str, mode: str, variants: list[str]) -> UUID:
        config = self.settings
        if mode not in {"live", "scripted"} or not variants or len(set(variants)) != len(variants) or any(v not in {"baseline", "protected"} for v in variants):
            raise HTTPException(422, "Invalid execution mode or variants.")
        if not config.simulation_enabled:
            raise HTTPException(404)
        if scenario_id not in SCENARIOS:
            raise HTTPException(404, "Unknown simulation scenario.")
        scenario = SCENARIOS[scenario_id]
        if len(scenario.payload) > config.simulation_max_payload_chars:
            raise HTTPException(422, "Scenario exceeds the configured payload limit.")
        if mode == "live" and not config.simulation_live_enabled:
            logger.warning("Live simulation admission rejected: simulation_live_disabled.")
            raise AgentError("simulation_live_disabled",
                "Live simulations are disabled. Set SIMULATION_LIVE_ENABLED=true in the local backend configuration and restart the backend.", 503)
        if mode == "live" and not config.ai_configured:
            logger.warning("Live simulation admission rejected: simulation_ai_not_configured.")
            raise AgentError("simulation_ai_not_configured",
                "Live simulations require AI_PROVIDER, AI_MODEL, and AI_API_KEY in the backend configuration. Configure them locally and restart the backend.", 503)
        now = utcnow()
        with self.database.session() as db:
            # Serialize admission across workers, not just inside one Python process.
            db.execute(text("BEGIN IMMEDIATE"))
            recover_expired(db)
            db.flush()
            if db.scalar(select(func.count()).select_from(SimulationRun).where(SimulationRun.status.in_(["QUEUED", "RUNNING"]))):
                raise HTTPException(409, "A simulation is already queued or running.")
            count = db.scalar(select(func.count()).select_from(SimulationRun).where(SimulationRun.created_at >= now - timedelta(minutes=1)))
            if count >= config.simulation_runs_per_minute:
                raise HTTPException(429, "Simulation rate limit reached. Try again after one minute.")
            definition = scenario.model_dump(mode="json")
            db.execute(insert(SimulationScenario).values(slug=scenario_id, definition=definition).on_conflict_do_nothing(index_elements=["slug"]))
            stored = db.scalar(select(SimulationScenario).where(SimulationScenario.slug == scenario_id))
            snapshot = {
                "scenario": definition, "resources_hash": fingerprint(resources(scenario)),
                "tool_schema_hash": fingerprint(tool_definitions()), "system_prompt_hash": fingerprint(SYSTEM_PROMPT),
                "variants": variants, "provider": config.ai_provider if mode == "live" else "scripted_harness",
                "model": config.ai_model if mode == "live" else None,
                "generation": {"max_completion_tokens": 2000, "parallel_tool_calls": False,
                               "temperature": "provider default; deterministic output not guaranteed"},
                "calls_per_variant": min(config.simulation_max_iterations, config.simulation_max_provider_requests // len(variants)),
                "tools_per_variant": config.simulation_max_tool_calls // len(variants),
                "duration_per_variant": config.simulation_max_duration_seconds / len(variants),
                "secondary_ai_classifier": False,
                "label": "Live model observation" if mode == "live" else "Scripted infrastructure test; not evidence of model vulnerability",
            }
            row = SimulationRun(scenario_id=stored.id, mode=mode, configuration=SecretRedactor(config).clean(snapshot),
                                deadline_at=now + timedelta(seconds=config.simulation_max_duration_seconds + 15))
            db.add(row)
            db.commit()
            return row.id

    def execute(self, run_id: UUID) -> None:
        with self.database.session() as db:
            db.execute(text("BEGIN IMMEDIATE"))
            run = db.get(SimulationRun, run_id)
            if run is None or run.status != "QUEUED":
                return
            run.status, run.started_at = "RUNNING", utcnow()
            snapshot, mode = run.configuration, run.mode
            db.commit()
        trace = TraceCollector(self.database, run_id, self.settings)
        results = {}
        try:
            from app.simulations.schemas import Scenario
            scenario = Scenario.model_validate(snapshot["scenario"])
            for variant in snapshot["variants"]:
                deadline = time.monotonic() + snapshot["duration_per_variant"]

                def check() -> None:
                    with self.database.session() as db:
                        current = db.get(SimulationRun, run_id)
                        if current.cancel_requested:
                            raise SimulationStop("cancelled")
                        if current.status != "RUNNING" or time.monotonic() >= deadline:
                            raise SimulationStop("duration_limit")

                provider = LiveProvider(self.settings, deadline, check) if mode == "live" else ScriptedProvider(scenario)
                result = run_variant(scenario, variant, self.settings, trace, provider, check,
                                     snapshot["calls_per_variant"], snapshot["tools_per_variant"])
                result.update(mode=mode, mode_label=snapshot["label"], benign=scenario.benign)
                results[variant] = result
                with self.database.session() as db:
                    db.add(SimulationResult(run_id=run_id, variant=variant, outcome=result["outcome"], details=result))
                    db.commit()
            with self.database.session() as db:
                run = db.get(SimulationRun, run_id)
                statuses = {r["execution_status"] for r in results.values()}
                run.status = "COMPLETED" if statuses == {"COMPLETED"} else "CANCELLED" if "CANCELLED" in statuses else "PARTIAL"
                run.comparison, run.completed_at = compare(results), utcnow()
                run.error_code = next((r["error_code"] for r in results.values() if r["error_code"]), None)
                db.commit()
        except Exception:
            with self.database.session() as db:
                run = db.get(SimulationRun, run_id)
                run.status, run.error_code, run.completed_at = "ERROR", "simulation_storage_or_setup_failed", utcnow()
                existing = set(db.scalars(select(SimulationResult.variant).where(SimulationResult.run_id == run_id)))
                for variant in snapshot["variants"]:
                    if variant not in existing:
                        db.add(SimulationResult(run_id=run_id, variant=variant, outcome="ERROR", details={
                            "outcome": "ERROR", "attack_success": None, "execution_status": "ERROR",
                            "error_code": "simulation_storage_or_setup_failed", "mode": mode, "is_simulation": True}))
                db.commit()
