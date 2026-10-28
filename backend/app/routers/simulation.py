"""Opt-in loopback-only simulation jobs and bounded history retrieval."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request
from sqlalchemy import func, select

from app.models import SimulationResult, SimulationRun, SimulationTrace
from app.routers.security import require_local_development
from app.simulations.engine import SimulationEngine, recover_expired
from app.simulations.scenarios import SCENARIOS, resources
from app.simulations.schemas import CompareRequest, RunRequest

router = APIRouter(prefix="/api/simulation", tags=["simulation (local development)"],
                   dependencies=[Depends(require_local_development)])


def engine(request: Request) -> SimulationEngine:
    if not request.app.state.settings.simulation_enabled:
        raise HTTPException(404)
    return SimulationEngine(request.app.state.database, request.app.state.settings)


Engine = Annotated[SimulationEngine, Depends(engine)]
Limit = Annotated[int, Query(ge=1, le=100)]
Offset = Annotated[int, Query(ge=0)]


@router.get("/scenarios")
def scenarios() -> list[dict]:
    return [s.model_dump(exclude={"payload", "task"}) for s in SCENARIOS.values()]


@router.get("/scenarios/{scenario_id}")
def scenario_detail(scenario_id: str) -> dict:
    if scenario_id not in SCENARIOS:
        raise HTTPException(404)
    scenario = SCENARIOS[scenario_id]
    return {**scenario.model_dump(), "resources": resources(scenario), "is_simulation": True}


@router.post("/run", status_code=202)
def run(payload: RunRequest, jobs: BackgroundTasks, service: Engine) -> dict:
    run_id = service.admit(payload.scenario_id, payload.mode, [payload.variant])
    jobs.add_task(service.execute, run_id)
    return {"run_id": run_id, "status": "QUEUED", "mode": payload.mode, "is_simulation": True}


@router.post("/compare", status_code=202)
def comparison(payload: CompareRequest, jobs: BackgroundTasks, service: Engine) -> dict:
    run_id = service.admit(payload.scenario_id, payload.mode, ["baseline", "protected"])
    jobs.add_task(service.execute, run_id)
    return {"run_id": run_id, "status": "QUEUED", "mode": payload.mode, "is_simulation": True}


def summary(row: SimulationRun) -> dict:
    return {"run_id": row.id, "scenario_id": row.configuration["scenario"]["id"], "mode": row.mode,
            "status": row.status, "is_simulation": True, "created_at": row.created_at,
            "started_at": row.started_at, "completed_at": row.completed_at, "error_code": row.error_code}


@router.get("/runs")
def runs(service: Engine, limit: Limit = 50, offset: Offset = 0) -> list[dict]:
    with service.database.session() as db:
        recover_expired(db)
        db.commit()
        return [summary(r) for r in db.scalars(select(SimulationRun).order_by(
            SimulationRun.created_at.desc(), SimulationRun.id.desc()).offset(offset).limit(limit))]


@router.get("/runs/{run_id}")
def details(run_id: UUID, service: Engine) -> dict:
    with service.database.session() as db:
        recover_expired(db)
        db.commit()
        row = db.get(SimulationRun, run_id)
        if row is None:
            raise HTTPException(404)
        results = {r.variant: r.details for r in db.scalars(select(SimulationResult).where(SimulationResult.run_id == run_id))}
        counts = db.execute(select(SimulationTrace.event_type, func.count()).where(
            SimulationTrace.run_id == run_id).group_by(SimulationTrace.event_type)).all()
        return {**summary(row), "configuration": row.configuration, "results": results,
                "comparison": row.comparison, "trace_summary": dict(counts), "cancel_requested": row.cancel_requested}


@router.get("/runs/{run_id}/traces")
def traces(run_id: UUID, service: Engine, limit: Limit = 100, offset: Offset = 0) -> list[dict]:
    with service.database.session() as db:
        if db.get(SimulationRun, run_id) is None:
            raise HTTPException(404)
        return [{"trace_id": r.id, "run_id": r.run_id, "variant": r.variant, "step": r.step,
                 "timestamp": r.created_at, "event_type": r.event_type, "details": r.details}
                for r in db.scalars(select(SimulationTrace).where(SimulationTrace.run_id == run_id)
                                   .order_by(SimulationTrace.step).offset(offset).limit(limit))]


@router.post("/runs/{run_id}/cancel")
def cancel(run_id: UUID, service: Engine) -> dict:
    with service.database.session() as db:
        row = db.get(SimulationRun, run_id)
        if row is None:
            raise HTTPException(404)
        if row.status in {"QUEUED", "RUNNING"}:
            row.cancel_requested = True
            db.commit()
        return {"run_id": run_id, "cancel_requested": row.cancel_requested, "status": row.status}


@router.get("/stats")
def stats(service: Engine) -> dict:
    groups = {}
    with service.database.session() as db:
        recover_expired(db)
        db.commit()
        total = db.scalar(select(func.count()).select_from(SimulationRun))
        for mode in ("scripted", "live"):
            group = {"total_runs": db.scalar(select(func.count()).select_from(SimulationRun).where(SimulationRun.mode == mode)), "variants": {}}
            for variant in ("baseline", "protected"):
                values = {k: 0 for k in ("results", "attack_successes", "conclusive_attacks", "benign_controls_observed", "false_positives",
                    "legitimate_tasks_completed", "completed_variants", "unauthorized_tool_attempts", "blocked_actions",
                    "injections_detected", "critical_content_quarantined", "errors", "inconclusive", "provider_errors")}
                duration, durations = 0., 0
                statement = select(SimulationResult.details).join(SimulationRun).where(SimulationRun.mode == mode, SimulationResult.variant == variant)
                for d in db.scalars(statement.execution_options(yield_per=100)):
                    values["results"] += 1
                    if not d.get("benign") and d.get("attack_success") is not None:
                        values["conclusive_attacks"] += 1
                        values["attack_successes"] += int(d["attack_success"])
                    if d.get("benign") and d.get("false_positive") is not None:
                        values["benign_controls_observed"] += 1
                        values["false_positives"] += int(d["false_positive"])
                    for key in ("unauthorized_tool_attempts", "blocked_actions", "injections_detected", "critical_content_quarantined"):
                        values[key] += d.get(key, 0)
                    if d.get("execution_status") == "COMPLETED":
                        values["completed_variants"] += 1
                        values["legitimate_tasks_completed"] += int(d.get("legitimate_task_completed", False))
                    values["errors"] += d["outcome"] == "ERROR"
                    values["inconclusive"] += d["outcome"] == "INCONCLUSIVE"
                    values["provider_errors"] += bool(d.get("error_code") and (d["error_code"].startswith(("ai_", "provider_"))))
                    if "duration_seconds" in d:
                        duration += d["duration_seconds"]
                        durations += 1
                for name, numerator, denominator in (("attack_success_rate", "attack_successes", "conclusive_attacks"),
                    ("false_positive_rate", "false_positives", "benign_controls_observed"),
                    ("legitimate_task_completion_rate", "legitimate_tasks_completed", "completed_variants")):
                    values[name] = values[numerator] / values[denominator] if values[denominator] else None
                values["average_variant_duration_seconds"] = duration / durations if durations else None
                group["variants"][variant] = values
            groups[mode] = group
    return {"total_simulations": total, "modes": groups,
            "interpretation": "Rates use the explicit adjacent denominators (0 to 1); empty denominators yield null. Scripted infrastructure tests are not model vulnerability measurements. Synthetic scenarios do not establish real-world protection rates."}
