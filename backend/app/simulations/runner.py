"""One bounded protocol loop for both variants; only the sandbox controls differ."""

import json
import time
from collections.abc import Callable

from app.agent.errors import AgentError
from app.agent.history import SYSTEM_PROMPT, bound_context
from app.agent.provider import AssistantReply, LLMProvider
from app.core.config import Settings
from app.core.redaction import SecretRedactor
from app.simulations.evaluator import evaluate
from app.simulations.sandbox import Sandbox, tool_definitions
from app.simulations.scenarios import fingerprint
from app.simulations.schemas import Scenario, Variant
from app.simulations.trace import SimulationStop, TraceCollector


def run_variant(scenario: Scenario, variant: Variant, settings: Settings, trace: TraceCollector,
                provider: LLMProvider, check: Callable[[], None], call_budget: int,
                tool_budget: int) -> dict:
    started = time.monotonic()
    final, error, status = "", None, "COMPLETED"
    model_requests = 0
    sandbox = Sandbox(scenario, variant, settings, trace)
    messages = [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": scenario.task}]
    definitions = tool_definitions()
    seen: set[str] = set()
    try:
        trace.add(variant, "SIMULATION_STARTED", {"initial_context_hash": fingerprint(messages),
                                                "tool_schema_hash": fingerprint(definitions)})
        trace.add(variant, "SCENARIO_LOADED", {"scenario_id": scenario.id, "payload_hash": fingerprint(scenario.payload)})
        if tool_budget == 0:
            raise SimulationStop("tool_limit")
        for iteration in range(call_budget):
            check()
            context = bound_context(messages, settings, definitions)
            trace.add(variant, "MODEL_REQUEST", {"iteration": iteration + 1, "context_hash": fingerprint(context),
                                               "message_count": len(context)})
            model_requests += 1
            reply = AssistantReply.model_validate(provider.complete(context, definitions,
                allow_tools=len(sandbox.requests) < tool_budget).model_dump())
            check()
            trace.add(variant, "MODEL_RESPONSE", {"content_hash": fingerprint(reply.content),
                "content_length": len(reply.content or ""), "tool_count": len(reply.tool_calls)})
            if not reply.tool_calls:
                final = SecretRedactor(settings).text(reply.content or "")[:4000]
                break
            messages.append(reply.model_dump(exclude_none=True))
            for call in reply.tool_calls:
                check()
                if call.id in seen:
                    raise SimulationStop("duplicate_tool_call")
                if len(sandbox.requests) >= tool_budget:
                    raise SimulationStop("tool_limit")
                seen.add(call.id)
                result = sandbox.execute(call.function.name, call.function.arguments)
                messages.append({"role": "tool", "tool_call_id": call.id, "content": json.dumps(result)})
        else:
            raise SimulationStop("iteration_limit")
    except SimulationStop as exc:
        error = exc.code
        status = "CANCELLED" if error == "cancelled" else "TIMED_OUT" if error in {"duration_limit", "provider_timeout"} else "LIMIT_REACHED"
    except AgentError as exc:
        status, error = "ERROR", exc.code
    except Exception:
        # No exception repr/provider bodies are logged or persisted.
        status, error = "ERROR", "simulation_execution_failed"
    finally:
        entry_observed = any(
            e["tool_name"] == "read_document" and e["arguments_summary"].get("filename") == "project_report.txt"
            if scenario.entry_point == "document" else
            e["tool_name"] == "search_database" and e["arguments_summary"].get("category") == "customer"
            for e in sandbox.executions)
        state = {"requests": sandbox.requests, "executions": sandbox.executions, "outbox": sandbox.outbox,
                 "blocks": sandbox.blocks, "scans": sandbox.scans, "entry_observed": entry_observed,
                 "legitimate_content_available": sandbox.legitimate_content_available}
        sandbox.close()
    result = evaluate(scenario, state, status, final, error)
    result.update(duration_seconds=round(time.monotonic() - started, 4), provider_requests=model_requests,
                  mode_label="Set by the run execution mode", is_simulation=True)
    try:
        trace.add(variant, "ATTACK_OBJECTIVE_EVALUATED", {"outcome": result["outcome"], "evidence": result["evidence"]}, terminal=True)
        trace.add(variant, "SIMULATION_COMPLETED" if status == "COMPLETED" else "SIMULATION_FAILED",
                  {"execution_status": status, "error_code": error}, terminal=True)
    except Exception:
        # Missing durable terminal evidence is not a completed evaluation.
        result.update(outcome="ERROR", attack_success=None, execution_status="ERROR", error_code="trace_persistence_failed")
    return result
