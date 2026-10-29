import { useMemo } from "react";
import type { Result, Trace, Variant } from "../api/types";
import { NeuralCanvas } from "../graph/NeuralCanvas";
import { traceGraph } from "../graph/model";
import { Badge, Empty, JsonDetails, Panel } from "./ui";
export function SimulationResult({
  variant,
  result,
  traces,
  loaded,
}: {
  variant: Variant;
  result?: Result;
  traces: Trace[];
  loaded: boolean;
}) {
  const graph = useMemo(
    () =>
      traceGraph(
        traces.filter((t) => t.variant === variant),
        variant === "baseline",
      ),
    [traces, variant],
  );
  const evidenceTypes = [
    "MODEL_REQUEST",
    "TOOL_REQUEST",
    "FIREWALL_EVALUATION",
    "INJECTION_SCAN",
    "TOOL_EXECUTION",
    "CONTENT_BLOCKED",
    "ATTACK_OBJECTIVE_EVALUATED",
  ];
  const values: [string, unknown][] = [
    ["Unauthorized attempts", result?.unauthorized_tool_attempts],
    ["Tools executed", result?.tools_executed],
    ["Firewall denials", result?.blocked_actions],
    ["Confidential access", result?.confidential_data_accessed],
    ["Simulated exfiltration", result?.simulated_exfiltration],
    ["Injection detections", result?.injections_detected],
    ["Critical quarantines", result?.critical_content_quarantined],
    ["Legitimate task completed", result?.legitimate_task_completed],
    [
      result?.mode === "scripted" ? "Scripted model turns" : "Provider requests",
      result?.provider_requests,
    ],
    [
      "Execution duration",
      result?.duration_seconds === undefined
        ? undefined
        : `${result.duration_seconds.toFixed(2)} s`,
    ],
  ];
  const tone =
    result?.outcome === "SUCCESS"
      ? result.benign
        ? "success"
        : "danger"
      : result?.outcome === "ERROR"
        ? "danger"
        : "neutral";
  return (
    <Panel
      className={`comparison-panel ${variant}`}
      title={variant === "baseline" ? "Baseline agent" : "Protected agent"}
      kicker={
        variant === "baseline"
          ? "ISOLATED · NO STAGE 3/4 CONTROLS"
          : "ISOLATED · STAGE 3 + STAGE 4"
      }
      actions={
        <Badge tone={tone}>{result?.outcome || "Awaiting result"}</Badge>
      }
    >
      <NeuralCanvas
        compact
        graph={graph}
        label={
          loaded
            ? "Recorded trace page · not a live replay"
            : "Topology · no trace loaded"
        }
      />
      {loaded && (
        <div className="panel-body">
          <small>Events in the loaded trace page</small>
          <div className="chips">
            {evidenceTypes.map((type) => {
              const count = traces.filter(
                (t) => t.variant === variant && t.event_type === type,
              ).length;
              return count ? (
                <span key={type}>
                  {type.toLowerCase().replaceAll("_", " ")} · {count}
                </span>
              ) : null;
            })}
          </div>
        </div>
      )}
      {result ? (
        <div className="panel-body">
          <div className="outcome">
            <span>Objective outcome</span>
            <strong>{result.outcome}</strong>
            <p>
              {result.success_criteria ||
                "Execution ended before a complete objective evaluation."}
            </p>
          </div>
          <dl className="result-metrics">
            {values.map(([name, value]) => (
              <div key={name}>
                <dt>{name}</dt>
                <dd>
                  {value === undefined
                    ? "Unavailable"
                    : typeof value === "boolean"
                      ? value
                        ? "Yes"
                        : "No"
                      : String(value)}
                </dd>
              </div>
            ))}
          </dl>
          {result.error_code && (
            <p className="danger">Execution error: {result.error_code}</p>
          )}
          {result.final_response && (
            <blockquote>{result.final_response}</blockquote>
          )}
          <JsonDetails value={result} />
        </div>
      ) : (
        <Empty title="No completed result">
          Start a run or select one from history.
        </Empty>
      )}
    </Panel>
  );
}
