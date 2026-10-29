import { useMemo, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { ShieldCheck, ArrowRight } from "lucide-react";
import { motion } from "motion/react";
import { api } from "../api/client";
import type { Json, Tool } from "../api/types";
import { usePolicies } from "../api/hooks";
import {
  Badge,
  decisionTone,
  Empty,
  ErrorState,
  JsonDetails,
  Notice,
  PageTitle,
  Panel,
} from "../components/ui";
import { NeuralCanvas } from "../graph/NeuralCanvas";
import { decisionGraph } from "../graph/model";
const examples: Record<Tool, Record<string, Json>> = {
  read_document: { filename: "project_report.txt" },
  search_database: { query: "John", category: "customer", limit: 5 },
  send_email: {
    to: "demo@example.com",
    subject: "Demo update",
    body: "Public project review is ready.",
  },
};
export default function Firewall() {
  const [tool, setTool] = useState<Tool>("read_document");
  const [args, setArgs] = useState(
    JSON.stringify(examples.read_document, null, 2),
  );
  const [validation, setValidation] = useState("");
  const query = useQueryClient();
  const policies = usePolicies();
  const evaluate = useMutation({
    mutationFn: (args: Record<string, Json>) => api.evaluate(tool, args),
    onSuccess: () => query.invalidateQueries(),
  });
  const graph = useMemo(() => decisionGraph(evaluate.data), [evaluate.data]);
  return (
    <>
      <PageTitle
        eyebrow="03 / AUTHORIZATION BOUNDARY"
        title="Permission comes first."
        description="Evaluate a request against the real policy engine. No tool is executed here."
      />
      <div className="workbench">
        <Panel title="Request builder" kicker="POLICY EVALUATION">
          <form
            className="panel-body stack"
            onSubmit={(e) => {
              e.preventDefault();
              try {
                const parsed = JSON.parse(args);
                if (
                  !parsed ||
                  Array.isArray(parsed) ||
                  typeof parsed !== "object"
                )
                  throw Error();
                setValidation("");
                evaluate.mutate(parsed);
              } catch {
                setValidation("Arguments must be a valid JSON object.");
              }
            }}
          >
            <label>
              Tool
              <select
                value={tool}
                disabled={evaluate.isPending}
                onChange={(e) => {
                  const value = e.target.value as Tool;
                  setTool(value);
                  setArgs(JSON.stringify(examples[value], null, 2));
                  evaluate.reset();
                }}
              >
                {Object.keys(examples).map((t) => (
                  <option key={t}>{t}</option>
                ))}
              </select>
            </label>
            <label>
              Arguments
              <textarea
                className="code-editor"
                value={args}
                maxLength={12000}
                onChange={(e) => setArgs(e.target.value)}
                rows={10}
              />
            </label>
            {tool === "read_document" && (
              <button
                type="button"
                className="text-button"
                onClick={() =>
                  setArgs(
                    JSON.stringify(
                      { filename: "confidential_strategy.txt" },
                      null,
                      2,
                    ),
                  )
                }
              >
                Try a confidential document <ArrowRight size={13} />
              </button>
            )}
            {validation && <ErrorState error={new Error(validation)} />}
            <button
              className="primary"
              disabled={evaluate.isPending}
              type="submit"
            >
              <ShieldCheck size={16} />
              {evaluate.isPending ? "Evaluating…" : "Evaluate request"}
            </button>
            <Notice>
              Writes an audit event. An ALLOW decision grants permission; it is
              not proof of execution.
            </Notice>
            {evaluate.error && <ErrorState error={evaluate.error} />}
          </form>
        </Panel>
        <Panel
          title="The authorization boundary"
          kicker="REQUEST → POLICY → DECISION"
        >
          <NeuralCanvas
            graph={graph}
            label="Evaluation only · no tool effects"
          />
          {evaluate.data ? (
            <motion.div
              key={evaluate.data.decision_id}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              className={`decision-banner ${decisionTone(evaluate.data.decision)}`}
            >
              <ShieldCheck size={26} />
              <div>
                <Badge tone={decisionTone(evaluate.data.decision)}>
                  {evaluate.data.decision}
                </Badge>
                <p>{evaluate.data.reason}</p>
              </div>
            </motion.div>
          ) : (
            <Empty title="Awaiting a request">
              No decision has been assumed.
            </Empty>
          )}
        </Panel>
      </div>
      <div className="two-columns">
        <Panel title="Decision evidence">
          <div className="panel-body">
            {evaluate.data ? (
              <>
                <dl className="facts">
                  <dt>Decision ID</dt>
                  <dd className="mono">{evaluate.data.decision_id}</dd>
                  <dt>Policy</dt>
                  <dd>{evaluate.data.policy_id}</dd>
                  <dt>Risk level</dt>
                  <dd>
                    <Badge tone={decisionTone(evaluate.data.risk_level)}>
                      {evaluate.data.risk_level}
                    </Badge>
                  </dd>
                  <dt>Timestamp</dt>
                  <dd>{evaluate.data.timestamp}</dd>
                  <dt>Session</dt>
                  <dd className="mono">{evaluate.data.session_id}</dd>
                  <dt>Validated arguments</dt>
                  <dd className="mono">
                    {Object.entries(evaluate.data.arguments_summary)
                      .map(([k, v]) => `${k}: ${JSON.stringify(v)}`)
                      .join(" · ") || "None recorded"}
                  </dd>
                </dl>
                <JsonDetails value={evaluate.data} />
              </>
            ) : (
              <p className="muted-text">
                Submit an evaluation to inspect its persisted evidence.
              </p>
            )}
          </div>
        </Panel>
        <Panel title="Policy posture">
          <div className="panel-body">
            {policies.isError ? (
              <ErrorState
                error={policies.error}
                retry={() => policies.refetch()}
              />
            ) : policies.data ? (
              <>
                <Badge tone={policies.data.valid ? "success" : "danger"}>
                  {policies.data.valid
                    ? "Configuration valid"
                    : "Configuration invalid"}
                </Badge>
                <p>
                  Default: {policies.data.default_decision} · Explicit deny
                  overrides allow.
                </p>
                <div className="chips">
                  {policies.data.baseline_guards.map((g) => (
                    <span key={g}>{g.replaceAll("_", " ")}</span>
                  ))}
                </div>
                <JsonDetails value={policies.data.rules} />
              </>
            ) : (
              <p>Loading policy configuration…</p>
            )}
          </div>
        </Panel>
      </div>
    </>
  );
}
