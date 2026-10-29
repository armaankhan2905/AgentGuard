import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Play, Square, ArrowUpRight, FlaskConical } from "lucide-react";
import { toast } from "sonner";
import { api } from "../api/client";
import type { Mode, Variant } from "../api/types";
import { useInspector } from "../components/Inspector";
import {
  Badge,
  date,
  decisionTone,
  Empty,
  ErrorState,
  Loading,
  Notice,
  Pager,
  PageTitle,
  Panel,
} from "../components/ui";
import { SimulationResult } from "../components/SimulationResult";
import { SimulationStats } from "../components/SimulationStats";
export const isActive = (status?: string) =>
  status === "QUEUED" || status === "RUNNING";
export const shouldPoll = (
  status: string | undefined,
  started: number,
  now = Date.now(),
) => (!status || isActive(status)) && now - started < 240000;
export default function Simulations() {
  const [scenario, setScenario] = useState("instruction_override");
  const [mode, setMode] = useState<Mode>("scripted");
  const [variant, setVariant] = useState<Variant | "compare">("compare");
  const [active, setActive] = useState<{ id: string; started: number }>();
  const [expiredPoll, setExpiredPoll] = useState<string>();
  const [offset, setOffset] = useState(0);
  const [traceOffset, setTraceOffset] = useState(0);
  const query = useQueryClient();
  const inspect = useInspector();
  const scenarios = useQuery({
    queryKey: ["scenarios"],
    queryFn: ({ signal }) => api.scenarios(signal),
  });
  const chosen = scenarios.data?.find((s) => s.id === scenario);
  const history = useQuery({
    queryKey: ["runs", offset],
    queryFn: ({ signal }) => api.runs(offset, signal),
  });
  const run = useQuery({
    queryKey: ["run", active?.id],
    queryFn: ({ signal }) => api.run(active!.id, signal),
    enabled: !!active,
    refetchInterval: (q) =>
      active &&
      !q.state.error &&
      shouldPoll(q.state.data?.status, active.started)
        ? 2000
        : false,
  });
  useEffect(() => {
    if (!active) return;
    const timer = setTimeout(
      () => setExpiredPoll(`${active.id}:${active.started}`),
      Math.max(0, active.started + 240000 - Date.now()),
    );
    return () => clearTimeout(timer);
  }, [active]);
  const polling =
    !!active &&
    expiredPoll !== `${active.id}:${active.started}` &&
    shouldPoll(run.data?.status, active.started);
  useEffect(() => {
    if (run.data?.status && !isActive(run.data.status)) {
      void query.invalidateQueries({ queryKey: ["runs"] });
      void query.invalidateQueries({ queryKey: ["simulation-stats"] });
    }
  }, [run.data?.status, active?.id, query]);
  const traces = useQuery({
    queryKey: ["traces", active?.id, traceOffset, run.data?.status],
    queryFn: ({ signal }) => api.traces(active!.id, traceOffset, signal),
    enabled: !!active,
    refetchInterval: (q) =>
      active && !q.state.error && shouldPoll(run.data?.status, active.started)
        ? 3000
        : false,
  });
  const launch = useMutation({
    mutationFn: () => api.launch(scenario, mode, variant),
    onSuccess: (r) => {
      setActive({ id: r.run_id, started: Date.now() });
      setTraceOffset(0);
      query.invalidateQueries();
      toast.success("Simulation queued");
    },
    onError: () => toast.error("Simulation was not admitted"),
  });
  const cancel = useMutation({
    mutationFn: () => api.cancel(active!.id),
    onSuccess: () => {
      query.invalidateQueries({ queryKey: ["run", active?.id] });
      toast("Cancellation requested");
    },
  });
  const selectRun = (id: string) => {
    setActive({ id, started: Date.now() });
    setTraceOffset(0);
  };
  return (
    <>
      <PageTitle
        eyebrow="05 / CONTROLLED ADVERSARIAL TESTING"
        title="Test the boundary."
        description="Same scenario. Same model. Two enforcement paths. Observe what actually happens."
        actions={
          <Badge tone="cyan">
            <FlaskConical size={13} />
            Isolated synthetic lab
          </Badge>
        }
      />
      <Panel className="launch-panel">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            launch.mutate();
          }}
        >
          <label>
            Attack scenario
            <select
              value={scenario}
              onChange={(e) => setScenario(e.target.value)}
              disabled={
                scenarios.isPending || scenarios.isError || launch.isPending
              }
            >
              {scenarios.data?.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.name}
                </option>
              ))}
            </select>
          </label>
          <label>
            Execution mode
            <select
              value={mode}
              onChange={(e) => setMode(e.target.value as Mode)}
            >
              <option value="scripted">Scripted</option>
              <option value="live">Live AI</option>
            </select>
          </label>
          <label>
            Execution paths
            <select
              value={variant}
              onChange={(e) =>
                setVariant(e.target.value as Variant | "compare")
              }
            >
              <option value="compare">Compare both</option>
              <option value="protected">Protected only</option>
              <option value="baseline">Baseline only</option>
            </select>
          </label>
          <button
            className="primary"
            disabled={!chosen || launch.isPending || isActive(run.data?.status)}
          >
            <Play size={16} />
            {launch.isPending ? "Queuing…" : "Launch simulation"}
          </button>
        </form>
        <div className="scenario-context">
          {chosen && (
            <>
              <Badge>{chosen.category.replaceAll("_", " ")}</Badge>
              <span>
                {chosen.difficulty} · {chosen.entry_point} entry
              </span>
              <button
                className="text-button"
                onClick={() =>
                  inspect({
                    title: chosen.name,
                    kind: "Scenario definition",
                    description: chosen.description,
                    data: chosen,
                  })
                }
              >
                Scenario details <ArrowUpRight size={14} />
              </button>
            </>
          )}
        </div>
        <Notice>
          {mode === "scripted"
            ? "Scripted infrastructure demonstration — no real model behavior is being evaluated."
            : "Live AI model evaluation using the configured provider. Uses real provider requests and account quota; launch only when intended."}
        </Notice>
        {chosen && (
          <p className="objective-note">
            <strong>Observable objective:</strong> {chosen.success_criteria}
          </p>
        )}
        {scenarios.error && (
          <ErrorState
            error={scenarios.error}
            retry={() => scenarios.refetch()}
          />
        )}{" "}
        {launch.error && <ErrorState error={launch.error} />}{" "}
        {cancel.error && <ErrorState error={cancel.error} />}
      </Panel>
      {active && (
        <div className="run-bar">
          <div>
            <span className="eyebrow">SELECTED RUN</span>
            <span className="mono">{active.id}</span>
          </div>
          <Badge tone={decisionTone(run.data?.status || "QUEUED")}>
            {run.data?.status || "Loading"}
          </Badge>
          <span>
            {run.data?.mode}{" "}
            {run.data?.configuration.model &&
              `· ${run.data.configuration.model}`}
          </span>
          {isActive(run.data?.status) && (
            <button
              disabled={cancel.isPending || run.data?.cancel_requested}
              onClick={() => cancel.mutate()}
            >
              <Square size={13} />
              {run.data?.cancel_requested
                ? "Cancellation requested"
                : "Cancel run"}
            </button>
          )}
          {!polling && isActive(run.data?.status) && (
            <button
              onClick={() => setActive({ ...active, started: Date.now() })}
            >
              Resume bounded polling
            </button>
          )}
        </div>
      )}
      {run.error && (
        <ErrorState
          error={run.error}
          retry={() => {
            if (active) setActive({ ...active, started: Date.now() });
            run.refetch();
          }}
        />
      )}
      <div className="comparison-grid">
        {(["baseline", "protected"] as const).map((v) => (
          <SimulationResult
            key={`${active?.id}-${v}`}
            variant={v}
            result={run.data?.results[v]}
            traces={traces.data || []}
            loaded={!!traces.data}
          />
        ))}
      </div>
      <Notice>
        An objective can succeed because a forbidden request was generated, even
        when execution was denied. Read confidential access and simulated
        exfiltration separately. No forbidden request is not a firewall block.{" "}
        {run.data?.comparison.note}
      </Notice>
      <Panel
        title="Execution evidence"
        kicker="ORDERED TRACE EVENTS"
        actions={
          run.data && (
            <button
              className="text-button"
              onClick={() =>
                inspect({
                  title: "Run comparison",
                  kind: "Recorded comparison",
                  data: run.data,
                })
              }
            >
              Inspect run <ArrowUpRight size={14} />
            </button>
          )
        }
      >
        {!active ? (
          <Empty title="No run selected">
            Launch a comparison or select a historical run.
          </Empty>
        ) : traces.isPending ? (
          <Loading />
        ) : traces.isError ? (
          <ErrorState error={traces.error} retry={() => traces.refetch()} />
        ) : (
          <>
            <div className="trace-table table-scroll">
              <table>
                <thead>
                  <tr>
                    <th>Step</th>
                    <th>Variant</th>
                    <th>Event</th>
                    <th>Recorded at</th>
                    <th>Evidence</th>
                  </tr>
                </thead>
                <tbody>
                  {traces.data.map((t) => (
                    <tr key={t.trace_id}>
                      <td className="mono">
                        {String(t.step).padStart(2, "0")}
                      </td>
                      <td>
                        <Badge
                          tone={t.variant === "protected" ? "cyan" : "neutral"}
                        >
                          {t.variant}
                        </Badge>
                      </td>
                      <td className="mono">{t.event_type}</td>
                      <td>{date(t.timestamp)}</td>
                      <td>
                        <button
                          aria-label={`Inspect trace step ${t.step}`}
                          onClick={() =>
                            inspect({
                              title: t.event_type,
                              kind: `Trace ${t.step} · ${t.variant}`,
                              data: t,
                            })
                          }
                        >
                          <ArrowUpRight size={15} />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {!traces.data.length && (
                <Empty title="No trace events recorded yet" />
              )}
            </div>
            <Pager
              offset={traceOffset}
              size={100}
              count={traces.data.length}
              onChange={setTraceOffset}
            />
          </>
        )}
      </Panel>
      <div className="two-columns">
        <Panel
          title="Simulation history"
          kicker="PERSISTED RUNS"
          actions={
            <button
              className="text-button"
              onClick={() => {
                history.refetch();
                query.invalidateQueries({ queryKey: ["simulation-stats"] });
              }}
            >
              Refresh history
            </button>
          }
        >
          {history.isPending ? (
            <Loading />
          ) : history.isError ? (
            <ErrorState error={history.error} retry={() => history.refetch()} />
          ) : (
            <>
              <div className="history-list">
                {history.data.map((r) => (
                  <button
                    key={r.run_id}
                    className={r.run_id === active?.id ? "selected" : ""}
                    onClick={() => selectRun(r.run_id)}
                  >
                    <div>
                      <strong>{r.scenario_id.replaceAll("_", " ")}</strong>
                      <small>
                        {r.mode} · {date(r.created_at)}
                      </small>
                    </div>
                    <Badge tone={decisionTone(r.status)}>{r.status}</Badge>
                  </button>
                ))}
                {!history.data.length && (
                  <Empty title="No simulation history" />
                )}
              </div>
              <Pager
                offset={offset}
                size={20}
                count={history.data.length}
                onChange={setOffset}
              />
            </>
          )}
        </Panel>
        <SimulationStats />
      </div>
    </>
  );
}
