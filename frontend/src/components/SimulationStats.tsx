import { useState } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import type { Mode } from "../api/types";
import { useSimStats } from "../api/hooks";
import { Empty, ErrorState, Loading, Notice, Panel } from "./ui";
export function SimulationStats() {
  const [mode, setMode] = useState<Mode>("scripted");
  const stats = useSimStats();
  const group = stats.data?.modes[mode];
  const chart = group
    ? (["baseline", "protected"] as const).map((variant) => ({
        name: variant,
        Attempts: group.variants[variant].unauthorized_tool_attempts,
        Denials: group.variants[variant].blocked_actions,
      }))
    : [];
  return (
    <Panel
      title="Measured in the lab"
      kicker="PERSISTED STATISTICS"
      actions={
        <div className="segmented" aria-label="Statistics mode">
          {(["scripted", "live"] as const).map((m) => (
            <button
              key={m}
              aria-pressed={mode === m}
              onClick={() => setMode(m)}
            >
              {m}
            </button>
          ))}
        </div>
      }
    >
      {stats.isPending ? (
        <Loading />
      ) : stats.isError ? (
        <ErrorState error={stats.error} retry={() => stats.refetch()} />
      ) : group?.total_runs ? (
        <div className="stats-layout">
          <div className="chart-container">
            <ResponsiveContainer width="100%" height={230}>
              <BarChart
                data={chart}
                margin={{ left: 0, right: 16, top: 16, bottom: 0 }}
              >
                <CartesianGrid
                  strokeDasharray="3 6"
                  stroke="#243149"
                  vertical={false}
                />
                <XAxis dataKey="name" stroke="#94a3b8" />
                <YAxis allowDecimals={false} stroke="#94a3b8" />
                <Tooltip
                  contentStyle={{
                    background: "#131d30",
                    border: "1px solid #243149",
                    color: "#e8f0ff",
                  }}
                />
                <Legend />
                <Bar
                  dataKey="Attempts"
                  fill="#8b5cf6"
                  radius={[3, 3, 0, 0]}
                  isAnimationActive={false}
                />
                <Bar
                  dataKey="Denials"
                  fill="#22d3ee"
                  radius={[3, 3, 0, 0]}
                  isAnimationActive={false}
                />
              </BarChart>
            </ResponsiveContainer>
          </div>
          <div className="panel-body">
            <p>
              {group.total_runs} {mode} runs recorded
            </p>
            {(["baseline", "protected"] as const).map((v) => (
              <div className="stat-cohort" key={v}>
                <strong>{v}</strong>
                <span>
                  {group.variants[v].attack_successes} /{" "}
                  {group.variants[v].conclusive_attacks} conclusive attack
                  objectives achieved
                </span>
                <small>
                  {group.variants[v].blocked_actions} firewall denials ·{" "}
                  {group.variants[v].injections_detected} injection detections
                  · {group.variants[v].critical_content_quarantined} critical
                  quarantines · {group.variants[v].legitimate_tasks_completed}{" "}
                  legitimate tasks completed
                </small>
                <small>
                  {group.variants[v].errors} errors ·{" "}
                  {group.variants[v].inconclusive} inconclusive ·{" "}
                  {group.variants[v].provider_errors} provider errors
                </small>
              </div>
            ))}
            <Notice>
              Synthetic scenario measurements, not general protection accuracy.
              Benign controls are excluded from attack denominators. Scripted
              results do not evaluate model behavior.
            </Notice>
          </div>
        </div>
      ) : (
        <Empty title={`No ${mode} measurements yet`}>
          Statistics appear only after actual runs are recorded.
        </Empty>
      )}
    </Panel>
  );
}
