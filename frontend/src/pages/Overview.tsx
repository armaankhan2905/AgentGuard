import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  ArrowUpRight,
  ShieldCheck,
  ScanLine,
  GitBranch,
  X,
} from "lucide-react";
import { api } from "../api/client";
import {
  useFirewallStats,
  useScanStats,
  useSimStats,
  useSystem,
} from "../api/hooks";
import type { FirewallEvent } from "../api/types";
import { NeuralCanvas } from "../graph/NeuralCanvas";
import { decisionGraph } from "../graph/model";
import {
  Badge,
  date,
  decisionTone,
  Empty,
  ErrorState,
  Loading,
  Metric,
  PageTitle,
  Panel,
} from "../components/ui";
export default function Overview() {
  const system = useSystem(),
    firewall = useFirewallStats(),
    scanner = useScanStats(),
    simulation = useSimStats();
  const events = useQuery({
    queryKey: ["overview-events"],
    queryFn: ({ signal }) => api.events({ limit: 5 }, signal),
  });
  const [selected, setSelected] = useState<FirewallEvent>();
  const graph = useMemo(() => decisionGraph(selected), [selected]);
  return (
    <>
      <PageTitle
        eyebrow="01 / SECURITY TOPOLOGY"
        title="Neural shield."
        description="A clear view of the boundaries between intention, permission, and action."
        actions={
          <Link className="button primary" to="/agent">
            Open AI workspace <ArrowUpRight size={17} />
          </Link>
        }
      />
      <div className="metrics-strip">
        <Metric
          label="Backend"
          value={
            system.isError
              ? undefined
              : system.data?.backend.available
                ? "Connected"
                : undefined
          }
          note="Current API status"
          tone="cyan"
        />
        <Metric
          label="Authorization events"
          value={
            firewall.isError ? undefined : firewall.data?.total_evaluations
          }
          note="All time · incl. firewall-page tests"
        />
        <Metric
          label="Allowed / denied"
          value={
            firewall.isError || !firewall.data
              ? undefined
              : `${firewall.data.allowed_actions} / ${firewall.data.blocked_actions}`
          }
          note="Permission, not execution"
        />
        <Metric
          label="Injection detections"
          value={scanner.isError ? undefined : scanner.data?.detected_threats}
          note="Heuristic matches · incl. manual scans"
          tone="warning"
        />
        <Metric
          label="Quarantined"
          value={scanner.isError ? undefined : scanner.data?.blocked_threats}
          note="BLOCK actions · incl. manual scans"
          tone="danger"
        />
        <Metric
          label="Simulations"
          value={
            simulation.isError ? undefined : simulation.data?.total_simulations
          }
          note="Scripted + live runs"
        />
      </div>
      <div className="overview-network">
        <Panel
          className="network-panel"
          title="The protection network"
          kicker="NEURAL MAP"
          actions={
            <Badge tone={selected ? "cyan" : "neutral"}>
              {selected ? "Historical event selected" : "System topology"}
            </Badge>
          }
        >
          <NeuralCanvas
            graph={graph}
            label={
              selected
                ? `Recorded decision · ${date(selected.timestamp)}`
                : "Known architecture · select a node to inspect"
            }
          />
          <div className="network-legend">
            <span>
              <i className="muted" />
              Topology
            </span>
            <span>
              <i className="success" />
              Authorized
            </span>
            <span>
              <i className="warning" />
              Flagged
            </span>
            <span>
              <i className="danger" />
              Denied / blocked
            </span>
            {selected && (
              <button
                className="text-button"
                onClick={() => setSelected(undefined)}
              >
                <X size={13} />
                Clear event
              </button>
            )}
          </div>
        </Panel>
        <aside className="boundary-notes">
          <div className="eyebrow">DEFENSE IN DEPTH</div>
          <h2>
            Two checks.
            <br />
            Distinct boundaries.
          </h2>
          <div className="boundary-step">
            <ShieldCheck />
            <span className="step-index">01</span>
            <h3>Authorize the action</h3>
            <p>The firewall checks permission before a tool can execute.</p>
            <Link to="/firewall">
              Explore the firewall <ArrowUpRight size={14} />
            </Link>
          </div>
          <div className="boundary-step">
            <ScanLine />
            <span className="step-index">02</span>
            <h3>Inspect the response</h3>
            <p>
              The scanner handles untrusted document and database content before
              it returns to the model.
            </p>
            <Link to="/scanner">
              Inspect content <ArrowUpRight size={14} />
            </Link>
          </div>
          <div className="topology-note">
            <GitBranch size={16} />
            <p>
              Connections show architecture. Select a recorded event below to
              see its authorization decision.
            </p>
          </div>
        </aside>
      </div>
      <Panel
        title="Recorded decisions"
        kicker="AUDIT SNAPSHOT"
        actions={
          <Link className="text-button" to="/audit">
            Explore all events <ArrowUpRight size={15} />
          </Link>
        }
      >
        {events.isPending ? (
          <Loading />
        ) : events.isError ? (
          <ErrorState error={events.error} retry={() => events.refetch()} />
        ) : !events.data.length ? (
          <Empty title="No recorded decisions">
            The graph shows topology only. Evaluate a tool request or start a
            conversation.
          </Empty>
        ) : (
          <div className="event-list">
            {events.data.map((event) => (
              <button
                className={`event-row ${selected?.decision_id === event.decision_id ? "selected" : ""}`}
                key={event.decision_id}
                onClick={() => setSelected(event)}
              >
                <Badge tone={decisionTone(event.decision)}>
                  {event.decision}
                </Badge>
                <strong className="mono">{event.tool_name}</strong>
                <span>{event.reason}</span>
                <time>{date(event.timestamp)}</time>
                <ArrowUpRight size={16} />
              </button>
            ))}
          </div>
        )}
        {[firewall.error, scanner.error, simulation.error]
          .filter(Boolean)
          .map((error, i) => (
            <ErrorState key={i} error={error} />
          ))}
      </Panel>
    </>
  );
}
