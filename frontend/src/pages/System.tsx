import { useQuery } from "@tanstack/react-query";
import {
  Activity,
  Database,
  Bot,
  ShieldCheck,
  FlaskConical,
  ScanLine,
} from "lucide-react";
import { api } from "../api/client";
import { useSystem, usePolicies, useScanStats } from "../api/hooks";
import {
  Badge,
  ErrorState,
  JsonDetails,
  Notice,
  PageTitle,
  Panel,
} from "../components/ui";
export default function System() {
  const status = useSystem();
  const health = useQuery({
    queryKey: ["health"],
    queryFn: ({ signal }) => api.health(signal),
  });
  const policies = usePolicies();
  const scans = useScanStats();
  const scenarios = useQuery({
    queryKey: ["scenarios"],
    queryFn: ({ signal }) => api.scenarios(signal),
  });
  const systems = [
    {
      name: "FastAPI backend",
      Icon: Activity,
      state: health.isError
        ? "Unavailable"
        : health.data
          ? "Healthy"
          : "Checking",
      ok: !health.isError && !!health.data,
      detail: "Current health endpoint response.",
    },
    {
      name: "SQLite database",
      Icon: Database,
      state: status.isError
        ? "Unavailable"
        : status.data
          ? status.data.database.connected
            ? "Connected"
            : "Disconnected"
          : "Checking",
      ok: !status.isError && status.data?.database.connected,
      detail: "Connectivity reported by the backend.",
    },
    {
      name: "AI provider configuration",
      Icon: Bot,
      state: status.isError
        ? "Unavailable"
        : status.data
          ? status.data.ai_provider.configured
            ? "Configured"
            : "Not configured"
          : "Checking",
      ok: !status.isError && status.data?.ai_provider.configured,
      detail: "Presence of configuration; not proof of API connectivity.",
    },
  ];
  return (
    <>
      <PageTitle
        eyebrow="07 / SYSTEM DIAGNOSTICS"
        title="Know the actual state."
        description="Current API responses, feature availability, and verification boundaries."
        actions={<Badge>Local frontend</Badge>}
      />
      <div className="system-grid">
        {systems.map(({ name, Icon, state, ok, detail }) => (
          <Panel key={name}>
            <div className="system-card">
              <Icon size={28} />
              <Badge
                tone={
                  ok ? "success" : state === "Checking" ? "neutral" : "warning"
                }
              >
                {state}
              </Badge>
              <h2>{name}</h2>
              <p>{detail}</p>
            </div>
          </Panel>
        ))}
      </div>
      {status.error && (
        <ErrorState error={status.error} retry={() => status.refetch()} />
      )}
      <div className="two-columns">
        <Panel
          title="Provider verification"
          kicker="CONFIGURATION ≠ CONNECTION"
        >
          <div className="panel-body">
            <Badge tone="warning">
              {status.isError ? "Unavailable" : "Not verified by status API"}
            </Badge>
            <p>
              The backend reports <code>connection_verified: false</code>. This
              field is not an active provider probe. A successful chat is
              separate evidence of connectivity at that time.
            </p>
            <Notice>
              No credentials are sent to this frontend. Provider and model
              identity are not exposed by this endpoint; recorded live runs may
              contain model metadata.
            </Notice>
          </div>
        </Panel>
        <Panel title="Application identity">
          <div className="panel-body">
            <dl className="facts">
              <dt>Application</dt>
              <dd>{health.data?.application || "Unavailable"}</dd>
              <dt>API version</dt>
              <dd>{status.data?.version || "Unavailable"}</dd>
              <dt>Frontend environment</dt>
              <dd>Local development</dd>
              <dt>Backend environment</dt>
              <dd>Not exposed by status endpoint</dd>
              <dt>Last response</dt>
              <dd>
                {status.dataUpdatedAt
                  ? new Date(status.dataUpdatedAt).toLocaleTimeString()
                  : "Unavailable"}
              </dd>
            </dl>
            <JsonDetails value={status.data || null} />
          </div>
        </Panel>
      </div>
      <Panel title="Feature availability" kicker="READ-ONLY CAPABILITY CHECKS">
        <div className="feature-list">
          {[
            { name: "Security firewall", Icon: ShieldCheck, q: policies },
            { name: "Injection scanning", Icon: ScanLine, q: scans },
            { name: "Attack simulation", Icon: FlaskConical, q: scenarios },
          ].map(({ name, Icon, q }) => (
            <div key={name}>
              <Icon size={22} />
              <strong>{name}</strong>
              <Badge
                tone={q.isError ? "warning" : q.data ? "success" : "neutral"}
              >
                {q.isError
                  ? "Unavailable / restricted"
                  : q.data
                    ? "Endpoint accessible"
                    : "Checking"}
              </Badge>
              {q.error && (
                <ErrorState error={q.error} retry={() => q.refetch()} />
              )}
            </div>
          ))}
        </div>
        <div className="panel-body">
          <Notice>
            Accessible simulation endpoints do not imply live mode is enabled.
            The backend checks that setting when a live run is explicitly
            submitted. No paid connectivity probe runs on this page.
          </Notice>
        </div>
      </Panel>
    </>
  );
}
