import { useCallback, useEffect, useRef, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Search, ArrowUpRight } from "lucide-react";
import { api } from "../api/client";
import { useInspector } from "../components/Inspector";
import type { LiveEvent } from "../live/events";
import { useLiveEvent } from "../live/hooks";
import {
  Badge,
  date,
  decisionTone,
  Empty,
  ErrorState,
  Loading,
  Pager,
  PageTitle,
  Panel,
} from "../components/ui";
const defaults = {
  decision: "",
  risk_level: "",
  tool: "",
  session_id: "",
  sort: "desc",
};
export default function Audit() {
  const [draft, setDraft] = useState(defaults);
  const [filters, setFilters] = useState(defaults);
  const [offset, setOffset] = useState(0);
  const [search, setSearch] = useState("");
  const [fresh, setFresh] = useState(0);
  const refresh = useRef<ReturnType<typeof setTimeout>>(undefined);
  useEffect(() => () => clearTimeout(refresh.current), []);
  const inspect = useInspector();
  const client = useQueryClient();
  const onNewest = offset === 0 && filters.sort === "desc";
  // Committed authorization records refresh page 1 in place (filters and the open
  // inspector are kept); on older pages they only raise an indicator, never a jump.
  useLiveEvent(
    useCallback(
      (event: LiveEvent) => {
        if (event.source !== "firewall") return;
        if (!onNewest) setFresh((n) => n + 1);
        else if (!refresh.current)
          // One refetch per burst, not one per event.
          refresh.current = setTimeout(() => {
            refresh.current = undefined;
            void client.invalidateQueries({ queryKey: ["audit-events", filters, 0] });
          }, 800);
      },
      [client, filters, onNewest],
    ),
  );
  const events = useQuery({
    queryKey: ["audit-events", filters, offset],
    queryFn: ({ signal }) =>
      api.events({ ...filters, limit: 20, offset }, signal),
  });
  const records = events.data?.filter((e) =>
    `${e.decision_id} ${e.reason} ${e.policy_id} ${e.tool_name}`
      .toLowerCase()
      .includes(search.toLowerCase()),
  );
  return (
    <>
      <PageTitle
        eyebrow="06 / SECURITY INVESTIGATION"
        title="Every decision leaves a trace."
        description="Inspect persisted authorization events. A denied attempt is not a successful breach."
      />
      <Panel className="audit-filters">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            setFilters(draft);
            setOffset(0);
            setFresh(0);
          }}
        >
          <label>
            Decision
            <select
              value={draft.decision}
              onChange={(e) => setDraft({ ...draft, decision: e.target.value })}
            >
              <option value="">All decisions</option>
              <option>ALLOW</option>
              <option>DENY</option>
            </select>
          </label>
          <label>
            Risk level
            <select
              value={draft.risk_level}
              onChange={(e) =>
                setDraft({ ...draft, risk_level: e.target.value })
              }
            >
              <option value="">All risks</option>
              {["LOW", "MEDIUM", "HIGH", "CRITICAL"].map((r) => (
                <option key={r}>{r}</option>
              ))}
            </select>
          </label>
          <label>
            Tool
            <select
              value={draft.tool}
              onChange={(e) => setDraft({ ...draft, tool: e.target.value })}
            >
              <option value="">All tools</option>
              {[
                "read_document",
                "search_database",
                "send_email",
                "unknown_tool",
              ].map((t) => (
                <option key={t}>{t}</option>
              ))}
            </select>
          </label>
          <label>
            Session UUID
            <input
              placeholder="All sessions"
              value={draft.session_id}
              pattern="[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
              onChange={(e) =>
                setDraft({ ...draft, session_id: e.target.value })
              }
            />
          </label>
          <label>
            Sort
            <select
              value={draft.sort}
              onChange={(e) => setDraft({ ...draft, sort: e.target.value })}
            >
              <option value="desc">Newest first</option>
              <option value="asc">Oldest first</option>
            </select>
          </label>
          <button className="primary">Apply filters</button>
        </form>
      </Panel>
      <Panel
        title="Authorization ledger"
        kicker="REAL AUDIT RECORDS"
        actions={
          <label className="search-field">
            <Search size={15} />
            <input
              aria-label="Search this audit page"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search this page…"
            />
          </label>
        }
      >
        {fresh > 0 && !onNewest && (
          <div className="new-events" role="status">
            <span>
              {fresh} new authorization {fresh === 1 ? "event" : "events"} recorded
              since you opened this page (before applying your filters)
            </span>
            <button
              className="text-button"
              onClick={() => {
                const next = { ...filters, sort: "desc" };
                setDraft(next);
                setFilters(next);
                setOffset(0);
                setFresh(0);
              }}
            >
              Show newest
            </button>
          </div>
        )}
        {events.isPending ? (
          <Loading />
        ) : events.isError ? (
          <ErrorState error={events.error} retry={() => events.refetch()} />
        ) : (
          <>
            <div className="table-scroll">
              <table>
                <thead>
                  <tr>
                    <th>Decision</th>
                    <th>Tool / policy</th>
                    <th>Risk</th>
                    <th>Reason</th>
                    <th>Recorded at</th>
                    <th>Inspect</th>
                  </tr>
                </thead>
                <tbody>
                  {records?.map((event) => (
                    <tr key={event.decision_id}>
                      <td>
                        <Badge tone={decisionTone(event.decision)}>
                          {event.decision}
                        </Badge>
                      </td>
                      <td>
                        <strong className="mono">{event.tool_name}</strong>
                        <small className="table-secondary">
                          {event.policy_id} ·{" "}
                          {event.metadata.source === "gateway"
                            ? "agent gateway"
                            : event.metadata.source === "development_test"
                              ? "firewall-page test"
                              : String(event.metadata.source ?? "unknown")}
                        </small>
                      </td>
                      <td>
                        <Badge tone={decisionTone(event.risk_level)}>
                          {event.risk_level}
                        </Badge>
                      </td>
                      <td className="reason-cell">{event.reason}</td>
                      <td>{date(event.timestamp)}</td>
                      <td>
                        <button
                          aria-label={`Inspect decision ${event.decision_id}`}
                          onClick={() =>
                            inspect({
                              title: `${event.decision} · ${event.tool_name}`,
                              kind: "Authorization event",
                              description: event.reason,
                              data: event,
                            })
                          }
                        >
                          <ArrowUpRight size={16} />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {!records?.length && (
                <Empty title="No matching decisions">
                  Adjust the backend filters or clear this page's text search.
                </Empty>
              )}
            </div>
            <Pager
              offset={offset}
              size={20}
              count={events.data.length}
              onChange={(next) => {
                setOffset(next);
                if (next === 0 && filters.sort === "desc") setFresh(0);
              }}
            />
          </>
        )}
      </Panel>
    </>
  );
}
