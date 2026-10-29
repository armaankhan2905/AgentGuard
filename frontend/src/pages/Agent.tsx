import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useSearchParams } from "react-router-dom";
import { ArrowUp, Bot, Plus, Sparkles, Wrench } from "lucide-react";
import { toast } from "sonner";
import { api, ApiError } from "../api/client";
import type { Execution } from "../api/types";
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
import { NeuralCanvas } from "../graph/NeuralCanvas";
import { requestPathGraph } from "../graph/model";
const prompts = [
  "Summarize project_report.txt.",
  "Search the customer database for John.",
  "Attempt to read confidential_strategy.txt.",
];
export default function Agent() {
  const [params, setParams] = useSearchParams();
  const sessionId = params.get("session") || undefined;
  const [offset, setOffset] = useState(0);
  const [messageOffset, setMessageOffset] = useState(0);
  const [input, setInput] = useState("");
  const [selected, setSelected] = useState<Execution>();
  const query = useQueryClient();
  const inspect = useInspector();
  const sessions = useQuery({
    queryKey: ["sessions", offset],
    queryFn: ({ signal }) => api.sessions(offset, signal),
  });
  const session = useQuery({
    queryKey: ["session", sessionId, messageOffset],
    queryFn: ({ signal }) => api.session(sessionId!, messageOffset, signal),
    enabled: !!sessionId,
  });
  const events = useQuery({
    queryKey: ["session-events", sessionId],
    queryFn: ({ signal }) =>
      api.events({ session_id: sessionId, limit: 100 }, signal),
    enabled: !!sessionId,
  });
  const scans = useQuery({
    queryKey: ["session-scans", sessionId],
    queryFn: ({ signal }) => api.scans(sessionId, signal),
    enabled: !!sessionId,
  });
  const send = useMutation({
    mutationFn: ({ message, id }: { message: string; id?: string }) =>
      api.chat(message, id),
    onSuccess: (data) => {
      setParams({ session: data.session_id });
      setInput("");
      query.invalidateQueries();
      toast.success("Response received");
    },
    onError: (error) => {
      if (error instanceof ApiError && error.sessionId)
        setParams({ session: error.sessionId });
      query.invalidateQueries({ queryKey: ["sessions"] });
      toast.error("Message could not be completed");
    },
  });
  const security = selected?.result?.security;
  const decisionId =
    security && typeof security === "object" && !Array.isArray(security)
      ? security.decision_id
      : undefined;
  const event = events.data?.find((e) => e.decision_id === decisionId);
  const graph = useMemo(
    () => requestPathGraph(event, selected?.tool_name),
    [event, selected?.tool_name],
  );
  const choose = (id?: string) => {
    if (send.isPending) return;
    setParams(id ? { session: id } : {});
    setSelected(undefined);
    setMessageOffset(0);
    send.reset();
  };
  const messages =
    session.data?.messages.filter(
      (m) => m.role === "user" || m.role === "assistant",
    ) || [];
  return (
    <>
      <PageTitle
        eyebrow="02 / AGENT WORKSPACE"
        title="Intent into action."
        description="Talk to the real agent. Inspect every recorded tool request along the way."
      />
      <div className="chat-layout">
        <Panel
          className="session-panel"
          title="Conversations"
          actions={
            <button
              aria-label="New conversation"
              disabled={send.isPending}
              onClick={() => choose()}
            >
              <Plus size={17} />
            </button>
          }
        >
          {sessions.isPending ? (
            <Loading />
          ) : sessions.isError ? (
            <ErrorState
              error={sessions.error}
              retry={() => sessions.refetch()}
            />
          ) : (
            <>
              <div className="session-list">
                {sessions.data.length ? (
                  sessions.data.map((s) => (
                    <button
                      disabled={send.isPending}
                      className={sessionId === s.id ? "selected" : ""}
                      key={s.id}
                      onClick={() => choose(s.id)}
                    >
                      <span>{s.name || "Untitled conversation"}</span>
                      <small>{date(s.created_at)}</small>
                    </button>
                  ))
                ) : (
                  <Empty title="No conversations yet" />
                )}
              </div>
              <Pager
                offset={offset}
                size={30}
                count={sessions.data.length}
                onChange={setOffset}
              />
            </>
          )}
        </Panel>
        <section className="chat-panel panel" aria-label="AI conversation">
          <div className="panel-header">
            <div className="inline">
              <Bot className="violet" size={20} />
              <h2>Agent workspace</h2>
            </div>
            <Badge tone="violet">Real provider</Badge>
          </div>
          <div className="chat-messages" aria-live="polite">
            {!sessionId ? (
              <div className="chat-welcome">
                <div className="agent-orbit">
                  <Bot size={34} />
                </div>
                <div className="eyebrow">A PROTECTED CONVERSATION</div>
                <h2>
                  What would you like
                  <br />
                  to investigate?
                </h2>
                <p>
                  Ask about approved documents or synthetic records. Tool
                  requests always pass through the security gateway.
                </p>
              </div>
            ) : session.isPending ? (
              <Loading />
            ) : session.isError ? (
              <ErrorState
                error={session.error}
                retry={() => session.refetch()}
              />
            ) : messages.length ? (
              messages.map((m) => (
                <article className={`chat-message ${m.role}`} key={m.id}>
                  <span className="eyebrow">
                    {m.role === "user" ? "YOU" : "AGENTGUARD"}
                  </span>
                  <p>{m.content || "Requested a tool operation."}</p>
                  <small>{date(m.created_at)}</small>
                </article>
              ))
            ) : (
              <Empty title="No visible conversation messages">
                This session may have been created by a security evaluation.
              </Empty>
            )}
            {send.isPending && (
              <article className="chat-message assistant">
                <span className="eyebrow">PROCESSING YOUR REQUEST</span>
                <p>{send.variables.message}</p>
                <Loading />
              </article>
            )}
            {send.data &&
              send.data.session_id === sessionId &&
              !messages.some(
                (m) =>
                  m.role === "assistant" && m.content === send.data.response,
              ) && (
                <article className="chat-message assistant">
                  <span className="eyebrow">LATEST RESPONSE</span>
                  <p>{send.data.response}</p>
                </article>
              )}
            {send.error && <ErrorState error={send.error} />}
            {session.data && (
              <Pager
                offset={messageOffset}
                size={100}
                count={Math.max(
                  session.data.messages.length,
                  session.data.tool_executions.length,
                )}
                onChange={setMessageOffset}
              />
            )}
          </div>
          <div className="prompt-chips">
            {prompts.map((p) => (
              <button
                key={p}
                disabled={send.isPending}
                onClick={() => setInput(p)}
              >
                <Sparkles size={12} />
                {p}
              </button>
            ))}
          </div>
          <form
            className="composer"
            onSubmit={(e) => {
              e.preventDefault();
              if (input.trim() && !send.isPending)
                send.mutate({ message: input.trim(), id: sessionId });
            }}
          >
            <label className="sr-only" htmlFor="chat-input">
              Message to AgentGuard
            </label>
            <textarea
              id="chat-input"
              maxLength={4000}
              value={input}
              disabled={send.isPending}
              onChange={(e) => setInput(e.target.value)}
              placeholder="Ask AgentGuard…"
              rows={3}
            />
            <div>
              <small>{input.length}/4,000 · Email is always simulated</small>
              <button
                className="primary"
                type="submit"
                aria-label="Send message"
                disabled={!input.trim() || send.isPending}
              >
                <ArrowUp size={18} />
              </button>
            </div>
          </form>
        </section>
        <div className="chat-insights">
          <Panel title="Tool activity" kicker="RECORDED EXECUTIONS">
            <div className="tool-list">
              {session.data?.tool_executions.length ? (
                session.data.tool_executions.map((tool) => (
                  <button
                    key={tool.id}
                    className={selected?.id === tool.id ? "selected" : ""}
                    onClick={() => {
                      setSelected(tool);
                      inspect({
                        title: tool.tool_name,
                        kind: "Tool execution",
                        data: tool,
                      });
                    }}
                  >
                    <Wrench size={16} />
                    <span className="mono">{tool.tool_name}</span>
                    <Badge tone={decisionTone(tool.status)}>
                      {tool.status}
                    </Badge>
                  </button>
                ))
              ) : (
                <Empty title="No tool executions">
                  Conversation alone may not need a tool.
                </Empty>
              )}
            </div>
          </Panel>
          <Panel title="Recorded request path">
            <NeuralCanvas
              graph={graph}
              compact
              label={
                event
                  ? `${event.decision} · recorded authorization`
                  : "Select a tool · topology only"
              }
            />
            {selected && !event && (
              <Notice>
                No matching decision in the loaded audit page. No authorization
                state is inferred.
              </Notice>
            )}
          </Panel>
          <Panel title="Session security">
            <div className="panel-body">
              <p>
                {events.data
                  ? `${events.data.length} authorization records loaded`
                  : "Authorization records unavailable"}
              </p>
              <p>
                {scans.data
                  ? `${scans.data.length} scans loaded`
                  : "Scan records unavailable"}
              </p>
              {events.error && <ErrorState error={events.error} />}
              <div className="stack">
                {scans.data?.slice(0, 5).map((s) => (
                  <button
                    className="list-item"
                    key={s.scan_id}
                    onClick={() =>
                      inspect({
                        title: s.classification,
                        kind: "Content scan",
                        data: s,
                      })
                    }
                  >
                    <Badge tone={decisionTone(s.action)}>{s.action}</Badge>
                    <span>{s.source_tool}</span>
                  </button>
                ))}
              </div>
            </div>
          </Panel>
        </div>
      </div>
    </>
  );
}
