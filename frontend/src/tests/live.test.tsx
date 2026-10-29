import { act, fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api, ApiError, request } from "../api/client";
import { parseLiveEvent, type LiveEvent } from "../live/events";
import { affectedQueries, createInvalidator } from "../live/hooks";
import { classify, NotificationCenter } from "../live/notifications";
import { backoffDelay, securityStream, SecurityStream } from "../live/stream";
import { animateEdges, liveGraph, topology } from "../graph/model";
import { inspectEvent, LiveFeed } from "../components/Live";
import Audit from "../pages/Audit";

vi.mock("../api/client", async (original) => ({
  ...(await original<typeof import("../api/client")>()),
  request: vi.fn(),
  api: { events: vi.fn() },
}));

class FakeSource {
  static all: FakeSource[] = [];
  listeners: Record<string, ((e: MessageEvent) => void)[]> = {};
  onerror: (() => void) | null = null;
  closed = false;
  constructor(public url: string) {
    FakeSource.all.push(this);
  }
  addEventListener(type: string, fn: (e: MessageEvent) => void) {
    (this.listeners[type] ||= []).push(fn);
  }
  close() {
    this.closed = true;
  }
  emit(type: string, data: unknown) {
    const message = { data: typeof data === "string" ? data : JSON.stringify(data) } as MessageEvent;
    act(() => this.listeners[type]?.forEach((fn) => fn(message)));
  }
  fail() {
    act(() => this.onerror?.());
  }
}
const last = () => FakeSource.all[FakeSource.all.length - 1];

let seq = 0;
function envelope(over: Record<string, unknown> = {}, metadata: Record<string, unknown> = {}) {
  seq += 1;
  return {
    version: 1,
    id: `firewall:${seq}`,
    cursor: `v1-${seq}-0-0`,
    sequence: seq,
    event_type: "FIREWALL_DENY",
    source: "firewall",
    record_type: "firewall_decision_v1",
    severity: "HIGH",
    summary: "read_document DENY: Confidential documents are not authorized.",
    timestamp: new Date(Date.UTC(2026, 9, 30, 0, 0, seq)).toISOString(),
    session_id: "s-1",
    correlation_id: "d-1",
    is_simulation: false,
    metadata: { tool_name: "read_document", decision: "DENY", policy_id: "DENY_CONFIDENTIAL_DOCUMENTS",
      origin: "gateway", ...metadata },
    ...over,
  };
}
const live = (over?: Record<string, unknown>, metadata?: Record<string, unknown>) =>
  parseLiveEvent(envelope(over, metadata)) as LiveEvent;

async function connected(stream: SecurityStream, history: unknown[] = [], cursor = "v1-0-0-0") {
  vi.mocked(request).mockResolvedValueOnce({ cursor, events: history });
  const release = stream.retain();
  await act(async () => {});
  last().emit("ready", { cursor, cursor_reset: false });
  return release;
}
const make = (extra = {}) =>
  new SecurityStream({
    createSource: (url) => new FakeSource(url) as unknown as EventSource,
    random: () => 1,
    ...extra,
  });

beforeEach(() => {
  FakeSource.all = [];
  vi.mocked(request).mockReset();
});
afterEach(() => vi.useRealTimers());

describe("event parsing", () => {
  it("accepts the versioned envelope and drops malformed or unknown messages", () => {
    expect(live().event_type).toBe("FIREWALL_DENY");
    for (const bad of [
      "{not json",
      envelope({ version: 2 }),
      envelope({ event_type: "DELETE_EVERYTHING" }),
      envelope({ cursor: "1-2-3" }),
      envelope({ severity: "URGENT" }),
      envelope({ timestamp: "yesterday" }),
      envelope({ metadata: [] }),
      [],
    ])
      expect(parseLiveEvent(bad)).toBeNull();
  });
  it("keeps only scalar or string-list metadata", () => {
    const event = live({}, { nested: { x: 1 }, categories: ["A", 2], list: ["A", "B"] });
    expect(event.metadata.nested).toBeUndefined();
    expect(event.metadata.categories).toBeUndefined();
    expect(event.metadata.list).toEqual(["A", "B"]);
  });
});

describe("shared stream client", () => {
  it("moves CONNECTING → CONNECTED and subscribes from the history cursor", async () => {
    const stream = make();
    vi.mocked(request).mockResolvedValueOnce({ cursor: "v1-4-2-9", events: [] });
    const release = stream.retain();
    expect(stream.getSnapshot().status).toBe("CONNECTING");
    await act(async () => {});
    expect(last().url).toBe("/api/security/stream?cursor=v1-4-2-9");
    last().emit("ready", { cursor: "v1-4-2-9" });
    expect(stream.getSnapshot().status).toBe("CONNECTED");
    release();
  });
  it("merges history and live events without duplicates and marks their origin", async () => {
    const stream = make();
    const first = envelope();
    const release = await connected(stream, [first], first.cursor);
    const received: LiveEvent[] = [];
    stream.onEvent((e) => received.push(e));
    last().emit("security", first); // Already in history: suppressed.
    const second = envelope();
    last().emit("security", second);
    last().emit("security", second); // Duplicate delivery: suppressed.
    const { events, cursor } = stream.getSnapshot();
    expect(events.map((e) => [e.id, e.historical])).toEqual([[first.id, true], [second.id, false]]);
    expect(received.map((e) => e.id)).toEqual([second.id]);
    expect(cursor).toBe(second.cursor);
    release();
  });
  it("counts and ignores malformed messages", async () => {
    const stream = make();
    const release = await connected(stream);
    last().emit("security", "<script>alert(1)</script>");
    expect(stream.getSnapshot()).toMatchObject({ malformed: 1, events: [] });
    release();
  });
  it("bounds the in-memory view", async () => {
    const stream = make({ maxEvents: 3 });
    const release = await connected(stream);
    for (let i = 0; i < 5; i++) last().emit("security", envelope());
    expect(stream.getSnapshot().events).toHaveLength(3);
    release();
  });
  it("reconnects with backoff from the last delivered cursor, then gives up", async () => {
    vi.useFakeTimers();
    const stream = make({ maxAttempts: 3 });
    const release = await connected(stream);
    const event = envelope();
    last().emit("security", event);
    last().fail();
    expect(stream.getSnapshot().status).toBe("RECONNECTING");
    expect(FakeSource.all[0].closed).toBe(true);
    act(() => vi.advanceTimersByTime(backoffDelay(0, () => 1)));
    expect(last().url).toContain(`cursor=${event.cursor}`);
    last().fail();
    act(() => vi.advanceTimersByTime(backoffDelay(1, () => 1)));
    last().fail();
    expect(stream.getSnapshot().status).toBe("ERROR");
    act(() => vi.advanceTimersByTime(backoffDelay(2, () => 1)));
    last().fail();
    expect(stream.getSnapshot().status).toBe("DISCONNECTED");
    const opened = FakeSource.all.length;
    act(() => vi.advanceTimersByTime(60000));
    expect(FakeSource.all).toHaveLength(opened); // No retry loop after giving up.
    stream.reconnect();
    expect(FakeSource.all).toHaveLength(opened + 1);
    release();
  });
  it("bounds backoff with jitter", () => {
    expect(backoffDelay(0, () => 0)).toBe(500);
    expect(backoffDelay(0, () => 1)).toBe(1000);
    expect(backoffDelay(10, () => 1)).toBe(30000);
  });
  it("resumes immediately on server rotation and reconnects after a silent connection", async () => {
    vi.useFakeTimers();
    const stream = make({ watchdogMs: 1000 });
    const release = await connected(stream);
    last().emit("heartbeat", { cursor: "v1-7-0-0" });
    last().emit("rotate", { cursor: "v1-7-0-0" });
    expect(last().url).toContain("cursor=v1-7-0-0");
    expect(stream.getSnapshot().status).toBe("CONNECTED");
    last().emit("ready", { cursor: "v1-7-0-0" });
    act(() => vi.advanceTimersByTime(1001));
    expect(stream.getSnapshot()).toMatchObject({ status: "RECONNECTING", reason: "No heartbeat received" });
    release();
  });
  it("reports a disabled stream without retrying and cleans up on release", async () => {
    const stream = make();
    vi.mocked(request).mockRejectedValueOnce(new ApiError(404, "http_error", "Not found"));
    const release = stream.retain();
    await act(async () => {});
    expect(stream.getSnapshot()).toMatchObject({ status: "DISCONNECTED" });
    expect(stream.getSnapshot().reason).toMatch(/disabled/);
    expect(FakeSource.all).toHaveLength(0);
    release();
    const other = make();
    const done = await connected(other);
    done();
    expect(last().closed).toBe(true);
    expect(other.getSnapshot().status).toBe("DISCONNECTED");
  });
});

describe("notifications", () => {
  it("maps severity from recorded evidence, not event names", () => {
    expect(classify(live())?.level).toBe("critical");
    expect(classify(live({ severity: "MEDIUM" }))?.level).toBe("warning");
    expect(classify(live({ event_type: "FIREWALL_ALLOW", severity: "LOW" }))).toBeNull();
    expect(classify(live({ event_type: "CONTENT_BLOCKED", source: "scanner", severity: "MEDIUM" }))?.level).toBe("warning");
    expect(classify(live({ event_type: "CONTENT_SCANNED", source: "scanner", severity: "LOW" }))).toBeNull();
    expect(classify(live({ event_type: "TOOL_EXECUTED", source: "gateway", severity: "LOW" }, { status: "succeeded" }))?.level).toBe("info");
    expect(classify(live({ is_simulation: true, event_type: "SIMULATION_TRACE", source: "simulation" }))).toBeNull();
    expect(classify(live({ is_simulation: true, event_type: "FIREWALL_DENY" }))).toBeNull();
  });
  it("deduplicates, groups repeats, rate limits toasts, bounds history and tracks unread", () => {
    let now = 0;
    const toast = vi.fn();
    const center = new NotificationCenter({ toast, max: 2, now: () => now });
    const event = live();
    center.ingest(event);
    center.ingest(event);
    center.ingest({ ...event, historical: true, id: "history" });
    now = 1000;
    center.ingest(live());
    expect(toast).toHaveBeenCalledTimes(1);
    expect(center.getSnapshot().notices).toHaveLength(1);
    expect(center.getSnapshot().notices[0].count).toBe(2);
    center.ingest(live({ event_type: "CONTENT_FLAGGED", source: "scanner" }, { action: "FLAG", source_tool: "read_document" }));
    center.ingest(live({ event_type: "TOOL_FAILED", source: "gateway", severity: "MEDIUM" }));
    expect(center.getSnapshot().notices).toHaveLength(2);
    expect(center.getSnapshot().unread).toBe(2);
    center.markRead();
    expect(center.getSnapshot().unread).toBe(0);
    center.setMuted(true);
    center.ingest(live({ severity: "CRITICAL" }, { policy_id: "OTHER" }));
    expect(toast).toHaveBeenCalledTimes(3);
    center.clear();
    expect(center.getSnapshot().notices).toEqual([]);
  });
});

describe("authoritative metrics", () => {
  it("invalidates each affected query once per burst and never counts events", () => {
    vi.useFakeTimers();
    const client = { invalidateQueries: vi.fn() } as unknown as QueryClient;
    const invalidator = createInvalidator(client, 1000);
    for (let i = 0; i < 20; i++) invalidator.push(live());
    expect(client.invalidateQueries).not.toHaveBeenCalled();
    vi.advanceTimersByTime(1000);
    expect(vi.mocked(client.invalidateQueries).mock.calls.map((c) => c[0]?.queryKey)).toEqual([
      ["firewall-stats"], ["overview-events"], ["session-events"]]);
  });
  it("refreshes simulation lifecycle views from run events", () => {
    const sim = (type: string) =>
      live({ event_type: type, source: "simulation", is_simulation: true, severity: "INFO" }, { run_id: "r1" });
    expect(affectedQueries(sim("SIMULATION_TRACE"))).toEqual([["traces", "r1"], ["run", "r1"]]);
    expect(affectedQueries(sim("SIMULATION_COMPLETED"))).toEqual([
      ["traces", "r1"], ["run", "r1"], ["simulation-stats"], ["runs"]]);
    expect(affectedQueries(live({ event_type: "CONTENT_BLOCKED", source: "scanner" }))).toEqual([
      ["scan-stats"], ["session-scans"]]);
  });
});

describe("live graph", () => {
  const edge = (g: ReturnType<typeof topology>, id: string) => g.edges.find((e) => e.id === id);
  const node = (g: ReturnType<typeof topology>, id: string) => g.nodes.find((n) => n.id === id);
  it("shows a denial at the firewall without a successful path to the resource", () => {
    const { graph } = liveGraph(live());
    expect(node(graph, "firewall")?.data).toMatchObject({ state: "DENY", tone: "danger" });
    expect(edge(graph, "firewall-document")?.label).toBe("DENY · not executed");
    expect(edge(graph, "gateway-firewall")?.className).toContain("danger");
    expect(edge(graph, "document-resources")?.className).toBeUndefined();
    expect(node(graph, "document")?.data.tone).toBeUndefined();
  });
  it("does not invent an agent path for direct evaluations or execution for ALLOW", () => {
    const { graph, caption } = liveGraph(live({ event_type: "FIREWALL_ALLOW", severity: "LOW" }, { origin: "development_test", decision: "ALLOW" }));
    expect(edge(graph, "agent-gateway")?.className).toBeUndefined();
    expect(node(graph, "document")?.data.state).toBe("Topology");
    expect(caption).toMatch(/direct evaluation/);
  });
  it("marks a tool only when execution is recorded, and scans on the returned-content path", () => {
    const executed = liveGraph(live({ event_type: "TOOL_EXECUTED", source: "gateway", severity: "LOW" }, { status: "quarantined" })).graph;
    expect(node(executed, "document")?.data).toMatchObject({ state: "Executed · quarantined", tone: "warning" });
    const scan = liveGraph(live({ event_type: "CONTENT_BLOCKED", source: "scanner" }, { source_tool: "read_document", action: "BLOCK", classification: "PROMPT_INJECTION" })).graph;
    expect(edge(scan, "document-scanner")?.className).toContain("danger");
    expect(edge(scan, "scanner-agent")?.label).toBe("withheld from model");
    const manual = liveGraph(live({ event_type: "CONTENT_FLAGGED", source: "scanner" }, { source_tool: "manual_test", action: "FLAG" }));
    expect(manual.graph.edges.every((e) => !e.className)).toBe(true);
    expect(liveGraph(live({ is_simulation: true })).graph.edges.every((e) => !e.className)).toBe(true);
  });
  it("animates live edges only when motion is allowed", () => {
    const { graph } = liveGraph(live());
    expect(animateEdges(graph.edges, undefined, false).filter((e) => e.animated).length).toBeGreaterThan(0);
    expect(animateEdges(graph.edges, "firewall", true).some((e) => e.animated)).toBe(false);
  });
});

describe("activity feed, inspector and audit", () => {
  const add = (events: LiveEvent[], notify = true) =>
    act(() => (securityStream as unknown as { add: (e: LiveEvent[], n: boolean) => void }).add(events, notify));
  afterEach(() => act(() => securityStream.clear()));
  it("lists new events first, filters, pauses and clears locally", () => {
    const onSelect = vi.fn();
    render(<LiveFeed onSelect={onSelect} />);
    add([live({}, { tool_name: "read_document" })]);
    add([live({ event_type: "CONTENT_SCANNED", source: "scanner", severity: "LOW" }, { source_tool: "search_database" })]);
    const rows = () => screen.getAllByRole("button").filter((b) => b.classList.contains("feed-row"));
    expect(rows()[0]).toHaveTextContent("content scanned");
    fireEvent.change(screen.getByLabelText("Minimum severity"), { target: { value: "3" } });
    expect(rows()).toHaveLength(1);
    fireEvent.click(screen.getByRole("button", { name: /Pause/ }));
    add([live({ severity: "CRITICAL" }, { policy_id: "X" })]);
    expect(rows()).toHaveLength(1);
    expect(screen.getByRole("button", { name: /Resume following \(1 new\)/ })).toBeVisible();
    fireEvent.click(rows()[0]);
    expect(onSelect).toHaveBeenCalledWith(expect.objectContaining({ event_type: "FIREWALL_DENY" }));
    fireEvent.click(screen.getByRole("button", { name: /Clear view/ }));
    expect(rows()).toHaveLength(0);
  });
  it("inspects with the live/historical origin", () => {
    const inspect = vi.fn();
    inspectEvent(inspect, { ...live(), historical: true });
    expect(inspect.mock.calls[0][0].kind).toBe("Recorded history · firewall_decision_v1");
  });
  it("refreshes page one in place and only signals new events on older pages", async () => {
    vi.mocked(api.events).mockResolvedValue(
      Array.from({ length: 20 }, (_, i) => ({
        decision_id: `d${i}`, session_id: "s", tool_name: "read_document", decision: "DENY",
        risk_level: "HIGH", policy_id: "P", reason: "r", timestamp: "2026-10-30T00:00:00Z",
        arguments_summary: {}, metadata: { source: "gateway" },
      })),
    );
    render(
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <MemoryRouter>
          <Audit />
        </MemoryRouter>
      </QueryClientProvider>,
    );
    await screen.findAllByText("agent gateway", { exact: false });
    add([live()]);
    await vi.waitFor(() => expect(api.events).toHaveBeenCalledTimes(2));
    fireEvent.click(screen.getByRole("button", { name: "Next page" }));
    await vi.waitFor(() => expect(api.events).toHaveBeenCalledTimes(3));
    add([live()]);
    expect(await screen.findByText(/1 new authorization event recorded/)).toBeVisible();
    expect(api.events).toHaveBeenCalledTimes(3);
    fireEvent.click(screen.getByRole("button", { name: "Show newest" }));
    await vi.waitFor(() => expect(vi.mocked(api.events).mock.lastCall?.[0]).toMatchObject({ offset: 0, sort: "desc" }));
  });
});

describe("burst handling", () => {
  it("absorbs a 1,000-event burst with bounded memory, one refresh and grouped alerts", async () => {
    vi.useFakeTimers();
    const stream = make();
    vi.mocked(request).mockResolvedValueOnce({ cursor: "v1-0-0-0", events: [] });
    const release = stream.retain();
    await vi.advanceTimersByTimeAsync(0);
    last().emit("ready", { cursor: "v1-0-0-0" });
    const client = { invalidateQueries: vi.fn() } as unknown as QueryClient;
    const invalidator = createInvalidator(client, 1000);
    const toast = vi.fn();
    const center = new NotificationCenter({ toast });
    stream.onEvent((e) => {
      invalidator.push(e);
      center.ingest(e);
    });
    const started = performance.now();
    act(() => {
      for (let i = 0; i < 1000; i++)
        last().listeners.security.forEach((fn) => fn({ data: JSON.stringify(envelope()) } as MessageEvent));
    });
    expect(performance.now() - started).toBeLessThan(3000);
    expect(stream.getSnapshot().events).toHaveLength(200);
    vi.advanceTimersByTime(1000);
    expect(client.invalidateQueries).toHaveBeenCalledTimes(3);
    expect(toast).toHaveBeenCalledTimes(1);
    expect(center.getSnapshot().notices[0].count).toBe(1000);
    release();
  });
});
