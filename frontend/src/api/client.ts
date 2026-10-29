import type {
  Admission,
  ChatReply,
  FirewallEvent,
  FirewallStats,
  Health,
  Json,
  Mode,
  Policies,
  RunDetail,
  RunSummary,
  Scan,
  ScanStats,
  Scenario,
  Session,
  SessionDetail,
  SimulationStats,
  SystemStatus,
  Tool,
  Trace,
  Variant,
} from "./types";

const base = (import.meta.env.VITE_API_BASE_URL || "").replace(/\/$/, "");
export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
    public sessionId?: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}
export async function request<T>(
  path: string,
  options: { signal?: AbortSignal; body?: unknown; timeout?: number } = {},
): Promise<T> {
  const controller = new AbortController();
  const cancel = () => controller.abort();
  options.signal?.addEventListener("abort", cancel, { once: true });
  if (options.signal?.aborted) controller.abort();
  const timer = setTimeout(cancel, options.timeout ?? 15000);
  try {
    const response = await fetch(`${base}/api${path}`, {
      method: options.body === undefined ? "GET" : "POST",
      headers: {
        Accept: "application/json",
        ...(options.body === undefined
          ? {}
          : { "Content-Type": "application/json" }),
      },
      body:
        options.body === undefined ? undefined : JSON.stringify(options.body),
      signal: controller.signal,
      credentials: "omit",
    });
    const body = await response.json().catch(() => null);
    if (!response.ok)
      throw new ApiError(
        response.status,
        body?.error?.code || "http_error",
        body?.error?.message || `Request failed (${response.status}).`,
        body?.error?.session_id,
      );
    if (body === null)
      throw new ApiError(
        response.status,
        "invalid_response",
        "The backend returned an unreadable response.",
      );
    return body as T;
  } catch (error) {
    if (error instanceof ApiError) throw error;
    if (options.signal?.aborted)
      throw new DOMException("Request cancelled", "AbortError");
    throw new ApiError(
      0,
      controller.signal.aborted ? "timeout" : "network_error",
      controller.signal.aborted
        ? "The request timed out. A submitted operation may still be running; check its history before retrying."
        : "Backend unavailable. Check that FastAPI is running on localhost.",
    );
  } finally {
    clearTimeout(timer);
    options.signal?.removeEventListener("abort", cancel);
  }
}
export const queryString = (
  params: Record<string, string | number | undefined>,
) => {
  const q = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => {
    if (v !== undefined && v !== "") q.set(k, String(v));
  });
  return `?${q}`;
};
export const api = {
  health: (signal?: AbortSignal) => request<Health>("/health", { signal }),
  status: (signal?: AbortSignal) =>
    request<SystemStatus>("/system/status", { signal }),
  firewallStats: (signal?: AbortSignal) =>
    request<FirewallStats>("/security/stats", { signal }),
  policies: (signal?: AbortSignal) =>
    request<Policies>("/security/policies", { signal }),
  events: (
    params: Record<string, string | number | undefined> = {},
    signal?: AbortSignal,
  ) =>
    request<FirewallEvent[]>("/security/events" + queryString(params), {
      signal,
    }),
  evaluate: (tool_name: Tool, arguments_: Record<string, Json>) =>
    request<FirewallEvent>("/security/evaluate", {
      body: { tool_name, arguments: arguments_ },
    }),
  scan: (content: string) =>
    request<Scan>("/security/injection/scan", {
      body: { content, source: "manual_test" },
      timeout: 30000,
    }),
  scanStats: (signal?: AbortSignal) =>
    request<ScanStats>("/security/injection/stats", { signal }),
  scans: (session_id?: string, signal?: AbortSignal) =>
    request<Scan[]>(
      "/security/injection/events" + queryString({ session_id, limit: 100 }),
      { signal },
    ),
  sessions: (offset = 0, signal?: AbortSignal) =>
    request<Session[]>("/agent/sessions" + queryString({ limit: 30, offset }), {
      signal,
    }),
  session: (id: string, offset = 0, signal?: AbortSignal) =>
    request<SessionDetail>(
      `/agent/sessions/${id}` + queryString({ limit: 100, offset }),
      { signal },
    ),
  chat: (message: string, session_id?: string) =>
    request<ChatReply>("/agent/chat", {
      body: { message, ...(session_id ? { session_id } : {}) },
      timeout: 180000,
    }),
  scenarios: (signal?: AbortSignal) =>
    request<Scenario[]>("/simulation/scenarios", { signal }),
  scenario: (id: string, signal?: AbortSignal) =>
    request<Scenario>(`/simulation/scenarios/${id}`, { signal }),
  runs: (offset = 0, signal?: AbortSignal) =>
    request<RunSummary[]>(
      "/simulation/runs" + queryString({ limit: 20, offset }),
      { signal },
    ),
  run: (id: string, signal?: AbortSignal) =>
    request<RunDetail>(`/simulation/runs/${id}`, { signal }),
  launch: (scenario_id: string, mode: Mode, variant: Variant | "compare") =>
    request<Admission>(
      `/simulation/${variant === "compare" ? "compare" : "run"}`,
      {
        body: {
          scenario_id,
          mode,
          ...(variant === "compare" ? { compare: true } : { variant }),
        },
      },
    ),
  traces: (id: string, offset = 0, signal?: AbortSignal) =>
    request<Trace[]>(
      `/simulation/runs/${id}/traces` + queryString({ limit: 100, offset }),
      { signal },
    ),
  cancel: (id: string) =>
    request<{ cancel_requested: boolean }>(`/simulation/runs/${id}/cancel`, {
      body: {},
    }),
  simulationStats: (signal?: AbortSignal) =>
    request<SimulationStats>("/simulation/stats", { signal }),
};
