import { ApiError, request } from "../api/client";
import { CURSOR, parseLiveEvent, type LiveEvent } from "./events";

export type StreamStatus =
  | "CONNECTING"
  | "CONNECTED"
  | "RECONNECTING"
  | "DISCONNECTED"
  | "ERROR";
export interface StreamSnapshot {
  status: StreamStatus;
  reason: string;
  cursor: string | null;
  attempts: number;
  lastMessageAt: number | null;
  connectedAt: number | null;
  malformed: number;
  events: LiveEvent[];
}
interface Options {
  baseUrl?: string;
  maxEvents?: number;
  historyLimit?: number;
  maxAttempts?: number;
  watchdogMs?: number;
  hiddenPauseMs?: number;
  random?: () => number;
  createSource?: (url: string) => EventSource;
}
type Listener = () => void;
type EventListener = (event: LiveEvent) => void;

/** Bounded exponential backoff with full jitter in [50%, 100%] of the step. */
export const backoffDelay = (attempt: number, random = Math.random) =>
  Math.round(Math.min(30000, 1000 * 2 ** attempt) * (0.5 + random() / 2));

/**
 * One shared connection for the whole application. The backend is authoritative: this
 * client only mirrors committed records, keeps a bounded in-memory view and resumes from
 * the last delivered cursor, so a reconnect recovers events persisted while it was away.
 */
export class SecurityStream {
  private source: EventSource | null = null;
  private retryTimer: ReturnType<typeof setTimeout> | undefined;
  private watchdog: ReturnType<typeof setTimeout> | undefined;
  private hiddenTimer: ReturnType<typeof setTimeout> | undefined;
  private listeners = new Set<Listener>();
  private eventListeners = new Set<EventListener>();
  private seen = new Set<string>();
  private retained = 0;
  private generation = 0;
  private snapshot: StreamSnapshot = {
    status: "DISCONNECTED",
    reason: "Not started",
    cursor: null,
    attempts: 0,
    lastMessageAt: null,
    connectedAt: null,
    malformed: 0,
    events: [],
  };
  private readonly o: Required<Omit<Options, "createSource">> &
    Pick<Options, "createSource">;
  constructor(options: Options = {}) {
    this.o = {
      baseUrl: "",
      maxEvents: 200,
      historyLimit: 50,
      maxAttempts: 6,
      watchdogMs: 45000,
      hiddenPauseMs: 60000,
      random: Math.random,
      ...options,
    };
  }
  getSnapshot = () => this.snapshot;
  subscribe = (listener: Listener) => {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  };
  onEvent(listener: EventListener) {
    this.eventListeners.add(listener);
    return () => {
      this.eventListeners.delete(listener);
    };
  }
  /** Reference-counted: the connection opens for the first user and closes after the last. */
  retain() {
    this.retained += 1;
    if (this.retained === 1) {
      document.addEventListener("visibilitychange", this.visibility);
      window.addEventListener("online", this.online);
      void this.start();
    }
    return () => {
      this.retained = Math.max(0, this.retained - 1);
      if (!this.retained) {
        document.removeEventListener("visibilitychange", this.visibility);
        window.removeEventListener("online", this.online);
        this.stop("Stopped");
      }
    };
  }
  /** Manual reconnection; also leaves DISCONNECTED after the retry budget is exhausted. */
  reconnect() {
    this.update({ attempts: 0 });
    if (this.snapshot.cursor) this.open("CONNECTING");
    else void this.start();
  }
  /** Clears the local view only; persisted records are untouched. */
  clear() {
    this.update({ events: [] });
  }
  private async start() {
    const generation = ++this.generation;
    this.update({ status: "CONNECTING", reason: "Loading recent history" });
    try {
      const history = await request<{ cursor: string; events: unknown[] }>(
        `/security/stream/recent?limit=${this.o.historyLimit}`,
      );
      if (generation !== this.generation) return;
      if (!CURSOR.test(history.cursor)) throw new Error("invalid cursor");
      const events = history.events
        .map((e) => parseLiveEvent(e, true))
        .filter((e): e is LiveEvent => !!e);
      this.add(events, false);
      this.update({ cursor: history.cursor });
      this.open("CONNECTING");
    } catch (error) {
      if (generation !== this.generation) return;
      if (error instanceof ApiError && [403, 404].includes(error.status))
        this.update({
          status: "DISCONNECTED",
          reason:
            error.status === 404
              ? "Live stream routes are disabled on this backend."
              : "Live stream refused: use the local frontend origin.",
        });
      else this.fail("History unavailable");
    }
  }
  private open(status: StreamStatus) {
    this.close();
    const generation = ++this.generation;
    const cursor = this.snapshot.cursor;
    const url = `${this.o.baseUrl}/api/security/stream${cursor ? `?cursor=${encodeURIComponent(cursor)}` : ""}`;
    this.update({ status, reason: status === "CONNECTING" ? "Opening stream" : this.snapshot.reason });
    let source: EventSource;
    try {
      source = this.o.createSource
        ? this.o.createSource(url)
        : new EventSource(url);
    } catch {
      this.fail("Browser could not open the stream");
      return;
    }
    this.source = source;
    const live = (handler: (e: MessageEvent) => void) => (e: Event) => {
      if (generation === this.generation) handler(e as MessageEvent);
    };
    source.addEventListener(
      "ready",
      live((e) => {
        const data = this.json(e.data);
        this.touch();
        this.update({
          status: "CONNECTED",
          reason: data?.cursor_reset
            ? "Cursor was ahead of the database and was reset"
            : "Receiving committed events",
          attempts: 0,
          connectedAt: Date.now(),
          cursor: typeof data?.cursor === "string" && CURSOR.test(data.cursor) ? data.cursor : cursor,
        });
      }),
    );
    source.addEventListener(
      "security",
      live((e) => {
        this.touch();
        const event = parseLiveEvent(e.data);
        if (!event) {
          this.update({ malformed: this.snapshot.malformed + 1 });
          return;
        }
        this.add([event], true);
        this.update({ cursor: event.cursor });
      }),
    );
    source.addEventListener(
      "heartbeat",
      live((e) => {
        this.touch();
        const data = this.json(e.data);
        if (typeof data?.cursor === "string" && CURSOR.test(data.cursor))
          this.update({ cursor: data.cursor });
      }),
    );
    // The server ends each stream after a bounded lifetime; resume at once, no backoff.
    source.addEventListener(
      "rotate",
      live(() => this.open("CONNECTED")),
    );
    source.addEventListener(
      "stream_error",
      live(() => this.fail("Backend stream reported an error")),
    );
    source.onerror = live(() => this.fail("Connection lost"));
  }
  private json(data: unknown): Record<string, unknown> | null {
    try {
      const value = JSON.parse(String(data));
      return value && typeof value === "object" ? value : null;
    } catch {
      return null;
    }
  }
  private touch() {
    this.update({ lastMessageAt: Date.now() });
    clearTimeout(this.watchdog);
    this.watchdog = setTimeout(
      () => this.fail("No heartbeat received"),
      this.o.watchdogMs,
    );
  }
  private add(events: LiveEvent[], notify: boolean) {
    const fresh = events.filter((e) => !this.seen.has(e.id));
    if (!fresh.length) return;
    fresh.forEach((e) => this.seen.add(e.id));
    const merged = [...this.snapshot.events, ...fresh]
      .sort((a, b) => a.timestamp.localeCompare(b.timestamp) || a.sequence - b.sequence)
      .slice(-this.o.maxEvents);
    // Keep the duplicate filter bounded alongside the view.
    if (this.seen.size > this.o.maxEvents * 5)
      this.seen = new Set(merged.map((e) => e.id));
    this.update({ events: merged });
    if (notify) fresh.forEach((e) => this.eventListeners.forEach((l) => l(e)));
  }
  private fail(reason: string) {
    this.close();
    const attempts = this.snapshot.attempts + 1;
    if (attempts > this.o.maxAttempts) {
      this.update({ status: "DISCONNECTED", reason: `${reason}; retries exhausted`, attempts });
      return;
    }
    this.update({ status: attempts > 2 ? "ERROR" : "RECONNECTING", reason, attempts });
    const generation = this.generation;
    this.retryTimer = setTimeout(() => {
      if (generation !== this.generation) return;
      if (this.snapshot.cursor) this.open("RECONNECTING");
      else void this.start();
    }, backoffDelay(attempts - 1, this.o.random));
  }
  private close() {
    this.generation += 1;
    clearTimeout(this.retryTimer);
    clearTimeout(this.watchdog);
    this.source?.close();
    this.source = null;
  }
  private stop(reason: string) {
    this.close();
    clearTimeout(this.hiddenTimer);
    this.update({ status: "DISCONNECTED", reason, connectedAt: null });
  }
  private visibility = () => {
    clearTimeout(this.hiddenTimer);
    if (document.visibilityState === "hidden")
      this.hiddenTimer = setTimeout(
        () => this.stop("Paused while the tab is hidden"),
        this.o.hiddenPauseMs,
      );
    else if (this.snapshot.status === "DISCONNECTED") this.reconnect();
  };
  private online = () => {
    if (this.snapshot.status !== "CONNECTED") this.reconnect();
  };
  private update(patch: Partial<StreamSnapshot>) {
    this.snapshot = { ...this.snapshot, ...patch };
    this.listeners.forEach((l) => l());
  }
}

export const securityStream = new SecurityStream({
  baseUrl: (import.meta.env.VITE_API_BASE_URL || "").replace(/\/$/, ""),
});
