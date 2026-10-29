import { meta, type LiveEvent } from "./events";

export type NoticeLevel = "info" | "warning" | "critical";
export interface SecurityNotice {
  key: string;
  level: NoticeLevel;
  title: string;
  detail: string;
  event: LiveEvent;
  count: number;
  firstAt: number;
  lastAt: number;
  read: boolean;
}
export interface NoticeSnapshot {
  notices: SecurityNotice[];
  unread: number;
  muted: boolean;
}

/**
 * Severity comes from recorded evidence (decision + recorded risk), not from the event
 * name alone: a LOW/MEDIUM denial is a warning, not an incident. Returns null for events
 * that are not worth a notification (routine ALLOWs, safe scans, simulation step traces).
 */
export function classify(
  event: LiveEvent,
): { level: NoticeLevel; title: string } | null {
  const high = event.severity === "HIGH" || event.severity === "CRITICAL";
  const tool = meta(event, "tool_name") || meta(event, "source_tool") || "tool";
  if (event.is_simulation) {
    if (event.event_type === "SIMULATION_STARTED")
      return { level: "info", title: `Simulation started (${meta(event, "mode") || "unknown"} · ${meta(event, "variant")})` };
    if (event.event_type === "SIMULATION_COMPLETED")
      return { level: "info", title: `Simulation variant completed (${meta(event, "variant")})` };
    if (event.event_type === "SIMULATION_FAILED")
      return { level: "warning", title: `Simulation variant ended: ${meta(event, "execution_status") || "failed"}` };
    return null;
  }
  switch (event.event_type) {
    case "FIREWALL_DENY":
      return {
        level: high ? "critical" : "warning",
        title: `${tool} denied · ${meta(event, "policy_id") || "policy"}`,
      };
    case "CONTENT_BLOCKED":
      return {
        level: high ? "critical" : "warning",
        title: `${meta(event, "classification") || "Content"} blocked from ${tool}`,
      };
    case "CONTENT_REDACTED":
    case "CONTENT_FLAGGED":
    case "INJECTION_DETECTED":
      return {
        level: "warning",
        title: `${meta(event, "action") || "Flagged"}: suspicious content from ${tool}`,
      };
    case "TOOL_FAILED":
      return { level: "warning", title: `${tool} execution failed` };
    case "TOOL_EXECUTED":
      // The quarantine itself is reported by its scan event; avoid a duplicate alert.
      return meta(event, "status") === "succeeded"
        ? { level: "info", title: `${tool} executed after authorization` }
        : null;
    default:
      return null;
  }
}

const groupKey = (event: LiveEvent) =>
  [
    event.event_type,
    meta(event, "tool_name") || meta(event, "source_tool"),
    meta(event, "policy_id") || meta(event, "classification"),
    meta(event, "run_id"),
  ].join("|");

export class NotificationCenter {
  private notices: SecurityNotice[] = [];
  private muted = false;
  private snapshot: NoticeSnapshot = { notices: [], unread: 0, muted: false };
  private listeners = new Set<() => void>();
  private seen = new Set<string>();
  constructor(
    private readonly options: {
      max?: number;
      groupWindowMs?: number;
      toast?: (notice: SecurityNotice) => void;
      now?: () => number;
    } = {},
  ) {}
  getSnapshot = () => this.snapshot;
  subscribe = (listener: () => void) => {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  };
  /** Live events only; history never generates alerts. */
  ingest(event: LiveEvent) {
    if (event.historical || this.seen.has(event.id)) return;
    this.seen.add(event.id);
    if (this.seen.size > 2000) this.seen = new Set([...this.seen].slice(-1000));
    const result = classify(event);
    if (!result) return;
    const now = (this.options.now || Date.now)();
    const key = groupKey(event);
    const window = this.options.groupWindowMs ?? 15000;
    const existing = this.notices.find(
      (n) => n.key === key && now - n.lastAt < window,
    );
    if (existing) {
      // Grouped and rate limited: repeats update the count without another toast.
      Object.assign(existing, { count: existing.count + 1, lastAt: now, event, read: false });
      this.notices = [existing, ...this.notices.filter((n) => n !== existing)];
    } else {
      const notice: SecurityNotice = {
        key,
        level: result.level,
        title: result.title,
        detail: event.summary,
        event,
        count: 1,
        firstAt: now,
        lastAt: now,
        read: false,
      };
      this.notices = [notice, ...this.notices].slice(0, this.options.max ?? 50);
      if (!this.muted && result.level !== "info") this.options.toast?.(notice);
    }
    this.emit();
  }
  markRead(key?: string) {
    this.notices.forEach((n) => {
      if (!key || n.key === key) n.read = true;
    });
    this.emit();
  }
  clear() {
    this.notices = [];
    this.emit();
  }
  setMuted(muted: boolean) {
    this.muted = muted;
    this.emit();
  }
  private emit() {
    this.snapshot = {
      notices: this.notices.map((n) => ({ ...n })),
      unread: this.notices.filter((n) => !n.read).length,
      muted: this.muted,
    };
    this.listeners.forEach((l) => l());
  }
}
