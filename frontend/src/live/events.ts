// Sanitized live-stream envelope (backend app/security/stream.py, schema version 1).
// Every field is validated before use; anything unexpected is dropped, never rendered.
export const LIVE_EVENT_TYPES = [
  "FIREWALL_ALLOW",
  "FIREWALL_DENY",
  "CONTENT_SCANNED",
  "INJECTION_DETECTED",
  "CONTENT_FLAGGED",
  "CONTENT_REDACTED",
  "CONTENT_BLOCKED",
  "TOOL_EXECUTED",
  "TOOL_REJECTED",
  "TOOL_FAILED",
  "SIMULATION_STARTED",
  "SIMULATION_COMPLETED",
  "SIMULATION_FAILED",
  "SIMULATION_TRACE",
] as const;
export type LiveEventType = (typeof LIVE_EVENT_TYPES)[number];
export type LiveSeverity = "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type LiveSource = "firewall" | "scanner" | "gateway" | "simulation";
export type LiveCategory = "authorization" | "content" | "execution" | "simulation";
export interface LiveEvent {
  version: 1;
  id: string;
  cursor: string;
  sequence: number;
  event_type: LiveEventType;
  source: LiveSource;
  record_type: string;
  severity: LiveSeverity;
  summary: string;
  timestamp: string;
  session_id: string | null;
  correlation_id: string | null;
  is_simulation: boolean;
  metadata: Record<string, string | number | boolean | string[]>;
  /** Client-side only: loaded from bounded history rather than received live. */
  historical: boolean;
  receivedAt: number;
}
export const SEVERITIES: LiveSeverity[] = [
  "INFO",
  "LOW",
  "MEDIUM",
  "HIGH",
  "CRITICAL",
];
const SOURCES: LiveSource[] = ["firewall", "scanner", "gateway", "simulation"];
export const CURSOR = /^v1-\d{1,18}-\d{1,18}-\d{1,18}$/;

const isScalar = (v: unknown) =>
  typeof v === "string" || typeof v === "number" || typeof v === "boolean";

export function parseLiveEvent(
  raw: unknown,
  historical = false,
): LiveEvent | null {
  let value = raw;
  if (typeof raw === "string") {
    try {
      value = JSON.parse(raw);
    } catch {
      return null;
    }
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const e = value as Record<string, unknown>;
  if (
    e.version !== 1 ||
    typeof e.id !== "string" ||
    e.id.length > 120 ||
    typeof e.cursor !== "string" ||
    !CURSOR.test(e.cursor) ||
    typeof e.sequence !== "number" ||
    !LIVE_EVENT_TYPES.includes(e.event_type as LiveEventType) ||
    !SOURCES.includes(e.source as LiveSource) ||
    !SEVERITIES.includes(e.severity as LiveSeverity) ||
    typeof e.timestamp !== "string" ||
    Number.isNaN(Date.parse(e.timestamp)) ||
    typeof e.summary !== "string" ||
    !e.metadata ||
    typeof e.metadata !== "object" ||
    Array.isArray(e.metadata)
  )
    return null;
  const metadata: LiveEvent["metadata"] = {};
  for (const [key, item] of Object.entries(
    e.metadata as Record<string, unknown>,
  )) {
    if (isScalar(item)) metadata[key] = item as string | number | boolean;
    else if (Array.isArray(item) && item.every((x) => typeof x === "string"))
      metadata[key] = item.slice(0, 8) as string[];
  }
  return {
    version: 1,
    id: e.id,
    cursor: e.cursor,
    sequence: e.sequence,
    event_type: e.event_type as LiveEventType,
    source: e.source as LiveSource,
    record_type: typeof e.record_type === "string" ? e.record_type : "",
    severity: e.severity as LiveSeverity,
    summary: e.summary.slice(0, 240),
    timestamp: e.timestamp,
    session_id: typeof e.session_id === "string" ? e.session_id : null,
    correlation_id:
      typeof e.correlation_id === "string" ? e.correlation_id : null,
    is_simulation: e.is_simulation === true,
    metadata,
    historical,
    receivedAt: Date.now(),
  };
}

export function category(event: LiveEvent): LiveCategory {
  if (event.is_simulation || event.source === "simulation") return "simulation";
  return event.source === "firewall"
    ? "authorization"
    : event.source === "scanner"
      ? "content"
      : "execution";
}
export const meta = (event: LiveEvent, key: string) => {
  const value = event.metadata[key];
  return typeof value === "string" ? value : undefined;
};
export function eventTone(event: LiveEvent) {
  if (event.event_type === "FIREWALL_DENY" || event.event_type === "TOOL_REJECTED")
    return "danger";
  if (event.event_type === "CONTENT_BLOCKED")
    return ["HIGH", "CRITICAL"].includes(event.severity) ? "danger" : "warning";
  if (
    ["CONTENT_FLAGGED", "CONTENT_REDACTED", "INJECTION_DETECTED", "TOOL_FAILED", "SIMULATION_FAILED"].includes(
      event.event_type,
    ) ||
    meta(event, "status") === "quarantined"
  )
    return "warning";
  if (
    ["FIREWALL_ALLOW", "TOOL_EXECUTED", "CONTENT_SCANNED", "SIMULATION_COMPLETED"].includes(
      event.event_type,
    )
  )
    return "success";
  return event.is_simulation ? "cyan" : "neutral";
}
export const eventLabel = (type: LiveEventType) =>
  type.toLowerCase().replaceAll("_", " ");
