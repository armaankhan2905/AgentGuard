import { useEffect, useMemo, useRef, useState } from "react";
import { AnimatePresence, motion } from "motion/react";
import { Bell, BellOff, Pause, Play, RotateCw, Trash2, X } from "lucide-react";
import {
  category,
  eventLabel,
  eventTone,
  meta,
  SEVERITIES,
  type LiveCategory,
  type LiveEvent,
} from "../live/events";
import { notifications, useNotifications, useStream } from "../live/hooks";
import type { NoticeLevel } from "../live/notifications";
import { securityStream, type StreamStatus } from "../live/stream";
import { useInspector } from "./Inspector";
import { Badge, date, Empty } from "./ui";

const statusText: Record<StreamStatus, string> = {
  CONNECTING: "Stream connecting",
  CONNECTED: "Live stream",
  RECONNECTING: "Stream reconnecting",
  DISCONNECTED: "Stream disconnected",
  ERROR: "Stream error · retrying",
};
export function StreamIndicator() {
  const stream = useStream();
  return (
    <span
      className={`stream-indicator ${stream.status}`}
      role="status"
      title={stream.reason}
      aria-label={`${statusText[stream.status]}: ${stream.reason}`}
    >
      <span className="status-dot" />
      <span>{statusText[stream.status]}</span>
    </span>
  );
}

export function inspectEvent(
  inspect: ReturnType<typeof useInspector>,
  event: LiveEvent,
) {
  inspect({
    title: eventLabel(event.event_type),
    kind: `${event.historical ? "Recorded history" : "Received live"} · ${event.record_type}`,
    description: event.summary,
    data: event,
  });
}

const levels: (NoticeLevel | "all")[] = ["all", "critical", "warning", "info"];
export function NotificationCenter() {
  const state = useNotifications();
  const [open, setOpen] = useState(false);
  const [level, setLevel] = useState<NoticeLevel | "all">("all");
  const inspect = useInspector();
  const visible = state.notices.filter(
    (n) => level === "all" || n.level === level,
  );
  return (
    <>
      <button
        className="notify-button"
        aria-label={`Security notifications, ${state.unread} unread`}
        aria-expanded={open}
        onClick={() => setOpen(!open)}
      >
        {state.muted ? <BellOff size={16} /> : <Bell size={16} />}
        {state.unread > 0 && (
          <span className="notify-count">
            {state.unread > 99 ? "99+" : state.unread}
          </span>
        )}
      </button>
      <AnimatePresence>
        {open && (
          <motion.section
            className="notify-panel panel"
            aria-label="Notification center"
            initial={{ opacity: 0, y: -6 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -6 }}
            onKeyDown={(e) => e.key === "Escape" && setOpen(false)}
          >
            <div className="panel-header">
              <div>
                <span className="eyebrow">LIVE · THIS BROWSER ONLY</span>
                <h2>Notifications</h2>
              </div>
              <button aria-label="Close notifications" onClick={() => setOpen(false)}>
                <X size={16} />
              </button>
            </div>
            <div className="notify-toolbar">
              <div className="segmented" aria-label="Notification severity">
                {levels.map((l) => (
                  <button key={l} aria-pressed={level === l} onClick={() => setLevel(l)}>
                    {l}
                  </button>
                ))}
              </div>
              <button onClick={() => notifications.markRead()}>Mark all read</button>
              <button
                aria-pressed={state.muted}
                onClick={() => notifications.setMuted(!state.muted)}
              >
                {state.muted ? "Unmute toasts" : "Mute toasts"}
              </button>
              <button onClick={() => notifications.clear()}>Clear</button>
            </div>
            <div className="notify-list">
              {visible.length ? (
                visible.map((n) => (
                  <button
                    key={n.key + n.firstAt}
                    className={`notify-item ${n.level} ${n.read ? "" : "unread"}`}
                    onClick={() => {
                      notifications.markRead(n.key);
                      inspectEvent(inspect, n.event);
                    }}
                  >
                    <i aria-hidden="true" />
                    <span>
                      <strong>
                        {n.title}
                        {n.count > 1 ? ` ×${n.count}` : ""}
                      </strong>
                      <small>{n.detail}</small>
                    </span>
                    <time>{date(n.event.timestamp)}</time>
                  </button>
                ))
              ) : (
                <Empty title="No notifications">
                  Alerts appear for important events received while this page is open.
                  Routine authorizations and safe scans stay in the activity feed.
                </Empty>
              )}
            </div>
          </motion.section>
        )}
      </AnimatePresence>
    </>
  );
}

const categories: (LiveCategory | "all")[] = [
  "all",
  "authorization",
  "content",
  "execution",
  "simulation",
];
export function LiveFeed({
  selected,
  onSelect,
}: {
  selected?: string;
  onSelect: (event: LiveEvent) => void;
}) {
  const stream = useStream();
  const [kind, setKind] = useState<LiveCategory | "all">("all");
  const [minimum, setMinimum] = useState(0);
  const [paused, setPaused] = useState<LiveEvent[] | null>(null);
  const list = useRef<HTMLDivElement>(null);
  const source = paused ?? stream.events;
  const rows = useMemo(
    () =>
      [...source]
        .reverse()
        .filter(
          (e) =>
            (kind === "all" || category(e) === kind) &&
            // Step-level simulation traces are only listed when asked for explicitly.
            (kind === "simulation" || e.event_type !== "SIMULATION_TRACE") &&
            SEVERITIES.indexOf(e.severity) >= minimum,
        ),
    [source, kind, minimum],
  );
  const waiting = paused
    ? stream.events.filter((e) => !paused.some((p) => p.id === e.id)).length
    : 0;
  const newest = stream.events.at(-1)?.id;
  useEffect(() => {
    // Following: keep the newest event in view as it arrives.
    if (!paused && list.current) list.current.scrollTop = 0;
  }, [newest, paused]);
  return (
    <div className="live-feed">
      <div className="feed-toolbar">
        <label>
          <span className="sr-only">Event category</span>
          <select value={kind} onChange={(e) => setKind(e.target.value as LiveCategory | "all")}>
            {categories.map((c) => (
              <option key={c} value={c}>
                {c === "all" ? "All categories" : c}
              </option>
            ))}
          </select>
        </label>
        <label>
          <span className="sr-only">Minimum severity</span>
          <select value={minimum} onChange={(e) => setMinimum(Number(e.target.value))}>
            {SEVERITIES.map((s, i) => (
              <option key={s} value={i}>
                {i ? `${s} and above` : "All severities"}
              </option>
            ))}
          </select>
        </label>
        <span className="spacer" />
        <button
          aria-pressed={!!paused}
          onClick={() => setPaused(paused ? null : stream.events)}
        >
          {paused ? <Play size={13} /> : <Pause size={13} />}
          {paused ? `Resume following${waiting ? ` (${waiting} new)` : ""}` : "Pause"}
        </button>
        <button
          onClick={() => {
            setPaused(null);
            securityStream.clear();
          }}
          title="Clears this browser's view; database records are not deleted."
        >
          <Trash2 size={13} />
          Clear view
        </button>
        {(stream.status === "DISCONNECTED" || stream.status === "ERROR") && (
          <button onClick={() => securityStream.reconnect()}>
            <RotateCw size={13} />
            Reconnect
          </button>
        )}
      </div>
      <div className="feed-list" ref={list} aria-live={paused ? "off" : "polite"}>
        {rows.length ? (
          rows.map((e) => (
            <button
              key={e.id}
              className={`feed-row ${e.historical ? "historical" : "live"} ${selected === e.id ? "selected" : ""}`}
              onClick={() => onSelect(e)}
            >
              <Badge tone={eventTone(e)}>{eventLabel(e.event_type)}</Badge>
              <strong className="mono">
                {meta(e, "tool_name") || meta(e, "source_tool") || meta(e, "trace_event_type") || e.source}
              </strong>
              <span>
                {e.summary}
                {e.session_id ? ` · session ${e.session_id.slice(0, 8)}` : ""}
              </span>
              <span className="live-tag">
                {e.historical ? "history" : "live"} · {e.severity}
              </span>
              <time>{date(e.timestamp)}</time>
            </button>
          ))
        ) : (
          <Empty title={stream.events.length ? "No events match these filters" : "No events yet"}>
            {stream.status === "CONNECTED"
              ? "Committed security records appear here as soon as the backend writes them."
              : stream.reason}
          </Empty>
        )}
      </div>
    </div>
  );
}
