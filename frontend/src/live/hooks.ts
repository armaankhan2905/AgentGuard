import { useEffect, useSyncExternalStore } from "react";
import type { QueryClient, QueryKey } from "@tanstack/react-query";
import { toast } from "sonner";
import { category, meta, type LiveEvent } from "./events";
import { NotificationCenter } from "./notifications";
import { securityStream, type SecurityStream } from "./stream";

export const notifications = new NotificationCenter({
  toast: (notice) =>
    (notice.level === "critical" ? toast.error : toast.warning)(notice.title, {
      description: notice.detail,
      id: notice.key,
    }),
});

export const useStream = (stream: SecurityStream = securityStream) =>
  useSyncExternalStore(stream.subscribe, stream.getSnapshot);
export const useNotifications = () =>
  useSyncExternalStore(notifications.subscribe, notifications.getSnapshot);

/** Query keys whose authoritative backend values an event can change (never counters). */
export function affectedQueries(event: LiveEvent): QueryKey[] {
  const keys: QueryKey[] = [];
  const kind = category(event);
  if (event.source === "firewall")
    keys.push(["firewall-stats"], ["overview-events"], ["session-events"]);
  if (kind === "content") keys.push(["scan-stats"], ["session-scans"]);
  if (kind === "execution") keys.push(["session"], ["sessions"]);
  if (kind === "simulation" && meta(event, "run_id")) {
    const run = meta(event, "run_id");
    keys.push(["traces", run], ["run", run]);
    if (event.event_type !== "SIMULATION_TRACE")
      keys.push(["simulation-stats"], ["runs"]);
  }
  return keys;
}

/**
 * Trailing debounce: an event burst becomes one refetch per affected query. Heartbeats
 * never reach here, and duplicate deliveries are filtered by the stream before this runs.
 */
export function createInvalidator(client: QueryClient, delay = 1200) {
  const pending = new Map<string, QueryKey>();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const flush = () => {
    timer = undefined;
    const keys = [...pending.values()];
    pending.clear();
    keys.forEach((queryKey) => void client.invalidateQueries({ queryKey }));
  };
  return {
    push(event: LiveEvent) {
      affectedQueries(event).forEach((k) => pending.set(JSON.stringify(k), k));
      if (pending.size && !timer) timer = setTimeout(flush, delay);
    },
    cancel() {
      clearTimeout(timer);
      pending.clear();
    },
  };
}

/** Mount once (in the shell): opens the shared connection and wires side effects. */
export function useLiveMonitoring(client: QueryClient, stream = securityStream) {
  useEffect(() => {
    const release = stream.retain();
    const invalidator = createInvalidator(client);
    const off = stream.onEvent((event) => {
      invalidator.push(event);
      notifications.ingest(event);
    });
    return () => {
      off();
      invalidator.cancel();
      release();
    };
  }, [client, stream]);
}

/** Subscribe a component to newly received events (cleaned up on unmount). */
export function useLiveEvent(
  handler: (event: LiveEvent) => void,
  stream = securityStream,
) {
  useEffect(() => stream.onEvent(handler), [handler, stream]);
}
