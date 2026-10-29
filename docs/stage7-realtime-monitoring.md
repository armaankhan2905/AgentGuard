# Stage 7 — Real-Time Security Monitoring

Stage 7 makes the Neural Shield frontend react to committed backend security records.
It adds one read-only Server-Sent Events (SSE) stream and a shared browser client. The
firewall, scanner, gateway, sandbox and every Stage 1–6 endpoint are unchanged.

## Architecture before Stage 7 (inspected)

| Record | Table | Written by | Commit point |
|---|---|---|---|
| Firewall decision | `security_events` (`event_type=firewall_decision_v1`) | `AuditService.record` | Own commit, **before** any tool effect |
| Injection scan | `security_events` (`injection_scan_v1`) | `record_scan` (flush only) | Committed with the tool execution, or by the manual scan endpoint |
| Tool execution | `tool_executions` | `ToolGateway.execute` | Inserted (flushed) pending, committed once with its terminal status |
| Simulation trace | `simulation_traces` | `TraceCollector.add` | One commit per trace row |
| Simulation run | `simulation_runs` | runner/engine | Updated in place (status changes) |

All IDs are UUIDs, and timestamps are application-set. No table had a sortable sequence
column. Nothing in the application deletes these rows. The database is SQLite only
(`Database.initialize` rejects other drivers). The local development routes are protected
by `require_local_development`, which checks for a loopback peer, a loopback `Host` and a
same-origin or absent `Origin`. There is no user authentication.

## Design

```
committed rows ──► security_events / tool_executions / simulation_traces  (source of truth)
                         │ read-only, own short session per poll
                         ▼
GET /api/security/stream (SSE, per-connection cursor poll, 1 s)  ─►  Vite proxy  ─►  EventSource
GET /api/security/stream/recent (bounded history + cursor)
                         ▼
SecurityStream (one shared client)
  → bounded event view (200) + duplicate filter
  → NotificationCenter (grouped, rate-limited, muteable)
  → debounced TanStack Query invalidation → authoritative REST aggregates re-read
  → Overview graph / activity feed, Audit page-1 refresh, Simulation run/trace refresh
```

- **No in-memory broker and no duplicate event store.** Each open stream polls the
  existing tables after its own cursor. Events are never buffered between polls, so
  nothing is lost when no browser is connected. Any process that commits to the same
  SQLite file is seen.
- **Cursor:** `v1-<security>-<tool>-<trace>`, one SQLite `rowid` per source table. These
  are rowid tables, and SQLite admits one writer at a time, so rowid order is commit order.
  No delete path exists. The cursor never uses UUIDs or timestamps. **No schema change was
  needed.** The documented assumption is that these tables stay append-only. Deleting the
  newest row of a table could let SQLite reuse that rowid.
- **Commit visibility:** reads use a separate session, so flushed but uncommitted rows and
  rolled-back rows are never seen. A tool execution that has committed but is not yet in a
  terminal state holds the tool cursor until it finishes (up to a 5-minute grace period).
  This way its final state is never skipped.
- **Ordering:** each source is delivered in commit order. Within a batch, sources are
  merged by timestamp, then source rank, then rowid (a deterministic k-way merge).
- **Isolation:** the stream only reads. A poll failure sends `stream_error` and ends that
  stream. It cannot affect authorization, scanning, execution or audit writes (tested by
  forcing the adapter to raise).

## Endpoints

Both endpoints exist only when `APP_ENVIRONMENT=local` and `SECURITY_DEV_ENDPOINTS=true`.
Both inherit the loopback and same-origin checks: remote peers and foreign `Origin`
headers get 403. CORS stays restricted to `CORS_ORIGINS`, with no wildcard.

### `GET /api/security/stream/recent?limit=1..100` (default 50)

Returns `{"version": 1, "cursor": "<cursor>", "events": [<envelope>, …]}` with events
oldest-first. The cursor is read **before** the history, so subscribing from it leaves no
gap and no overlap. History includes only simulation lifecycle traces (started, completed,
failed). Step-level traces come from the existing trace API, or arrive live.

### `GET /api/security/stream`

- Resume position: the `Last-Event-ID` header (sent automatically by browsers) takes
  precedence over the `?cursor=` query. With neither, the stream starts at the latest
  record. A malformed cursor returns 400 `invalid_cursor`; a cursor longer than 64
  characters returns 422. A cursor ahead of the database is clamped, with
  `cursor_reset: true`.
- Response: `text/event-stream`, `Cache-Control: no-cache, no-store`, `X-Accel-Buffering: no`.
- Frames, all with JSON `data`:

| `event:` | `id:` | Meaning |
|---|---|---|
| `ready` | cursor | First frame. `retry: 3000`, includes `resumed`, `cursor_reset`, `lifetime_seconds` |
| `security` | event cursor | One sanitized envelope |
| `heartbeat` | cursor | Every `STREAM_HEARTBEAT_SECONDS` |
| `rotate` | cursor | Lifetime reached; the client resumes immediately |
| `stream_error` | — | Poll failed; the client reconnects with backoff |

- Limits (all validated in `Settings`): `STREAM_POLL_SECONDS=1`,
  `STREAM_HEARTBEAT_SECONDS=15`, `STREAM_MAX_CONNECTIONS=16` (503 `stream_capacity` when
  full), `STREAM_MAX_LIFETIME_SECONDS=60`. Each poll reads at most 100 rows per source.
  The connection slot is released in the generator's `finally`, whether the client
  disconnects or the stream ends normally.

### Event envelope (version 1)

```json
{
  "version": 1,
  "id": "firewall:67b49c2d-7491-44bf-b92d-265af9b5cabe",
  "cursor": "v1-56-9-296",
  "sequence": 56,
  "stream": "security",
  "event_type": "FIREWALL_DENY",
  "source": "firewall",
  "record_type": "firewall_decision_v1",
  "severity": "HIGH",
  "summary": "read_document DENY: Confidential documents are not authorized for ordinary sessions.",
  "timestamp": "2026-10-29T22:26:22.104311Z",
  "session_id": "29b2cef0-…",
  "correlation_id": "67b49c2d-…",
  "is_simulation": false,
  "metadata": {"decision_id": "67b49c2d-…", "tool_name": "read_document", "decision": "DENY",
               "policy_id": "DENY_CONFIDENTIAL_DOCUMENTS", "risk_level": "HIGH", "origin": "development_test"}
}
```

Mapping from persisted records. Persisted `event_type` values are not renamed; the
original is exposed as `record_type`.

| Record | Stream `event_type` |
|---|---|
| firewall decision | `FIREWALL_ALLOW` / `FIREWALL_DENY` |
| scan, not detected | `CONTENT_SCANNED` |
| scan, detected, action ALLOW / FLAG / REDACT / BLOCK | `INJECTION_DETECTED` / `CONTENT_FLAGGED` / `CONTENT_REDACTED` / `CONTENT_BLOCKED` |
| tool `succeeded` / `quarantined` | `TOOL_EXECUTED` (`metadata.status` keeps the difference) |
| tool `rejected` | `TOOL_REJECTED` (not executed) |
| tool `failed` | `TOOL_FAILED` |
| trace `SIMULATION_STARTED` / `COMPLETED` / `FAILED` | same name |
| other traces | `SIMULATION_TRACE` (`metadata.trace_event_type`) |

`correlation_id` is the firewall decision ID for decisions, scans and executions, and the
run ID for traces. Simulation-sandbox firewall decisions are also written to
`security_events`; they carry `is_simulation: true` and never drive the operational graph
or alerts.

**Sanitization.** The envelope is built from a whitelist, never by passing records
through. It contains no tool arguments or results, no document or record content, no
scan indicators or evidence, no email recipients or bodies, and no trace details beyond
fixed labels. String labels must match `^[A-Za-z0-9_.:-]{1,80}$` or they are dropped
(an unknown tool becomes `unknown_tool`). Summaries are built from fixed templates plus
policy reasons, which are fixed server strings. The whole envelope then passes through
`SecretRedactor`.

## Frontend integration

| Module | Role |
|---|---|
| `src/live/events.ts` | Envelope types, strict validation (`parseLiveEvent`), categories, tones |
| `src/live/stream.ts` | `SecurityStream`: one reference-counted `EventSource`, states, cursor resume, backoff, watchdog, visibility |
| `src/live/notifications.ts` | `classify` (evidence-based levels) and `NotificationCenter` |
| `src/live/hooks.ts` | `useLiveMonitoring` (mounted once in the shell), `useStream`, `useLiveEvent`, debounced `createInvalidator` |
| `src/components/Live.tsx` | `StreamIndicator`, `NotificationCenter` panel, `LiveFeed` |
| `src/graph/model.ts` | `liveGraph(event)`: the path an event proves; `animateEdges` (reduced-motion aware) |

**Connection states.** The stream reports CONNECTING, CONNECTED, RECONNECTING,
DISCONNECTED or ERROR (ERROR from the third consecutive failure onward). It is shown
separately from backend API status in the command bar and on System Status. A stream
outage never marks the dashboard offline.

**Reconnection.** Every reconnect resumes from the last delivered cursor, so the backend
replays anything committed in between:
- **After a failure:** bounded exponential backoff, `min(30 s, 1 s · 2^n)` scaled by a
  random factor between 0.5 and 1. After 6 failures the state becomes DISCONNECTED,
  with a manual **Reconnect** button.
- **`rotate`** reconnects immediately.
- **Watchdog:** with no frame for 45 s, the client reconnects.
- **Hidden tab:** the client disconnects after 60 s hidden and resumes when visible.
- **`online` event:** triggers a reconnect.
- **Dev proxy:** the Vite proxy now ends the browser's response when the backend aborts
  mid-stream, so drops are noticed immediately.

**Graph.** Each new operational event highlights only what it proves, for 6 s; a clicked
feed event stays pinned. The latest event wins (one highlight at a time), using a node
pulse, tone colors, animated edges and a contextual caption.

| Event | What the graph shows |
|---|---|
| ALLOW / DENY | Firewall node state and the firewall→tool edge ("ALLOW · authorization" or "DENY · not executed"). The agent→gateway path appears only when `origin=gateway`. Direct Firewall-page evaluations are captioned "direct evaluation, no agent". |
| TOOL_EXECUTED | The tool node shows "Executed", or "Executed · quarantined". This is the only case that marks a tool. |
| Scans | tool→scanner→agent on the returned-content path, labeled "withheld from model" for BLOCK. Manual and history scans light only the scanner. |

Under `prefers-reduced-motion`, edges don't animate and CSS pulses are disabled.

**Metrics.** Events never increment counters. Each event maps to the REST queries it can
change. Those keys are invalidated after a 1.2 s trailing debounce, so a burst triggers
one refetch per query, and the authoritative endpoints (`/security/stats`,
`/injection/stats`, `/simulation/stats` and others) are read again. Values are therefore
identical after a reload.

**Notifications.** Only events received live produce notifications; history never does.
- **Critical:** a DENY or BLOCK with recorded risk HIGH or CRITICAL.
- **Warning:** a lower-risk DENY or BLOCK, flagged, redacted or detected content, a failed
  tool, or a failed simulation variant.
- **Info (center only, no toast):** a successful execution, or a simulation start or
  completion.
- **None:** routine ALLOWs, safe scans and simulation step traces.

Repeats of the same type, tool and policy within 15 s are grouped (×N) without another
toast. History is bounded to 50, with an unread count, severity filter, mark-read, clear,
and mute for toasts. There are no approval actions (Stage 8).

**Audit Explorer.** On page 1 sorted newest-first, new authorization records trigger a
debounced in-place refetch. Filters, pagination and an open inspector are kept. On other
pages or sort orders, a "N new authorization events" banner offers **Show newest**.

**Attack Simulation.** Stream events for the selected run invalidate its run and trace
queries. While the stream is connected, polling slows to a 10 s safety net, returning to
2–3 s if it drops. The run bar labels the update source. For finished runs, **Replay
recorded trace** steps through the persisted events at 450 ms each, labeled "Historical
replay … not live execution". No simulation is started automatically, and no provider
calls are made to animate anything.

## Security considerations and limitations

- The stream is **unauthenticated, like the rest of the local demonstration**. It is not
  production-secure. It is gated by the same opt-in local development flags and loopback
  checks as the other monitoring routes. Bind Uvicorn to `127.0.0.1`.
- Real-time delivery is polling-based. The latency is up to `STREAM_POLL_SECONDS` plus
  network time, measured at about 1 s.
- Up to 16 connections, each issuing one indexed query per second against SQLite.
  Multi-instance deployments on other databases would need a different cursor (Stage 10).
- The cursor relies on append-only rowid tables, which is documented above.
- Uvicorn waits for open streams on shutdown. Each stream ends within 60 s, and
  `--timeout-graceful-shutdown 3` makes Ctrl+C prompt.
- Browser-side views (feed, notifications) are per tab and in memory. Clearing them never
  deletes records.
- History shows the latest 50 events. Older records stay in the Audit Explorer and the
  REST APIs.

## Run and demonstrate

Backend (PowerShell):

```powershell
Set-Location 'C:\Users\ASUS\OneDrive\hackathon\AgentGuard\backend'
$env:APP_ENVIRONMENT = 'local'; $env:SECURITY_DEV_ENDPOINTS = 'true'; $env:SIMULATION_ENABLED = 'true'
..\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload --no-access-log --no-proxy-headers --timeout-graceful-shutdown 3
```

Frontend: `Set-Location ..\frontend; npm.cmd run dev`, then open http://127.0.0.1:5173/.

Demo script, with the Neural Overview open and the command bar showing **Live stream**:

1. In a second tab, evaluate `read_document` with `confidential_strategy.txt` on Security
   Firewall. The first tab gets a critical toast, a DENY row in the feed, a red firewall
   node with "DENY · not executed", and the totals update.
2. Scan the "Instruction override" sample on Injection Scanner. The scanner node shows
   PROMPT_INJECTION · BLOCK, labeled "Manual scan · no tool path".
3. Ask the AI Agent to summarize `project_report.txt` (one real chat). The feed shows
   FIREWALL_ALLOW, TOOL_EXECUTED and CONTENT_SCANNED. Click each one to pin its path.
4. Launch a scripted comparison in Attack Simulation. Status and traces update from the
   stream; then press **Replay recorded trace**.
5. Stop and restart the backend. The indicator goes RECONNECTING and back to Live stream,
   and anything recorded meanwhile appears.

## Tests

```powershell
.\.venv\Scripts\python.exe -m pytest backend/app/tests -q      # repo root
Set-Location frontend; npm.cmd run typecheck; npm.cmd run lint; npm.cmd test; npm.cmd run build
```

Stream tests are in `backend/app/tests/test_stream.py`, `frontend/src/tests/live.test.tsx`
and `frontend/src/tests/proxy.test.ts`. Results are in `docs/stage7-verification.md`.
