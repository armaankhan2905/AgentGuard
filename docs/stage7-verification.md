# Stage 7 — Verification Report

Date: 2026-10-30 (backend timestamps are UTC). Environment: Windows 11; backend on
`127.0.0.1:8000` (local development routes and simulation enabled); Vite dev server on
`127.0.0.1:5173`; Groq through the OpenAI-compatible adapter (`openai/gpt-oss-20b`).
Browser testing used the Claude desktop app's built-in Chromium pane, through real page
loads, the real SSE connection and real backend writes.

**Status: PASS WITH LIMITATIONS.** All 16 completion criteria were met. The limitations
are listed at the end.

## Automated tests

| Command | Result |
|---|---|
| `.venv\Scripts\python.exe -m pytest backend/app/tests -q` | **355 passed, 1 skipped** (Stage 6: 333 + 1 skipped; 22 new). The skip is the existing Windows symlink-permission test. |
| `npm.cmd run typecheck` | 0 errors |
| `npm.cmd run lint` | 0 problems |
| `npm.cmd test` | **7 files, 66 passed** (Stage 6: 43; 22 in `live.test.tsx`; 1 in `proxy.test.ts`) |
| `npm.cmd run build` | Success |
| Bundle secret scan (counts only) | Configured key: 0 files; `gsk_`/`sk-` patterns: 0 files |

### Backend coverage (`backend/app/tests/test_stream.py`)

1. **Connection:** routes exist only with the local opt-in; remote peers and foreign
   `Origin` get 403. The stream returns `text/event-stream`, no-cache headers, a `ready`
   frame with `retry: 3000`, heartbeats, and a final `rotate`.
2. **Serialization:** firewall and scan envelopes match the committed records exactly,
   with no indicators or content.
3. **Commit visibility:** flushed-but-uncommitted rows are not streamed, rolled-back rows
   never are, and committed rows are.
4. **Recovery and ordering:** reconnecting with `Last-Event-ID` recovers 3 missed events
   exactly once, in order. Resuming from the last event re-sends nothing.
5. **Cursor validation:** malformed cursors (6 variants, both header and query) return
   400 `invalid_cursor`; an over-length cursor returns 422; a cursor ahead of the database
   is clamped with `cursor_reset`.
6. **Multiple clients:** two concurrent clients receive identical events.
7. **Resource bounds:**
   - Disconnecting or completing a stream releases its slot.
   - At capacity, the server returns 503 `stream_capacity`.
   - Batches are at most 100 per source, and the cursor covers every examined row.
   - History is bounded with no gap before the stream.
   - A synthetic 350-row burst arrives as 4 ordered batches.
8. **Redaction:** the configured secret, document and record content, email body and
   `<img` markup never appear in the stream. Unsafe labels become `unknown_tool`; a secret
   used as a label is redacted.
9. **Tool states:** each terminal tool status maps correctly. A pending execution holds
   the cursor until it is terminal; a stale pending row is skipped.
10. **Simulation:** traces stream labeled `is_simulation` with their mode. Recipients are
    omitted, and history includes lifecycle events only.
11. **Isolation:** a poll that raises yields `stream_error`, while firewall enforcement and
    the audit trail keep working and the slot is released.
12. **Settings:** invalid stream limits are rejected.

### Frontend coverage (`frontend/src/tests/live.test.tsx`)

1. **Parsing:** envelope validation drops 8 malformed or unknown message types; metadata
   is limited to scalars or string lists.
2. **Connection states:** CONNECTING → CONNECTED, subscribing from the history cursor.
3. **Duplicates:** history and live events merge without duplicates and keep their
   historical/live label.
4. **Robustness:** malformed messages are counted and ignored, and the view is bounded.
5. **Backoff:** reconnects resume from the last cursor, through RECONNECTING → ERROR →
   DISCONNECTED, with no retry loop afterwards and a working manual reconnect. Backoff
   bounds and jitter are checked.
6. **Recovery:** a server `rotate` resumes at once; the watchdog reconnects a silent
   connection.
7. **Disabled or released:** a 404 shows DISCONNECTED (disabled) without retries, and
   release closes the source.
8. **Notification levels:** taken from recorded evidence, for example a HIGH DENY is
   critical, a MEDIUM DENY is a warning, an ALLOW gets none, a quarantine is not
   duplicated, and simulation traces and sandbox decisions get none.
9. **Notification center:** deduplication, ×N grouping, a single toast per group,
   bounded history, unread/mark-read, mute and clear.
10. **Cache invalidation:** a 20-event burst triggers one invalidation per affected query
    and no counting. Simulation lifecycle events refresh the matching queries.
11. **Graph highlighting:**
    - A DENY lights no resource path.
    - Direct evaluations draw no agent path.
    - An ALLOW does not mark a tool executed; only TOOL_EXECUTED does.
    - Scans use the returned-content path; manual scans light no tool path.
    - Simulation events don't touch the operational graph.
12. **Reduced motion:** no animated edges when reduced motion is set.
13. **Activity feed:** newest first, severity filter, pause with a "1 new" count, resume,
    and a local clear.
14. **Inspector:** shows whether an event is history or live.
15. **Audit:** page 1 refetches in place; page 2 shows a "new events" banner without
    refetching; **Show newest** resets to page 1, newest first.
16. **Burst:** 1,000 events processed in under 3 s, a 200-event view, 3 invalidations,
    1 toast (×1000).
17. **Proxy:** the dev proxy closes the browser response when the backend aborts a stream
    (`proxy.test.ts`).

## Browser verification (real app, real backend)

| Check | How | Result |
|---|---|---|
| Stream opens | Overview load; network log | One `GET /api/security/stream?cursor=v1-55-9-296` after `/recent`. Command bar shows **Live stream**, separate from **Backend connected**. |
| Firewall DENY end to end | Real `POST /api/security/evaluate` (`confidential_strategy.txt`, decision `67b49c2d-7491-44bf-b92d-265af9b5cabe`) | Feed row "firewall deny · LIVE · HIGH" without reload. Metrics went from 34 · 16/18 to 35 · 16/19, equal to `/api/security/stats`. Unread count went to 1. A critical toast showed for about 4 s; the graph flashed for 6 s. |
| DENY graph | Pinned the CRITICAL email DENY (direct evaluation) | Firewall node DENY (danger); only `firewall-email` highlighted, "DENY · not executed"; caption "Denial recorded · DENY_EMAIL_RECIPIENT · direct evaluation, no agent". |
| ALLOW via the agent | One real chat: "Read project_report.txt and summarize it in one sentence." (session `693fee92-9265-4cea-be0c-27577a3185a1`, 2 Groq calls) | Feed: FIREWALL_ALLOW → TOOL_EXECUTED → CONTENT_SCANNED, all live. The ALLOW pins agent→gateway→firewall→document with the document **not** marked executed. TOOL_EXECUTED marks "Executed Document tool". The scan shows document→scanner→agent "returned content" / "handled result", SAFE · ALLOW. |
| Injection detection | Real manual scan of an override payload | CONTENT_BLOCKED live. The scanner node shows PROMPT_INJECTION · BLOCK (danger), captioned "Manual scan · no tool path involved", with no tool edges. |
| Inspector | Click feed rows | Inspector shows "Received live · firewall_decision_v1", or "Recorded history · …" after a reload. |
| Audit live update | Audit page 1, then a real CRITICAL path-traversal DENY | One in-place refetch; the new row is on top with "firewall-page test" as source. |
| Audit older page | Page 2, then 3 real DENYs | Banner "3 new authorization events recorded …"; stayed on Page 2; no refetch. |
| Notification center | Panel after the burst | "read_document denied · DENY_CONFIDENTIAL_DOCUMENTS ×3" (critical) and the path-variant denial; critical/info filters; mark all read cleared the badge; clicking opened the inspector. |
| Simulation lifecycle | Scripted comparison `b19d3d3b-c32f-4d48-b83c-08122dac0f69` (no provider calls) | RUNNING / "Live updates · stream" → 34 traces → COMPLETED / "Recorded run". Both variants SUCCESS (scripted; the objective was a request, not access). Requests: 2 run reads and 4 trace reads. |
| Replay | **Replay recorded trace** | Stepped 1/34 … 11/34 with the notice "Historical replay of the recorded trace … not live execution". |
| Reconnection | Stopped the backend for about 5 s, restarted, created a DENY while the browser was reconnecting | **Before the fix:** the dev proxy kept the browser side open, so the drop went unnoticed until the 45 s watchdog (both missed events were still recovered). **After the fix:** Live stream → RECONNECTING (3.0 s) → ERROR · retrying (4.8 s) → RECONNECTING → Live stream (12.8 s). The missed DENY arrived; 51/51 feed rows unique; "Backend connected" stayed independent. |
| Console and traffic | Reload, then visited all 7 pages | 0 errors, 0 warnings. 26 API requests for the full pass, with no request per heartbeat. |
| Security | Real SSE frames | Only whitelisted metadata. No arguments, results, content, indicators or recipients. Foreign `Origin` through the proxy gets 403. |

**Viewports.** Desktop (1024 px pane) was inspected by screenshot. New layout rules collapse
the feed row and hide the indicator label below 700 px. Stage 6's measured responsive
checks were not repeated at every size for the new panels.

## Bugs found and fixed during Stage 7

| Bug | Root cause | Fix | Regression test |
|---|---|---|---|
| A backend drop went unnoticed for up to 45 s | The Vite proxy did not end the browser response when the upstream SSE socket closed | `dev-proxy.ts` destroys the browser response when the upstream ends incomplete | `proxy.test.ts` "closes the browser response…"; verified live |
| History was flooded by simulation step traces (296) | `recent()` took the newest rows of every source | History keeps lifecycle traces only; the feed hides step traces unless "simulation" is selected | `test_simulation_traces_stream…` history assertion |
| Audit page 1 refetched once per event during bursts | Direct invalidation per event | 800 ms burst debounce | Covered by the Audit test path; verified live (1 refetch) |
| Mixed-encoding source files; two edits silently skipped (graph caption, footer text) | A cp1252 default in the helper script used for multi-line edits | Repaired byte-exact to UTF-8, re-applied both edits, verified every changed file is valid UTF-8 | Caption verified in the browser |
| `element.scrollTo` missing in jsdom | API not implemented there | Uses `scrollTop = 0` | `live.test.tsx` feed test |
| Running backend lacked the new routes | It was started without `--reload` | Restarted with `--timeout-graceful-shutdown 3`, now documented | n/a |

## Security checks

1. Confidential document contents: never streamed (envelope whitelist; tested with planted content).
2. API keys: the configured key appears in 0 stream frames (tested), 0 bundle files and 0 git history lines.
3. Database results, arguments and email bodies: omitted by construction (tested).
4. HTML: React text only; no `dangerouslySetInnerHTML`; a planted `<img onerror>` label is replaced.
5. No frontend feature calls a tool. The stream is GET-only, and no event triggers execution.
6. Audit persistence is unchanged; the forced stream failure left the audit intact (tested).
7. The stream follows the local development model: opt-in flags, loopback and same-origin
   checks, CORS limited to configured origins. It is not production authentication.

## Remaining limitations

- The stream is unauthenticated, like the whole local demonstration.
- Polling-based delivery, about 1 s.
- Single SQLite instance; the cursor assumes append-only rowid tables.
- The in-chat firewall DENY → `TOOL_REJECTED` path was not observed live, because the
  model refused before calling a tool in Stage 6. It is covered by backend and frontend
  unit tests.
- Live-mode simulation monitoring was not re-run (provider quota). The scripted run
  exercised the same stream path.
- Physical mobile devices, the OS reduced-motion toggle (covered by a unit test and CSS),
  and the 60 s hidden-tab pause were not exercised manually.
- Notifications and the feed are per tab and in memory, by design.

## Stage 8 readiness

Stage 7 is complete and ready to demonstrate. Stage 8 (human approval workflows) can
start; no approval actions were added here.
