# Stage 6 — Neural Shield

Seven connected workspaces, using the existing FastAPI backend. No backend source,
policy, provider configuration, or database schema was changed for Stage 6.

## Run locally — Windows PowerShell

Prerequisites: Python 3.11+ and Node.js 24 with npm. Verification used Python 3.13.5,
Node 24.13.0, and npm 11.6.2. Keep the existing backend `.env` and virtual environment.
For a fresh checkout, follow the root README's Python installation steps first.

Backend terminal:

```powershell
Set-Location 'C:\Users\ASUS\OneDrive\hackathon\AgentGuard\backend'
$env:APP_ENVIRONMENT = 'local'
$env:SECURITY_DEV_ENDPOINTS = 'true'
$env:SIMULATION_ENABLED = 'true'
..\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload --no-access-log --no-proxy-headers
```

These existing opt-in flags expose the local demonstration endpoints. They do not
disable normal-agent authorization or scanning. Live simulations additionally
require `SIMULATION_LIVE_ENABLED=true` in `backend/.env` and working AI credentials.
Live mode is never automatically launched by the UI.

Frontend terminal:

```powershell
Set-Location 'C:\Users\ASUS\OneDrive\hackathon\AgentGuard\frontend'
npm.cmd ci
if (-not (Test-Path -LiteralPath .\.env)) {
    Copy-Item -LiteralPath .\.env.example -Destination .\.env
}
npm.cmd run dev
```

Open **http://127.0.0.1:5173/**. Backend documentation is at
http://127.0.0.1:8000/docs. Stop either foreground server with Ctrl+C. If a port is
already serving AgentGuard, use that server instead of launching a duplicate.

Frontend configuration:

```dotenv
VITE_API_BASE_URL=
AGENTGUARD_BACKEND_URL=http://127.0.0.1:8000
```

Leave `VITE_API_BASE_URL` empty for the supported local setup. Requests go to
`/api` on the frontend origin and through the guarded development proxy.
`AGENTGUARD_BACKEND_URL` is read only by Vite's server configuration. It must be a
loopback HTTP origin without credentials, path, query, or fragment.

**API keys belong only in `backend/.env` on `AI_API_KEY=`.** Never put credentials
in frontend files or any `VITE_*` variable: Vite variables are public bundle data.
The existing Groq/OpenAI-compatible adapter and model selection remain unchanged.

For a local production-build preview:

```powershell
npm.cmd run build
npm.cmd run preview
```

The preview is at http://127.0.0.1:4173/ and uses the same guarded local proxy.
This is not a production hosting or authentication solution.

## Features and evidence rules

- **Neural Overview:** draggable, zoomable React Flow topology, fit/reset/focus
  controls, keyboard node inspection, edge inspection, and real security totals.
  Stage 3 precedes execution; Stage 4 scans returned document/database content.
- **AI Agent:** real chat requests, persisted session selection and restoration,
  paginated history, tool arguments/results, correlated authorization and scans,
  and a compact selected-tool path. The response is rendered as safe text.
- **Security Firewall:** validated JSON request builder, real ALLOW/DENY reasons,
  policy posture and audit metadata. This calls evaluation only, never tool execution.
- **Injection Scanner:** five labeled sample inputs, actual heuristic scores,
  category/action indicators, and safe highlighting. Only valid original-view
  codepoint offsets are mapped, and only when the submitted text hash matches.
  Normalized/decoded offsets are kept separate. Match strength is not probability.
- **Attack Simulation:** registry details, explicit scripted/live selection,
  single-variant or paired launches, persisted history, cancellation, trace pages,
  side-by-side graphs, and separate scripted/live statistics. Admission captures
  the real run ID. Detail/trace polling stops at terminal state or four minutes;
  leaving the page cleans up subscriptions and timers. Resume polling is explicit.
- **Audit Explorer:** server-side decision, risk, tool, session and sort filters,
  pagination, current-page text search, and a dismissible event inspector.
- **System Status:** health, database, AI configuration and connection verification
  are separate. Feature probes use actual read endpoints; live admission is not inferred.

Graphs distinguish topology, historical evidence and current API status. Selection
animation is a visual focus aid, not traffic replay. Simulation graphs summarize
events in the loaded trace page. An attack objective can succeed because a forbidden
request was generated while execution was denied; confidential access, outbox
effects, denials and quarantines remain separate. Baseline resources are fictional
and sandbox-owned. Email delivery remains simulated everywhere.

The layout collapses its navigation on smaller screens, stacks comparisons and
keeps large tables in their own horizontal scroll regions. Motion respects the
system reduced-motion preference. React text rendering is used throughout; there
is no raw HTML rendering of prompts, documents, results or trace data.

## Local security boundary

FastAPI retains its existing local-only peer, Host and Origin checks. Before
proxying `/api`, Vite requires a loopback Host on port 5173/4173, absent or exact
same-origin Origin, and no cross-site Fetch Metadata. Only after that validation
does it translate Origin/Host to the loopback backend. Forwarded identity headers
are removed. Foreign-origin requests were verified to return HTTP 403.

No request carries provider credentials in the browser. Mutation retries are
disabled to avoid duplicate chat or simulation operations. Timeouts explain that
submitted work may still be running. Existing backend error codes are preserved;
non-JSON upstream errors become a generic safe message.

## API integration

All paths below are existing endpoints, verified against FastAPI OpenAPI and source.

- `GET /api/health`, `GET /api/system/status`
- `POST /api/agent/chat`
- `GET /api/agent/sessions`, `GET /api/agent/sessions/{session_id}`
- `POST /api/security/evaluate`
- `GET /api/security/events`, `GET /api/security/stats`, `GET /api/security/policies`
- `POST /api/security/injection/scan`
- `GET /api/security/injection/events`, `GET /api/security/injection/stats`
- `GET /api/simulation/scenarios`
- `POST /api/simulation/run`, `POST /api/simulation/compare`
- `GET /api/simulation/runs`, `GET /api/simulation/runs/{run_id}`
- `GET /api/simulation/runs/{run_id}/traces`
- `POST /api/simulation/runs/{run_id}/cancel`
- `GET /api/simulation/stats`

Event, scenario and scan inspectors use full records already returned by list
endpoints. No invented detail endpoint is required.

## Files created and modified

Created frontend source/configuration (the tree is also the complete new file inventory):

```text
frontend/
  .env.example
  package.json
  package-lock.json
  index.html
  dev-proxy.ts
  vite.config.ts
  vitest.config.ts
  tsconfig.json
  eslint.config.js
  public/shield.svg
  src/
    main.tsx
    App.tsx
    styles.css
    api/client.ts
    api/hooks.ts
    api/types.ts
    components/ui.tsx
    components/Inspector.tsx
    components/Shell.tsx
    components/SimulationResult.tsx
    components/SimulationStats.tsx
    graph/model.ts
    graph/NeuralCanvas.tsx
    pages/Overview.tsx
    pages/Agent.tsx
    pages/Firewall.tsx
    pages/Scanner.tsx
    pages/Simulations.tsx
    pages/Audit.tsx
    pages/System.tsx
    tests/setup.ts
    tests/client.test.ts
    tests/proxy.test.ts
    tests/evidence.test.tsx
    tests/firewall.test.tsx
    tests/simulations.test.tsx
```

Created `docs/stage6-frontend.md`. Modified `README.md` for Stage 6 setup and
architecture, and `.gitignore` to exclude TypeScript build cache. `node_modules`,
`dist`, local `.env`, databases and verification logs/screenshots are ignored.

Runtime dependencies: React/React DOM, React Router, `@xyflow/react`, Motion,
Lucide, TanStack Query, Recharts, Sonner, and locally bundled Inter.
Development dependencies: Vite/React plugin, TypeScript and React/Node types,
Tailwind/Vite plugin, ESLint/TypeScript/hooks/refresh integrations, Vitest,
jsdom and Testing Library. Exact versions and transitive dependencies are locked
in `package-lock.json`. No Python dependency changes were needed.

## Verification

```powershell
Set-Location 'C:\Users\ASUS\OneDrive\hackathon\AgentGuard\frontend'
npm.cmd run typecheck
npm.cmd run lint
npm.cmd test
npm.cmd run build
Set-Location ..
.\.venv\Scripts\python.exe -m pytest backend/app/tests -q
```

Stage 6 verification on 2026-10-29:

- TypeScript, lint and production build passed.
- 38 frontend tests passed: API payloads/errors/cancellation/timeouts, proxy origin
  restrictions, evidence interpretation, safe Unicode highlighting, form validation,
  comparison admission/polling/termination and rejected admission.
- Backend: **333 passed, 1 skipped**. The skipped filesystem test requires Windows
  symlink creation permission. Existing reparse/root-escape tests ran. One existing
  Starlette HTTPX deprecation warning remains.
- Production output scanned against the configured backend secret and common
  credential patterns: no matches. The check printed counts only, never secrets.

Browser/API checklist:

- [x] All seven pages load real backend data.
- [x] Real chat summarizes `project_report.txt`; one successful tool execution,
  one ALLOW audit and one content scan; reload restores the session.
- [x] Public document evaluation ALLOW; confidential document evaluation DENY.
- [x] Instruction override scan BLOCK, score 55, original-span highlight.
- [x] Eight scenarios load; explicit scripted comparison completes and updates history/statistics.
- [x] Comparison `07e76839-2300-4962-bd41-131e07ea8e85`: both objectives SUCCESS;
  baseline confidential access Yes, protected No; protected one denial and one
  critical quarantine. 34 persisted trace events are inspectable.
- [x] Audit DENY + read_document filtering, current-page search/empty state and inspector.
- [x] System reports actual backend/database health and configured-but-unverified AI.
- [x] Graph selection, zoom, fit, reset, focus; keyboard inspection and Escape dismissal.
- [x] Desktop, tablet and mobile layout checks; table scrolling remains contained.
- [x] Automated provider/network/rate-limit errors show errors, never successful fixtures.
- [x] Same-origin proxy requests succeed; foreign-origin proxy requests return 403.

No new live comparison was launched during Stage 6 verification: live requests
consume provider quota. The UI can inspect the existing live history and submit
an explicitly requested live run. Cancellation during a live request and touch
gestures on physical mobile hardware were not exercised manually.

## Limitations and scope

- Local demonstration UI, without production authentication or deployment.
- No streaming/event bus; status refresh and bounded simulation polling only.
- The status API always reports `connection_verified: false`; successful chat
  is separate evidence and does not alter that contract. Provider/model names
  are shown only where actual run metadata supplies them.
- Manual scanner source is fixed by the backend to `manual_test`.
- Audit text search covers the loaded page; backend-supported filters cover the dataset.
- Session security lists load up to 100 records, with five scan summaries shown.
  Missing correlations are labeled unavailable rather than inferred.
- Graph counts summarize the loaded trace page; they are not animation replays.
- Missing aggregate metrics are omitted; no unsupported security-effectiveness
  calculation or calibrated probability is claimed.
- Backend flags may intentionally restrict a feature; the UI shows the error and
  setup guidance without changing security configuration.
- Stages 7–10, approval workflows and real email delivery remain out of scope.
