# AgentGuard — AI Firewall for Autonomous AI Agents

**Stage 4: prompt-injection scanning.** Stage 1 health/status contracts, safe logging,
and existing database records are preserved. Version remains `0.1.0` to preserve
the Stage 1 API contract.

The agent uses a real configurable LLM API, persists conversations, and routes
every tool call through `ToolGateway`. Its tools read approved fictional
documents, search synthetic SQLite records, and save simulated emails. No real
email delivery, arbitrary code/command execution, frontend, attack simulator,
or approval workflow is implemented.

Every tool request now passes through a default-deny firewall with server-owned
policies and a committed security audit before execution. See
[the Stage 3 guide](docs/stage3-security.md) for policy configuration, local
monitoring, Swagger examples, verification, and limitations.

Stage 4 adds bounded, heuristic scanning after authorized document/database reads
and before persistence or model context. Critical content is quarantined;
reliable original-text redaction preserves safe surrounding lines. See the
[Stage 4 guide](docs/stage4-injection.md) for scoring, examples, optional classifier
configuration, scan APIs, limitations, and the file inventory. The Stage 3 firewall
remains the final authority for every tool call. No complete injection protection
or calibrated detection accuracy is claimed.

## Windows PowerShell setup

Install Python **3.11+**, with `python` on PATH. From the project root:

```powershell
Set-Location 'C:\Users\ASUS\OneDrive\hackathon\AgentGuard'
python --version
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r .\backend\requirements.txt
if (-not (Test-Path -LiteralPath .\backend\.env)) {
    Copy-Item -LiteralPath .\backend\.env.example -Destination .\backend\.env
}
```

For an existing installation, retain `.venv` and `.env`, run the dependency
installation command, and copy desired new settings from `.env.example`.
No new dependencies were added; HTTPX now also provides the LLM adapter.

Edit `backend/.env` for live chat:

```dotenv
AI_PROVIDER=openai
AI_MODEL=your-chat-completions-tool-calling-model-id
AI_API_KEY=your-real-key-here
AI_BASE_URL=
```

These are placeholders, not working credentials. Choose a model your provider
supports for **Chat Completions with function tools**. For another compatible
provider, use `AI_PROVIDER=openai-compatible` and set `AI_BASE_URL` to its API
root, including `/v1` if needed. HTTPS is required except for loopback development
endpoints. The adapter sends `max_completion_tokens`, `parallel_tool_calls`, and
function tools; it does not translate provider-specific protocols.

The adapter follows the assistant/tool-result exchange in the
[official OpenAI function-calling documentation](https://developers.openai.com/api/docs/guides/function-calling).
Keys go in authorization headers, never in prompts. Redirects, automatic retries,
and environment proxy inheritance are disabled.

Start the backend:

```powershell
Set-Location .\backend
..\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload --no-access-log --no-proxy-headers
```

Stop with **Ctrl+C**. No virtual-environment activation or execution-policy change
is required. Change the initial path for another checkout location.
[Swagger UI](http://127.0.0.1:8000/docs) documents the endpoints.
Without credentials, health/status/session reads still work; chat returns 503
with `ai_not_configured`. There is no fake fallback agent.

Enter the API key locally on the `AI_API_KEY=` line in `backend/.env`, never in
`.env.example` or chat. The example file supplies `AI_PROVIDER=openai` and the
`gpt-4.1-mini` model, whose
[official model documentation](https://developers.openai.com/api/docs/models/gpt-4.1-mini)
lists Chat Completions and function-calling support. Account/model access still
requires a live check. Preserve your existing `.env`; edit the required lines
instead of overwriting it with the example. Restart the backend after saving
changes because its settings are loaded when the application starts. Existing
process environment variables, even empty ones, take precedence over `.env`.

## Try the API

In a second PowerShell terminal:

```powershell
Invoke-RestMethod 'http://127.0.0.1:8000/api/health' | ConvertTo-Json -Depth 10
Invoke-RestMethod 'http://127.0.0.1:8000/api/system/status' | ConvertTo-Json -Depth 10

$chatBody = @{ message = 'Summarize project_report.txt' } | ConvertTo-Json
$chat = Invoke-RestMethod -Method Post -Uri 'http://127.0.0.1:8000/api/agent/chat' -ContentType 'application/json' -Body $chatBody
$chat | ConvertTo-Json -Depth 10

$followupBody = @{ session_id = $chat.session_id; message = 'Search the database for Aurora projects' } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri 'http://127.0.0.1:8000/api/agent/chat' -ContentType 'application/json' -Body $followupBody | ConvertTo-Json -Depth 10

$emailBody = @{ session_id = $chat.session_id; message = 'Simulate an email to mira@example.test with subject Aurora update and a short summary.' } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri 'http://127.0.0.1:8000/api/agent/chat' -ContentType 'application/json' -Body $emailBody | ConvertTo-Json -Depth 10

Invoke-RestMethod 'http://127.0.0.1:8000/api/agent/sessions?limit=50&offset=0' | ConvertTo-Json -Depth 10
Invoke-RestMethod "http://127.0.0.1:8000/api/agent/sessions/$($chat.session_id)" | ConvertTo-Json -Depth 10
```

`POST /api/agent/chat` accepts an optional UUID `session_id` and a nonblank
`message` up to 4,000 characters. It returns `session_id`, final `response`, and
`tool_calls`: persisted execution IDs, safe argument summaries, statuses, results,
and timestamps. An ordinary conversation returns an empty `tool_calls` list.
Rejected tools are audited and their errors returned to the model.

`GET /api/agent/sessions` lists sessions newest first (`limit` 1–100, default 50;
`offset` default 0). `GET /api/agent/sessions/{session_id}` returns the session,
chronological protocol messages, tool executions, and simulated emails. Its
`limit` (1–500, default 100) and `offset` apply independently to each collection.

Errors use `{"error":{"code":"...","message":"..."}}`. Chat errors include
the session UUID once allocated. Missing sessions return 404; invalid requests
422; simultaneous turns on one session 409; missing/unsupported configuration
503; provider rate limiting 429; provider errors/malformed output 502; provider timeouts 504. Completed tool
effects remain stored if a later provider call fails. No automatic replay occurs.

### AI provider diagnostics

Provider errors now have distinct public codes with fixed, safe messages:

- `ai_authentication_failed` (503): the upstream rejected the server's credentials.
- `ai_billing_error` (503): credits, billing, or account/project quota prevent use.
- `ai_model_unavailable` (503): the model is unsupported, missing, or inaccessible.
- `ai_permission_denied` (503): the provider denied account/project access.
- `ai_rate_limited` (429): request/token throttling; wait before trying again.
- `ai_timeout` (504): an HTTP timeout or an upstream timeout response.
- `ai_network_error` (502): a connection, transport, or network failure.
- `ai_provider_error` (502): an upstream service failure.
- `ai_invalid_request` (502): rejected request format, endpoint, or redirect.
- `invalid_ai_response` (502): malformed, incomplete, or invalid structured output.

JSON logs include a `provider_diagnostic` object with the category, upstream HTTP
status, recognized provider error code/type, and whether retry might be useful.
Unknown provider codes/types are omitted as null. Raw error messages, bodies,
headers, request IDs, and credentials are never copied into diagnostics or public
responses. No automatic retries or provider/model substitutions are performed.

An upstream 429 with `insufficient_quota` is classified as billing rather than
rate limiting. More specific recognized codes include `credit_balance_exhausted`,
`organization_spend_limit_exceeded`, `project_spend_limit_exceeded`, and
`organization_usage_limit_exceeded`. Check the organization/project associated
with the API key: restore credits, adjust an enforced spend limit, or request an
approved usage-limit increase as appropriate. Repeated retries cannot resolve
these account conditions. See the
[official provider error guidance](https://developers.openai.com/api/docs/guides/error-codes).

`GET /api/health` retains the exact Stage 1 response:

```json
{ "status": "healthy", "application": "AgentGuard", "version": "0.1.0" }
```

`GET /api/system/status` executes `SELECT 1` and reports backend availability,
database connectivity, AI configuration presence, and version. A database failure
returns 503. `ai_provider.connection_verified` remains false: this diagnostic
does not contact the provider or track successful chats. `configured` checks only
the presence of provider/model/key, not validity or model compatibility.

## Configuration and limits

Process environment variables override `backend/.env`. `.env` is Git-ignored.

- `DATABASE_URL`: default `sqlite:///./data/agentguard.db`. Relative SQLite paths
  always resolve from `backend/`.
- `LOG_LEVEL`: `DEBUG`, `INFO` (default), `WARNING`, `ERROR`, or `CRITICAL`.
- `CORS_ORIGINS`: comma-separated explicit origins; defaults to
  `http://localhost:5173,http://127.0.0.1:5173`. GET and POST are allowed.
- `AI_PROVIDER`: `openai` or `openai-compatible` for live chat.
- `AI_MODEL`, `AI_API_KEY`: required for live chat.
- `AI_BASE_URL`: optional for `openai` (default `https://api.openai.com/v1`),
  required for `openai-compatible`.
- `AI_TIMEOUT_SECONDS`: per-call HTTP timeout; default 30, greater than 0 and at
  most 120 seconds. A turn can make multiple provider calls.
- `AGENT_MAX_TOOL_ITERATIONS`: tool rounds per request; default 4, range 1–8.
  At most four calls per provider response are accepted. After these rounds, one
  final provider request disables tools; further calls are never executed.
- `AGENT_CONTEXT_MESSAGES`: total context messages including the system prompt;
  default 40, range 4–100.
- `AGENT_CONTEXT_CHARS`: serialized context/schema character budget; default
  24,000, range 8,000–100,000. This is not a token count. Old turns are removed
  together, preserving call/result pairs. A current turn that cannot fit stops
  with `context_limit` (422); stored history remains.

Provider requests use at most 2,000 completion tokens. Text replies are limited to
8,000 characters and argument JSON to 12,000 characters. Invalid envelopes,
repeated call IDs within a turn, and incomplete completions fail before additional
operations execute. Text resembling code or a tool call cannot trigger execution.

## Tool boundary

`ToolGateway` is the only dispatcher for model-requested operations. It records
allowed/denied decisions in `security_events` before dispatch, then execution
outcomes in `tool_executions`. Strict Pydantic argument schemas
forbid unknown fields, type coercion, duplicate JSON keys, and non-finite values.

- `read_document(filename)`: only catalogued public fixtures, including
  `project_report.txt`, `meeting_notes.txt`, `quarterly_summary.txt`, and the seven
  Stage 4 fixtures in `backend/data/public/`. Traversal, absolute paths,
  alternate streams, other filenames, symlinks/reparse points, and directory
  escapes are rejected. File identity is checked before reading; cap 6,000 bytes.
  All successful reads are scanned before results reach the agent. A quarantined
  document produces `status: quarantined`, `ok: false`, and safe scan metadata.
- `search_database(query, category?, limit?)`: parameterized literal substring
  searches only on fictional `demo_records`. Categories: `project`, `customer`,
  `inventory`; maximum 10 results. No raw SQL, table choice, or database writes.
  Recognized SQL-operation attempts are denied before search; all remaining
  text is parameterized and wildcard-escaped. Policy categories also scope rows
  when the optional category is omitted.
  Returned text is bounded and scanned per record. Blocked records retain their
  IDs with safe placeholders; safe neighboring records remain available.
- `send_email(to, subject, body)`: saves a `simulated_emails` row atomically with
  its execution and returns `delivered: false`. No SMTP/API transport exists.
  Recipient, subject, and body are bounded; subject header injection and transport
  settings are rejected.
  Both exact recipient and domain must be allowlisted; conservative sensitive
  content restrictions also apply. Defaults allow `demo@example.com` and
  `mira@example.test`. Email bodies are omitted from security/dispatch metadata
  and assistant tool-call history; approved simulated messages retain their body
  in `simulated_emails`.

The fictional confidential `payroll_demo.txt` and `credentials_demo.txt` are never
exposed by tools or an HTTP file-serving route. Startup does not modify public
documents. Synthetic search records seed idempotently.

## Persistence and Stage 1 compatibility

Every record retains a UUID v4 key and UTC creation timestamp. SQLite retrieves
timestamps without an offset; interpret them as UTC.

The original `AgentSession`, `ChatMessage`, `ToolExecution`, `SecurityEvent`, and
`ApprovalRequest` models remain. Stage 2 adds `DemoRecord` and `SimulatedEmail`.
Startup performs an idempotent additive SQLite upgrade adding nullable
`tool_calls` and `tool_call_id` columns to existing chat messages, preserving IDs
and contents. Other schema changes still require an explicit migration.
Stage 3 needs no schema migration: it writes versioned `firewall_decision_v1`
events into the existing `SecurityEvent.details` JSON column. Legacy events are
preserved and excluded from firewall statistics. Back up SQLite before upgrading.
Stage 4 also reuses the existing table, with `injection_scan_v1` event details.
It stores hashes/offsets and safe metadata, not raw malicious tool output. Scan
events and sanitized execution outcomes commit before a model request. Restored
tool history is scanned again; legacy stored rows are not deleted or rewritten.

User/assistant/tool protocol messages persist. Reads are paginated, writes commit
explicitly, foreign keys remain enforced, and no database transaction is held
across an LLM network wait. One session accepts one active turn at a time. A
process crash can leave a session marked `processing`; automatic crash recovery
and request idempotency are not implemented.

Configured credentials are redacted from stored/public chat and tool data,
including parsed tool arguments. Configuration code never puts them in model
context. Application/Uvicorn logs are JSON without exception payloads/tracebacks;
HTTP client debug/access logging and SQL parameter logging are disabled. Upstream
error bodies and raw validation inputs are not returned.

## Tests

From the project root:

```powershell
.\.venv\Scripts\python.exe -m pytest -c .\backend\pytest.ini .\backend\app\tests
```

From `backend/`:

```powershell
..\.venv\Scripts\python.exe -m pytest
```

Tests use mocked LLM responses/HTTP transports and isolated SQLite databases.
They cover Stage 1 contracts, all tools, persistence/restart, gateway rejection,
filesystem escapes, SQL restrictions, provider errors/timeouts and validation,
context/iteration limits, credential redaction, and Stage 1 schema upgrades.
Stage 3 adds deterministic allow/deny policies, audit failure, forced unauthorized
LLM calls, recipient/content controls, and local-only monitoring tests. Two SQL
regression cases now require rejection rather than a successful empty search,
while retaining the original database-integrity assertions.
No live API key or external email account is needed. The actual symlink test
skips if the OS denies symlink creation; reparse-point and root-escape tests run.

## Project structure

```text
backend/
  .env.example, requirements.txt, pytest.ini
  config/        security_policies.json
                 injection_policy.json
  app/
    main.py
    core/        config.py, exceptions.py, logging.py, redaction.py
    database/    base.py, session.py, migrations.py, seed.py
    models/      original five models, demo_record.py, simulated_email.py
    schemas/     system.py, agent.py
    routers/     health.py, system.py, agent.py, security.py, injection.py
    services/    system.py
    agent/       errors.py, provider.py, provider_errors.py, history.py, service.py
    tools/       schemas.py, gateway.py
    security/    firewall.py, policy_engine.py, policies.py, risk_engine.py,
                 audit_service.py, schemas.py, documents.py, summaries.py
      injection/ detector.py, normalizer.py, rules.py, risk_scorer.py,
                 classifier.py, response_handler.py, processor.py,
                 audit.py, schemas.py, config.py
    simulations/ reserved
    tests/       Stage 1/2 plus test_firewall.py and test_security_api.py
                 test_injection.py, test_injection_api.py, test_injection_integration.py
  data/
    public/       project_report.txt, meeting_notes.txt, quarterly_summary.txt
                  safe_project_report.txt and six injection demonstration fixtures
    confidential/ payroll_demo.txt, credentials_demo.txt
    agentguard.db (generated, ignored)
frontend/         reserved; no frontend implementation
docs/             stage3-security.md, stage4-injection.md
README.md, .gitignore
```

All Python packages include `__init__.py`. Provider credentials/connectivity,
model compatibility, and answer quality require a live API run; automated tests
mock the LLM. Authentication, attack simulations (Stage 5), and frontend
functionality remain outside this implementation.
