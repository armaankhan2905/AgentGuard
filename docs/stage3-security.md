# Stage 3 security firewall

## Execution and trust boundary

The existing agent calls only `ToolGateway.execute`. The gateway invokes
`SecurityFirewall.evaluate`, which validates bounded JSON against strict tool
schemas, resolves server-owned resource identities, applies baseline guards,
evaluates JSON policies, and assigns risk independently of the model. An
`AuditService` commits the decision before dispatch. DENY returns a safe tool
error; ALLOW reaches the existing tool implementation. Execution outcomes and
simulated emails commit together. `result.security.decision_id` links the
execution outcome to its authorization event.

Unknown tools, invalid arguments, absent allows, and invalid/missing policy files
deny by default. Explicit deny wins regardless of rule order. Built-in guards
cannot be overridden by a broad JSON allow. Caller roles and classifications
are not accepted. All sessions use the ordinary, unprivileged context. There is
no session elevation API, policy modification API, alternate dispatcher, real
email transport, shell tool, or arbitrary SQL tool.

Audit persistence errors roll back and return controlled HTTP 503
`security_audit_unavailable` before any tool executes. Security evaluation
errors also fail closed. An ALLOW event is authorization, not proof that the tool
succeeded; inspect the linked execution outcome. A process crash after the audit
commit may leave an authorization event without an execution outcome.

## Policy configuration

`SECURITY_POLICY_FILE` defaults to `backend/config/security_policies.json`.
Relative paths resolve from `backend/`. This file is server-owned configuration;
never give the agent filesystem write access to it. New gateways load one
validated snapshot per chat request (or development evaluation request).

Each rule has a unique uppercase `id`, a registered `tool`, an `effect` of
`ALLOW` or `DENY`, and optionally a document `classification`. Unknown fields,
duplicate JSON keys/IDs, unsupported tool names/categories, invalid recipients,
oversized files, malformed JSON, and out-of-range settings invalidate the entire
configuration. No partial policy is applied. `GET /api/security/policies` reports
validity, rules, and the baseline guards; it never returns secrets.

The trusted catalog in `security/policies.py` maps the three existing public
fixtures to PUBLIC, payroll to CONFIDENTIAL, and demonstration credentials to
RESTRICTED. `confidential_strategy.txt` is a denied catalog identity for the
requested example; no new sensitive file is created. Unknown names deny. No
INTERNAL resources or privileged demo sessions are provisioned; INTERNAL is a
reserved classification and ordinary sessions cannot read it.

Exact public identities reject traversal, absolute paths, encoded/normalized
variants, alternate streams, and unknown files before filesystem access.
Shared path checks reject symbolic links, reparse points, directory escapes,
and multiply linked files before authorization. The reader repeats the checks
and compares file identity before reading. A document remains limited to 6,000
bytes. Keep demo files and their directories writable only by trusted developers.

`database_categories` is a subset of `project`, `customer`, `inventory`. The
query always scopes results to that subset, including when no category is given.
SQL-like operations are rejected; parameterized, wildcard-escaped SELECT queries
remain the actual injection protection. No policy can select another table or
enable writes. Results remain capped at 10.

Emails require a match in **both** `email_domains` and `email_recipients`, with
case-insensitive exact matches, never suffix/wildcard matches. Defaults are
`demo@example.com` and `mira@example.test` to preserve the existing demo tests.
Edit both lists to change recipients. `email_max_body_chars` can tighten the
4,000-character ceiling. Multiple recipients/CC/BCC/transport arguments are
rejected. Conservative content checks cover sensitive labels, credential terms,
and the existing confidential fixture markers, including normalized Unicode.
An approved recipient never disables those content checks.

Risk is separate from permission: public reads/searches LOW, approved simulated
email MEDIUM, confidential/restricted/invalid operations HIGH, paths/links and
unauthorized or sensitive email transmission CRITICAL. LOW never grants access
without an explicit allow policy.

## Database and audit privacy

No schema migration is needed for Stage 3. The existing `security_events` table
holds `firewall_decision_v1` events. Its UUID and UTC timestamp match the decision;
JSON details hold session, known tool name, decision, risk, policy, fixed reason,
safe argument summary, and unprivileged context. Unknown tool names are recorded
as `unknown_tool`, avoiding attacker-controlled strings in audit metadata.

Summaries contain known document IDs/classifications, permitted category/limit,
query length, and email subject/body lengths. They never contain full email
bodies, search text, credentials, arbitrary paths, or confidential contents.
Assistant email tool-call history uses omitted placeholders; approved simulated
messages still store their intended redacted body in the existing email table.
User/assistant chat text remains conversation data, not security audit data.
Existing rows are neither deleted nor retroactively rewritten. Legacy security
events remain intact and are excluded from Stage 3 counts.

Before upgrading, stop the backend, back up `backend/data/agentguard.db` locally,
then start the backend normally. Retain the existing `.env` and API credentials.
Startup still performs the previous additive chat-history upgrade if needed.

## Local monitoring and Swagger testing

There is no authentication system yet. Security routes are **absent by default**.
Enable them only on a local developer machine. Do not expose this application
publicly or through a reverse proxy/tunnel. Existing chat/session routes also
lack authentication; this stage does not make the application production-ready.

From the project root in Windows PowerShell:

```powershell
Set-Location 'C:\Users\ASUS\OneDrive\hackathon\AgentGuard'
$env:APP_ENVIRONMENT = 'local'
$env:SECURITY_DEV_ENDPOINTS = 'true'
Set-Location .\backend
..\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --no-access-log --no-proxy-headers
```

Stop an existing server first with Ctrl+C in its terminal. These two PowerShell
variables apply to this shell and children; alternatively set them in
`backend/.env`. Process environment values override `.env`. Keep API keys only
on the existing `AI_API_KEY=` line in `.env`; Stage 3 requires no new credential.
To disable the development routes, set `SECURITY_DEV_ENDPOINTS=false` and restart.

The local routes require both explicit settings, an actual loopback client,
a localhost/loopback Host, and same-origin requests when Origin is supplied.
Forwarded headers are not an authorization source. **Use `--no-proxy-headers`**
so the server does not replace the socket peer with proxy-supplied information.

Open [Swagger UI](http://127.0.0.1:8000/docs). Expand the security group:

- `GET /api/security/events`: `limit` (1–100), `offset`, `decision`, `risk_level`,
  `tool`, `session_id`, and `sort=asc|desc`; stable timestamp/UUID ordering.
- `GET /api/security/events/{event_id}`: full safe authorization record.
- `GET /api/security/stats`: actual total/allowed/blocked/HIGH/CRITICAL counts.
- `GET /api/security/policies`: validated rule descriptions; read-only.
- `POST /api/security/evaluate`: development evaluation only; **never executes**
  tools, including allowed actions. It records an event marked
  `metadata.source=development_test`. These events count in monitoring statistics.

Use **Try it out** on `/api/security/evaluate` with these payloads:

```json
{"tool_name":"read_document","arguments":{"filename":"project_report.txt"}}
```

Expect ALLOW/LOW. Then change filename to `confidential_strategy.txt` (DENY/HIGH)
or `../../secrets.env` (DENY/CRITICAL). These tests need no LLM connection.

```json
{"tool_name":"search_database","arguments":{"query":"John","category":"customer","limit":5}}
```

Expect ALLOW/LOW. A `restricted_financial_records` category or limit 10000 denies.

```json
{"tool_name":"send_email","arguments":{"to":"demo@example.com","subject":"Demo update","body":"Public project review is ready."}}
```

Expect ALLOW/MEDIUM but **no simulated email created by evaluation**. Change the
recipient to `attacker@unknown-domain.com` or the body to `CONFIDENTIAL payroll`
to see a denial. Add `role` or `context` to the request to see schema rejection.
The optional `session_id` must identify an existing session; omitting it creates
a fixed ordinary development-test session. It never grants privileges.

Use `/api/agent/chat` with `{"message":"Read project_report.txt and summarize it."}`
to exercise real model selection and execution. This requires the existing live
provider to work; a model may choose not to call a tool. Verify `tool_calls`, its
security decision ID, and monitoring events. Automated tests force tool calls
to prove backend enforcement even when the model requests forbidden operations.

## Verification and limits

Verified on 2026-10-26: **200 passed, 1 skipped** across the full Stage 1–3 suite.
The skip is the real file-symlink test because this Windows account lacks the
creation privilege. One upstream Starlette/httpx deprecation warning remains.
Existing regressions pass with the two intentional SQL-denial expectation
updates described above; no regression tests were deleted.

The restarted backend returned HTTP 200 for health and system status, with
SQLite connected. Actual Groq requests using the existing `openai/gpt-oss-20b`
model succeeded for both a greeting and `read_document(project_report.txt)`.
The document execution had a persisted ALLOW event. Eight live development
evaluations produced the expected public/search/email allows and confidential,
traversal, restricted-category, and unauthorized-recipient denials. At the end
of that smoke check the real event counts were 9 total, 4 allowed, 5 denied,
3 HIGH, and 2 CRITICAL. Those are observed records, not seeded statistics.

The existing `/api/system/status` `connection_verified` field remains static
false; it is not an active provider probe. The successful real chat responses
above are the live connection evidence. No provider/model configuration changed.

Run all Stage 1–3 tests from the project root:

```powershell
.\.venv\Scripts\python.exe -m pytest -c .\backend\pytest.ini .\backend\app\tests
```

Tests use mocked provider replies and real isolated SQLite transactions. They
cover allowed execution, forced forbidden calls, deny precedence, invalid
policies, safe summaries, gateway audit ordering, persistence failure, restored
events, filtering/counts, and development endpoint isolation. The original SQL
cases now assert rejection as required by Stage 3 rather than an empty literal
search. The real symlink test skips on Windows accounts lacking that privilege;
reparse and root-escape tests still run.

This is a deterministic demo firewall, not a universal content classifier.
Content markers can have false positives and miss arbitrary encodings,
paraphrases, or novel sensitive data. Resource denial prevents confidential
fixtures from entering tool results; email is always simulated. The system does
not defend against an attacker who can edit Python, policy files, the SQLite
database, or public fixture contents. No user authentication, tamper-proof audit
store, full DLP, process sandbox, internal-session entitlement system, or general
prompt-injection detection is claimed. Stage 4, Stage 5, and frontend work have
not been implemented.

## Files changed in Stage 3

Created: `backend/config/security_policies.json`; `backend/app/security/` modules
`schemas.py`, `policies.py`, `policy_engine.py`, `risk_engine.py`, `documents.py`,
`firewall.py`, `audit_service.py`, `summaries.py`; `backend/app/routers/security.py`;
`backend/app/tests/test_firewall.py`, `test_security_api.py`; this guide.

Modified: `backend/app/security/__init__.py`, `backend/app/tools/gateway.py`,
`backend/app/tools/schemas.py`, `backend/app/agent/service.py`,
`backend/app/routers/agent.py`, `backend/app/core/config.py`, `backend/app/main.py`,
`backend/app/tests/test_gateway.py`, `backend/.env.example`, and `README.md`.
The provider adapter, database schema, real `.env`, and frontend are unchanged.
