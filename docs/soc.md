# SOC API

The FastAPI backend in `soc/api/`. Sensors send alerts and block reports to it; the dashboard
(and later the assistant) reads them, triages, and asks sensors to act.

## Running it

```bash
pip install -e ".[dev]"
export IDPS_SOC_JWT_SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
python -m soc.api create-user alice --role admin      # asks for the password (12+ characters)
python -m soc.api create-sensor lab-sensor-1          # prints the sensor token once
uvicorn soc.api.main:app --ws-max-size 65536 --reload   # one process, see "Live feed" below
```

Settings (environment variables, prefix `IDPS_SOC_`):

| Variable | Default | Meaning |
|---|---|---|
| `JWT_SECRET` | none, required | Signs login tokens, 32+ characters |
| `DATABASE_URL` | `sqlite:///./soc.db` | SQLAlchemy URL; PostgreSQL: `postgresql+psycopg://user:pass@host/idps` |
| `ACCESS_TOKEN_MINUTES` | 30 | Login token lifetime (5 to 1440) |
| `LOGIN_MAX_FAILURES` / `LOGIN_MAX_FAILURES_PER_IP` / `LOGIN_LOCKOUT_MINUTES` | 5 / 20 / 15 | Lockout, see below |
| `CORS_ORIGINS` | `http://localhost:5173` | Comma-separated browser origins |
| `SEVERITY_BY_CLASS` | built-in map | JSON, e.g. `{"Bot": "critical"}`; class names match case-insensitively |
| `DEFAULT_SEVERITY` | `medium` | For classes not in the map |
| `LOW_CONFIDENCE_BELOW` | 0.6 | Below this confidence, severity drops one level (never below low) |
| `WS_MAX_CONNECTIONS` / `WS_QUEUE_SIZE` | 50 / 200 | Live feed limits |
| `ENABLE_DOCS` | false | Serves `/docs` and `/openapi.json` (unauthenticated, so off by default) |
| `WOULD_BLOCK_RETENTION_DAYS` | 7 | Dry-run would-block records older than this are deleted (1 to 365) |
| `BLOCK_ALLOWLIST` | **empty: blocking refused** | Comma-separated addresses/networks the SOC must never ask to block: gateways, DNS, the SOC host, the sensors, the analysts. Required before any block request is accepted |

The SOC owns its block allowlist (`IDPS_SOC_BLOCK_ALLOWLIST`). Sensors keep their own
(`IDPS_ALLOWLIST`) as a second, independent check; set both.

## Endpoints

"User" means a logged-in analyst or admin. Lists use keyset pagination: `limit` (1 to 500) and
`cursor` (the `next_cursor` of the previous page); newest first.

| Method and path | Who | Purpose |
|---|---|---|
| `GET /health` | public | Liveness |
| `POST /auth/login`, `GET /auth/me` | public, user | Login; current user |
| `POST /ingest/alerts` | sensor | Batch of 1 to 500 alerts; stores and broadcasts them |
| `GET /alerts` | user | Filters: `severity` (repeatable), `predicted_class`, `ip` (source or destination), `status`, `since`, `until` (timezone required) |
| `GET /alerts/{id}`, `PATCH /alerts/{id}` | user | Detail with explanation; set `status` (new, acknowledged, false_positive, resolved) |
| `WS /ws/alerts` | user | Live feed: alerts (as `GET /alerts` plus `src_geo`) and typed block messages; see "Live feed" |
| `POST /ingest/blocks` | sensor | Up to 100 `blocked` / `unblocked` / `would_block` events (`would_block` = a dry-run decision, stored in its own table, never a block) |
| `GET /blocks` | user | `active=true/false`, `ip` |
| `GET /blocks/would` | user | Dry-run `would_block` decisions, newest first: `ip`, `since_hours` (1 to 720, default 24), `limit`, `cursor` |
| `POST /sensor/status` | sensor | The sensor's status snapshot (mode, policy, allowlist, health, counters); every 30 s; overwrites the sensor's one row |
| `GET /sensors/status` | user | `{redacted, soc_allowlist, sensors: [{sensor_id, name, revoked, last_seen_at, online, status}]}`; `status` is null for a sensor never seen (and, for non-admins, for a revoked one); **non-admins get `redacted: true`, `soc_allowlist: null` and `allowlist: null`, `policy: null` in each status** (admins get all of it); online = reported within 120 s and not revoked; no tokens or hashes |
| `POST /actions` | user | Request `block_ip` / `unblock_ip` on a sensor; starts confirmed |
| `GET /actions`, `GET /actions/{id}` | user | List (filter by `status`), detail |
| `POST /actions/{id}/confirm`, `/reject` | user | Decide a pending action (for assistant proposals) |
| `GET /sensor/actions` | sensor | Confirmed actions for this sensor |
| `POST /sensor/actions/{id}/result` | sensor | `{"success": bool, "result": {...}}` |
| `GET/POST /cases`, `GET/PATCH/DELETE /cases/{id}` | user | Cases |
| `POST /cases/{id}/notes` | user | Note, up to 10,000 characters |
| `POST /cases/{id}/alerts`, `DELETE /cases/{id}/alerts/{alert_id}` | user | Attach or detach alerts (an alert is in at most one case) |
| `GET /metrics/summary?hours=24` | user | Alerts per bucket (hourly up to 72 h, else daily), by class and severity, top 10 sources, false-positive rate, detection latency p50/p95, active blocks, `would_blocks` (dry-run decisions in the window), `by_class_per_day` (cached for 60 s; last 7 UTC days whatever `hours` is: `[{day, class, count}]`, non-zero pairs only, classes beyond the top 25 as `(other)`), `anomaly_per_day` (same 7 days and cache: `[{day, count}]`, alerts the Isolation Forest also flagged, non-zero days only) |
| `GET /topology?hours=1` | user | Nodes (host, alert count, max severity) and edges (src to dst, count, max severity) |
| `GET/POST /admin/users`, `PATCH /admin/users/{id}/role`, `POST /admin/users/{id}/disable`, `/enable`, `/reset-password` | admin | User management |
| `GET/POST /admin/sensors`, `POST /admin/sensors/{id}/revoke` | admin | Sensors; the token is returned once, on creation |
| `GET /admin/audit` | admin | Audit log, filter by `actor` and `action` (repeat `action` for several, up to 20) |

Rules worth knowing:

- **Severity** comes from the predicted class and the confidence (see `SEVERITY_BY_CLASS`).
  BENIGN alerts in a batch are skipped and counted in `skipped_benign`.
- **Allowlist.** `block_ip` is refused (422) for any address in `IDPS_SOC_BLOCK_ALLOWLIST`
  and for loopback, multicast, link-local, reserved and unspecified addresses. IP fields reject
  IPv6 zone IDs (`%eth0`) and anything longer than 45 characters. The check runs when the
  action is created, when it is confirmed, and again when the sensor polls for it. While the
  allowlist is empty, every block request is refused (503); already-confirmed actions are then
  held back, not failed, and are handed out once the allowlist is set again.
- **Concurrency.** Confirm and reject, and a sensor's result report, use conditional updates,
  so of two simultaneous requests exactly one wins and the other gets 409. The login lockout
  counts an attempt before the password check, so parallel guesses can't exceed the limit.
- **Actions.** pending, then confirmed or rejected by an analyst; then the sensor reports
  executed or failed. A sensor only sees and answers its own actions.
  The live sensor polls and executes them (see "Analyst actions" in `live.md`); in dry-run it
  reports them failed with `sensor is in dry-run: not applied`.
- **Would-block events.** A dry-run sensor reports each block it *would* have applied as
  `{"event": "would_block", "ip", "reason", "ttl_seconds", "decided_at"}` through `/ingest/blocks`. They go to
  the `would_blocks` table, never `blocks`, so active-block counts and the firewall are unaffected;
  a sensor that blocks for real never sends them. `expires_at` is refused on them. `decided_at`
  (timezone required, optional) is the sensor's decision time and is stored as `at`, so an event
  delayed in the outbox keeps its real time; absent (older sensors) or more than 60 s in the future
  it, or older than 24 h (a wrong sensor clock), is replaced by the receive time. Retention: would-block rows older than
  `IDPS_SOC_WOULD_BLOCK_RETENTION_DAYS` (default 7, 1 to 365) are deleted by a background task started
  by the block ingest path (it runs after the response, with its own database session), at most once
  per 10 minutes per process, one at a time, and at most 10,000 rows per run (1,000 per DELETE, the
  ids chosen by a subquery so SQLite's old 999-variable limit does not apply), so a large backlog is
  worked off over several runs. The 10 minutes count from when a prune starts: a prune that fails
  is logged (with its traceback) and not retried until the interval has passed; batches already
  deleted stay deleted. It only ever touches `would_blocks`, never `blocks`.
  A failed prune is logged and does not fail the ingest. `at` is indexed (`ix_would_blocks_at`);
  the table is new, so `create_all` creates it with the index and nothing needs adding by hand.
- **Sensor status.** The live sensor posts a status report at start and every 30 s
  (`IDPS_LIVE_STATUS_SECONDS`, 5 to 3600). The SOC's bounds on the policy fields cover everything the
  sensor's settings allow (`unblock_grace_seconds` is capped at one year on both sides), so a valid
  sensor never gets a 422 on its status. A stored status that no longer validates (older schema)
  is listed as `status: null` instead of failing the listing. The body is strict (unknown fields refused; strings,
  lists, numbers bounded; at most 100 allowlist entries). `last_seen_at` is the SOC's clock, not
  the sensor's. These posts are not audited (one every 30 s would bury the audit log). Shape of one
  entry's `status`: `dry_run`, `blocking_enabled`, `interface` (null in replay), `mode`
  (`live`/`replay`), `model {name, checksum_ok}`, `policy {confidence_threshold, min_flows,
  window_seconds, min_alert_confidence, block_ttl_seconds, unblock_grace_seconds,
  max_analyst_blocks}`, `allowlist` (the sensor's `IDPS_ALLOWLIST`), `allowlist_total` (the real count; `allowlist` is cut at 100), `outbox_pending`, `shap_p95_ms`, `heartbeat {enabled, ok}`, `counters {flows, alerts, blocked, would_block}`,
  `faithfulness` (optional, absent from older sensors or when the sensor has no report):
  `{model, model_matches, model_check, flows, top_k, random_mean_drop, methods: {shap?, lime?}}` with
  each method `{mean_drop, ratio_to_random, label_flip_rate, share_flows_beating_random}`.
  `ratio_to_random` may be `null` (random removal changed nothing) or negative (deleting the
  explanation raised confidence): the worst outcomes are reported, not dropped. `model_check` is
  `"digest"` (report and loaded model compared by sha256) or `"name"` (older report without a
  digest, or older sensor: only the algorithm name was compared, a weak match), absent from older
  sensors; at least one
  method; unknown keys are refused. Model-level numbers from the offline faithfulness report, not
  live LIME. `sensor_version`, `sent_at` (the sensor's clock, informational).
- **Anomaly series.** `anomaly_per_day` counts alerts whose stored `anomaly_score` is above 0:
  exactly the Isolation Forest's outlier flag (score = -decision_function). It is a separate
  series, not a synthetic class row, so no class name can collide with it; ingest also refuses a
  `predicted_class` starting with `(` so nothing real collides with the `(other)` fold bucket.
  The result is one grouped query over the week's alerts, cached in-process for 60 s per database
  and UTC day (new alerts show up to a minute late; a new day never reuses yesterday's buckets).
  The cost still grows with the alerts of the last 7 days. The model now declares an index
  `ix_alerts_received_class_anomaly` on `alerts (received_at, predicted_class, anomaly_score)`, so
  new databases get it from `create_all`; an **existing** database does not (create_all never
  touches existing tables), so add it by hand:
  `CREATE INDEX ix_alerts_received_class_anomaly ON alerts (received_at, predicted_class, anomaly_score);`
  An alert has a class and may also be an outlier, so the series overlaps the class rows; alerts
  with no score (a model without an anomaly detector) are ignored.
- **Last admin.** Demoting or disabling the last enabled admin, including yourself, returns 409.
- **Request body limits.** `soc/api/limits.py` (pure ASGI middleware, constants in one place)
  answers 413 before anything is read or parsed (so before authentication, even for a revoked
  sensor): by `Content-Length` when sent, and by counting streamed bytes (chunked bodies) until the
  limit. 10 MiB for `/ingest/alerts` (500 alerts x 16 KiB explanation fit), 128 KiB `/ingest/blocks`
  and `/cases`, 64 KiB `/sensor/status` and `/assistant`, 16 KiB `/actions`, `/sensor/actions` and
  `/admin`, 4 KiB `/auth/login`, 256 KiB anything else. A malformed `Content-Length` is a 400. The
  Caddyfile in `infra/templates/soc-user-data.sh.tftpl` also sets `request_body { max_size 11MiB }`,
  `X-Frame-Options: DENY` and `Content-Security-Policy: frame-ancestors 'none'`.
- **Sensor-supplied text.** Interface, model and sensor-version names in a status report are
  refused (422) if they contain control, formatting (bidi override, zero-width) or separator
  characters; would-block and block reasons, the `reason` of `POST /actions` and the assistant's
  `propose_block` reason have those characters removed (a reason that is blank afterwards is
  refused); a NUL anywhere in a
  stored string (alert class, explanation, reason, action result, status) is refused because
  PostgreSQL cannot store it. Allowlist entries must be IP addresses or networks (stored
  normalised, e.g. `10.1.1.1/32`), `allowlist_total` must be at least the list's length, and
  booleans and integers are strict (`"yes"` is not a bool). A `would_block` event always has
  `source: "auto"`, whatever the sensor says.
- **WebSocket size.** The body-limit middleware does not see WebSocket messages, and the live feed
  reads the first message before checking its 4096 characters, so start uvicorn with
  `--ws-max-size 65536` (every start script in the repo does; its default is 16 MiB). The server
  then closes an oversized message with 1009 before any handler runs.
- **What analysts can see (decided, deliberate).** `GET /sensors/status` withholds the SOC
  allowlist and each sensor's allowlist and block policy from non-admins, and the 422 for a blocked
  address on the allowlist names the matching network only to admins (analysts, and the assistant,
  get "this address is on the block allowlist"). Block reasons and action results stay visible to
  analysts because they need them to triage. An analyst can therefore still infer from a reason
  such as "5 flows >= 0.9 confidence in 60s" the sensor's threshold, flow count, window and block
  length, and from refused actions the analyst-block cap. That is accepted: redacting reasons would
  make blocks impossible to review; the allowlist (who is never blocked) is the part that matters.
- **Sensor status audit.** One audit row (`sensor_status_first`) on a sensor's first report, and
  `sensor_status_changed` when `dry_run`, `blocking_enabled`, `mode`, `model`, the `policy`, the
  allowlist (or its total) or `faithfulness.model_matches` changes: `details.changed` maps each
  field to `[old, new]` (policy: per sub-field; allowlist: counts, totals and at most 20 added and
  removed entries plus `more`). Counters, outbox size and times never cause a row. At most one row
  per sensor per field per 10 minutes (`AUDIT_WINDOW_SECONDS`): a change inside the window is not
  lost, the next post after it compares with the last *audited* value and writes one row (old to
  latest) with `details.folded[field]` counting the changes it absorbed; the throttle state is in
  memory, after a restart the stored status is the baseline. Stored allowlists from before entries
  were normalised (`10.10.1.1`) are normalised before comparing, so an upgrade is not a change.
- **Audit.** Every mutating request writes one audit row in the same transaction as the change
  (an alert or block batch is one row). `POST /auth/login` is not audited.

## Auth model

- **Users** log in at `/auth/login` with a username and password (argon2id) and get a bearer
  token (JWT, HS256). Send it as `Authorization: Bearer ...`. The role is read from the database
  on every request, so demotions and disabling apply at once; a password reset or disable also
  invalidates existing tokens.
- **Sensors** use API tokens (`idps_sensor_...`, created by `python -m soc.api create-sensor` or
  by an admin). Only a SHA-256 of the token is stored. Sensor tokens work only on `/ingest/*`
  and `/sensor/*`; user tokens do not work there.
- **WebSocket.** Browsers can't set headers on a WebSocket, so after connecting, the client's
  first message must be `{"token": "<access token>"}`, sent within 5 seconds. Any failure closes
  the socket with code **4401**, as does the token expiring or the user being disabled while
  connected (re-checked every 30 s). Other close codes: 4429 too many connections, 4408 client
  too slow. The server then sends `{"type": "ready"}` followed by one JSON object per new alert
  (the same fields as `GET /alerts`, without the explanation; fetch `/alerts/{id}` for that).
  Reconnect when the token is renewed.
- **Lockout.** After `LOGIN_MAX_FAILURES` failed logins for a (username, client IP) pair, or
  `LOGIN_MAX_FAILURES_PER_IP` for one IP, logins are refused (429) for `LOGIN_LOCKOUT_MINUTES`,
  even with the right password. The counters are **in memory**: they reset when the process
  restarts and are not shared between processes, so run one process or move them to the
  database or Redis before scaling out. Behind a reverse proxy, use uvicorn's `--proxy-headers`
  so the client IP is the real one.

## Live feed (single process)

New alerts reach WebSocket clients through an in-process broadcaster (`soc/api/broadcast.py`).
Each client has a bounded queue; one that falls behind is disconnected (4408) and ingest never
waits for it. Because it lives in memory, run **one** API process. With several workers, a
client would only see alerts ingested by its own worker. Scaling out needs a shared bus
(PostgreSQL LISTEN/NOTIFY or Redis pub/sub) behind the same `publish` interface.

**Messages** (any signed-in user receives all of them; after the auth message the server sends
`{"type": "ready"}`, unchanged). Older clients ignore messages without an `id`.

- *Alert* (published after `POST /ingest/alerts` commits): the fields of `GET /alerts` (with `id`)
  plus `src_geo`, only in this message (not stored, not in `/alerts`):
  `{"lat": float, "lon": float, "country": str|null, "city": str|null, "source": "geoip"|"demo"}`
  or `null` when the source has no location. It comes from the same `GeoLocator` as
  `/geo/attacks` (same demo rules; it caches per address, 50,000 at most, so a lookup on the ingest
  path is a dictionary hit for repeat sources and a lookup failure only gives `null`).
- *Block event* (one per event of an accepted `POST /ingest/blocks`, published after the commit;
  nothing for a refused batch):
  `{"type": "block", "event": "blocked"|"unblocked"|"would_block", "sensor_id": int, "ip": str,
  "source": "auto"|"analyst", "at": ISO8601, "expires_at": ISO8601|null, "ttl_seconds": int|null,
  "reason": str, "geo": <as src_geo>|null}`. `at` is the SOC's time (for `would_block` the stored
  decision time); `expires_at` is set for `blocked` only and `ttl_seconds` is the given one or the
  remaining seconds; an analyst-confirmed unblock arrives as `unblocked`. An `unblocked` event that
  closed no active block (already expired or never known) is not published.
- *Bounds:* block messages may use at most half of a client's queue (`BLOCK_SHARE`); beyond that
  they are dropped for that client (counted in `Subscriber.blocks_dropped`, the client stays
  connected), so a burst of block reports cannot push alerts out or get a client disconnected. A
  client that falls behind on alerts is still disconnected (4408) as before.

## Database

SQLite (`sqlite:///./soc.db`) for development; PostgreSQL in deployment. Tables are created
with `create_all` at start-up (`soc.api.db.init_db`), which adds missing tables but does not
alter existing ones. Schema migrations (Alembic) are a later step, so until then a model change
means recreating the development database. Timestamps are stored and returned as timezone-aware
UTC.

Tables: `users`, `sensor_tokens`, `alerts`, `blocks`, `actions`, `cases`, `case_notes`,
`audit_log`, `would_blocks`, `sensor_status`.

## Maps

- **Attack map** (`GET /geo/attacks?hours=24`, dashboard "Attack map"): the busiest attack
  sources placed on a world map, with lines to the protected site.
  - Real locations need the free MaxMind **GeoLite2 City** database: create a MaxMind
    account, download `GeoLite2-City.mmdb`, and set `IDPS_SOC_GEOIP_DB` to its path.
    Without it, public addresses can't be placed (the page says so).
  - Lab addresses are private and have no real location. `IDPS_SOC_GEO_DEMO=true` gives them
    made-up, stable locations named "Demo: ..."; the page labels these as not real. Keep it off
    for real results.
  - `IDPS_SOC_HOME_LAT`, `IDPS_SOC_HOME_LON` and `IDPS_SOC_HOME_LABEL` set where the attack
    lines end (the protected site).
- **Topology** (`GET /topology?hours=1`, dashboard "Topology"): hosts seen in alerts and the
  source-to-target pairs between them, coloured by highest severity. Both maps refresh on new
  alerts from the live feed.

## SOC assistant

A chat panel ("Assistant", and "Explain this alert with the assistant" on every alert) backed
by Claude through the Anthropic Python SDK (`soc/assistant/`).

**Turning it on.** Set `ANTHROPIC_API_KEY` in the API server's environment (never in the
browser). Without it the assistant is switched off, the page says so, and everything else
works. Each message costs API usage; limits below keep it bounded.

| Setting (`IDPS_SOC_` prefix) | Default | Meaning |
|---|---|---|
| `ASSISTANT_MODEL` | `claude-opus-5-5` | Model used |
| `ASSISTANT_EFFORT` | `medium` | Reasoning effort (`low` is cheaper and faster) |
| `ASSISTANT_RATE_PER_10MIN` | 20 | Messages per user per 10 minutes |
| `ASSISTANT_MAX_TURNS` | 30 | Messages per conversation |

Requests use server-side fallbacks (`fallbacks: "default"`), so if the model declines a
request the API retries it on a fallback model automatically. The system prompt and tool list
are constant and prompt-cached.

**What it can do.** It calls fixed tools (`soc/assistant/tools.py`); it never writes SQL:
`search_alerts`, `get_alert` (with the SHAP/LIME explanation), `top_attackers`, `list_blocks`,
`get_case`, `metrics_summary`, `get_playbook` (the response playbooks in `docs/playbooks/`,
mapped to MITRE ATT&CK), and `propose_block`. Tool arguments are validated before anything
runs, and at most 8 tool rounds run per reply.

**Safety.**
- `propose_block` only creates a **pending** action. Nothing happens until an analyst confirms
  it on the Actions page, and the usual block allowlist checks apply.
- Alert fields come from network traffic, so an attacker can influence them (prompt
  injection). Tool results are wrapped in `<soc_data>` and the system prompt tells the model to
  treat them as data and point out embedded instructions. The confirm-before-act rule is what
  makes this safe even if the model is fooled.
- Conversations are private to their user. API errors are reported without internal details.

**Endpoints.** `GET /assistant/status`, `GET /assistant/conversations`,
`GET /assistant/conversations/{id}`, and `POST /assistant/chat` (streams NDJSON events:
`conversation`, `text`, `tool`, `tool_result`, `action_proposed`, `error`, `done`).

**Evaluation.** For the report, write about 30 questions with answers you can check against the
database (for example "top attacker in the last hour") and score answer accuracy, the share of
correct block proposals, and response time.

## Upgrading an existing database

Tables are created with `create_all`, which adds missing tables but **not** new columns on
existing tables (proper migrations with Alembic are a later step). After pulling a change that
adds a column, either start from a fresh database or add the column by hand, for example:

```sh
sqlite3 soc.db "ALTER TABLE assistant_conversations ADD COLUMN busy_since DATETIME;"
```
