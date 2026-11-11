# SOC API

The FastAPI backend in `soc/api/`. Sensors send alerts and block reports to it; the dashboard
(and later the assistant) reads them, triages, and asks sensors to act.

## Running it

```bash
pip install -e ".[dev]"
export IDPS_SOC_JWT_SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
python -m soc.api create-user alice --role admin      # asks for the password (12+ characters)
python -m soc.api create-sensor lab-sensor-1          # prints the sensor token once
uvicorn soc.api.main:app --reload                     # one process, see "Live feed" below
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
| `WS /ws/alerts` | user | Live feed |
| `POST /ingest/blocks` | sensor | Up to 100 `blocked` / `unblocked` events |
| `GET /blocks` | user | `active=true/false`, `ip` |
| `POST /actions` | user | Request `block_ip` / `unblock_ip` on a sensor; starts confirmed |
| `GET /actions`, `GET /actions/{id}` | user | List (filter by `status`), detail |
| `POST /actions/{id}/confirm`, `/reject` | user | Decide a pending action (for assistant proposals) |
| `GET /sensor/actions` | sensor | Confirmed actions for this sensor |
| `POST /sensor/actions/{id}/result` | sensor | `{"success": bool, "result": {...}}` |
| `GET/POST /cases`, `GET/PATCH/DELETE /cases/{id}` | user | Cases |
| `POST /cases/{id}/notes` | user | Note, up to 10,000 characters |
| `POST /cases/{id}/alerts`, `DELETE /cases/{id}/alerts/{alert_id}` | user | Attach or detach alerts (an alert is in at most one case) |
| `GET /metrics/summary?hours=24` | user | Alerts per bucket (hourly up to 72 h, else daily), by class and severity, top 10 sources, false-positive rate, detection latency p50/p95, active blocks |
| `GET /topology?hours=1` | user | Nodes (host, alert count, max severity) and edges (src to dst, count, max severity) |
| `GET/POST /admin/users`, `PATCH /admin/users/{id}/role`, `POST /admin/users/{id}/disable`, `/enable`, `/reset-password` | admin | User management |
| `GET/POST /admin/sensors`, `POST /admin/sensors/{id}/revoke` | admin | Sensors; the token is returned once, on creation |
| `GET /admin/audit` | admin | Audit log, filter by `actor`, `action` |

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
- **Last admin.** Demoting or disabling the last enabled admin, including yourself, returns 409.
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

## Database

SQLite (`sqlite:///./soc.db`) for development; PostgreSQL in deployment. Tables are created
with `create_all` at start-up (`soc.api.db.init_db`), which adds missing tables but does not
alter existing ones. Schema migrations (Alembic) are a later step, so until then a model change
means recreating the development database. Timestamps are stored and returned as timezone-aware
UTC.

Tables: `users`, `sensor_tokens`, `alerts`, `blocks`, `actions`, `cases`, `case_notes`,
`audit_log`.
