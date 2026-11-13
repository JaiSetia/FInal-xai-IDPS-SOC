# Live detection (`python -m idps.live`)

One process joins the pieces: capture, features, model, SHAP, alert and response engine.

```
interface or PCAP ─> NFStream flows ─> micro-batch ─> model ─> (non-BENIGN) ─> SHAP top 5 ─┬─> response engine (dry-run by default)
                                                                                           └─> alert: SOC outbox, or a JSON-lines file
```

## Run it

Replay a capture (as fast as possible; for demos and tests):

```sh
python -m idps.live --pcap capture.pcap --model models/friday_xgboost.joblib \
    --alerts-file data/processed/live_alerts.jsonl
```

Live, on an interface (root or `CAP_NET_RAW`):

```sh
python -m idps.live --interface eth0 --model models/friday_xgboost.joblib
```

Options: `--max-flows N`, `--duration SECONDS` (live only), `--batch-size`, `--batch-seconds`,
`--min-alert-confidence`, `--alerts-file`. `--model` defaults to `IDPS_MODEL_PATH`
(`models/model.joblib`). Ctrl-C or SIGTERM flushes the last batch and the outbox, then stops.

Exit codes: 0 normal stop, 1 the capture failed while running, 2 it could not start.

### It refuses to run without a matching model

The bundle is loaded once at startup with the sha256 check and with the capture settings this
process will use (extractor from `IDPS_EXTRACTOR`, default `nfstream`, idle and active timeout
120 s). A missing, tampered or unreadable model, or one trained with a different extractor or
timeouts, ends the run with exit code 2 and a message. There is no "detection without a model" mode.

## Settings

Shared with the rest of the IDPS: `IDPS_MODEL_PATH`, `IDPS_DRY_RUN` (default `true`),
`IDPS_ALLOWLIST` (see the next section), `IDPS_CONFIDENCE_THRESHOLD` (block threshold, default 0.9),
`IDPS_BLOCK_TTL_SECONDS`, `IDPS_EXTRACTOR`.

| Variable | Default | Meaning |
|---|---|---|
| `IDPS_LIVE_MIN_ALERT_CONFIDENCE` | 0.5 | Alerts below this are not sent. Blocking is not affected: it uses `IDPS_CONFIDENCE_THRESHOLD` |
| `IDPS_LIVE_BATCH_SIZE` | 64 | Score a micro-batch at this many flows... |
| `IDPS_LIVE_BATCH_SECONDS` | 2.0 | ...or this long after its first flow, whichever comes first |
| `IDPS_LIVE_TOP_K` | 5 | Features per SHAP explanation |
| `IDPS_LIVE_MAX_EXPLANATIONS_PER_BATCH` | 50 | Alerts per batch that get SHAP; the rest are sent without |
| `IDPS_LIVE_BACKGROUND_SIZE` | 50 | First BENIGN flows kept as SHAP background (only models that need one) |
| `IDPS_LIVE_OUTBOX_MAX_ALERTS` | 5000 | Cap of the SOC outbox |
| `IDPS_LIVE_OUTBOX_FILE` | `data/processed/live_outbox.json` | Where unsent alerts are saved |
| `IDPS_LIVE_ALERTS_FILE` | `data/processed/live_alerts.jsonl` | Alerts when no SOC is configured (mode 0600) |
| `IDPS_LIVE_METRICS_SECONDS` | 10 | Period of the metrics log line |
| `IDPS_SOC_URL` | unset | SOC base URL, `https://` (plain `http://` only for localhost) |
| `IDPS_SOC_SENSOR_TOKEN` (alias `IDPS_SOC_TOKEN`) | unset | Sensor token from `python -m soc.api create-sensor`. Never logged |
| `IDPS_SOC_CA_FILE` | unset | PEM of the CA that signed the SOC certificate |

Setting only one of URL and token is an error (exit 2), not a silent fallback to the file. Only
the `IDPS_`-prefixed names are read; a bare `SOC_URL` or `SOC_TOKEN` in the environment is ignored.
The token is stripped, must not contain whitespace or control characters (exit 2 otherwise, without
printing it), is held as a secret and never appears in logs or error messages.

## Protect your servers: the allowlist is the safeguard

**Every server you protect MUST be in `IDPS_ALLOWLIST`**, next to the gateway, DNS, the SOC host
and the analyst's address, for example `IDPS_ALLOWLIST=10.10.1.1,10.10.2.0/24`. Real blocking
(`IDPS_DRY_RUN=false`) refuses to start with an empty allowlist, but it cannot know which servers
matter; you have to say so.

Why: NFStream names the sender of a flow's *first captured packet* `src_ip`. A capture that starts
mid-conversation, or a long flow cut by the 120 s timeout, yields flows that begin with the
server's reply, so the server shows up as the source. A full replay of the Friday capture produced
1,207 such alerts for the victim web server. Two layers handle it:

1. **Reply direction heuristic** (`block_candidate` in `idps/live/detector.py`). For TCP/UDP, if
   `src_port < dst_port`, `dst_port >= 32768` and `src_port < 32768`, the flow is read as a reply
   and the response engine is given `dst_ip` (the likely offender) instead of `src_ip`. Ports 0
   and other protocols use `src_ip`. The alert payload is not changed (it shows the flow as
   observed). Redirected detections are counted in the metric `reply_direction` and logged.
2. **The allowlist**, which is the real guarantee. The heuristic can be imitated (an attacker
   sending from port 80 to a high port makes the *victim* the block candidate) and it can be wrong
   in the other direction; an allowlisted address is never blocked, whatever the model says.

## Alerts: SOC or file

* **No SOC configured:** each alert is appended to the JSON-lines file, in the format the SOC
  ingests (`soc/api/routes/alerts.py`), so the file can be posted later.
* **SOC configured:** alerts go into an in-memory outbox and a sender thread posts them in batches
  of at most 500 (the SOC's `MAX_BATCH`). If the SOC is down or slow, detection and blocking do not
  wait: the outbox grows, the sender retries with a pause that doubles up to 60 s. A 4xx answer
  drops that batch (retrying cannot help) and is counted. At shutdown one last attempt is made
  and anything unsent is saved to the outbox file, which the next run sends first.

## Bounded memory and what is shed

| Pressure | What happens | Counted as |
|---|---|---|
| More alerts in a batch than `MAX_EXPLANATIONS_PER_BATCH` | The most confident ones get SHAP, the rest go out with an empty `top_features` | `dropped.explanations` |
| Outbox 80% full | No SHAP until it drains, except for detections that can lead to a block (below) | `dropped.explanations` |
| Outbox over its cap | Oldest alerts are dropped | `dropped.alerts` |
| Alert file not writable | The alerts of that batch are lost, detection continues | `dropped.alerts` |
| SOC answers 401/403/404 | The alerts are kept (it is the sensor's URL/token that is wrong), one ERROR line per streak, retried with backoff | `errors.soc_config` |
| A batch fails unexpectedly | Logged with a traceback, the batch is skipped, detection continues (never re-run: some of its flows may already have reached the response engine) | `errors.batch` |
| Scoring slower than capture | The flow queue is bounded (4 batches); the reader waits instead of growing memory | none |

A block is always audited with its explanation: whatever the budget, the first `min_flows` (5)
detections at or above the block threshold per blockable address in a batch are explained, because
the block is triggered by one of them. That is at most 5 SHAP calls per distinct address per
batch, and addresses on the allowlist are skipped.

Explanations are shed first because the alert itself (who, what, how sure) matters more than
its detail. Every shedding event is also logged as a warning.

On stop (SIGINT/SIGTERM, `--duration`) or end of input every flow that already left the capture is
scored, including the ones queued behind the open batch. With `--max-flows` the queue's surplus
beyond the limit is discarded and counted (`flows_discarded`). What NFStream still holds inside
the capture is not processed.

The outbox file and the JSONL file are created with mode 0600 and a symbolic link at their path is
refused. An outbox file is checked when loaded (batches of JSON objects, re-chunked to 500, trimmed
to the cap, at most 64 MiB); one that fails is moved to `<name>.corrupt-<timestamp>`, never
overwritten.

The SHAP background is the first `IDPS_LIVE_BACKGROUND_SIZE` BENIGN flows the loop sees. Tree
models (XGBoost, random forest) need none, so for them it is unused. A kernel explainer (MLP, slow,
not meant for live use) is built once from that sample. A fixed first-N sample is simple and
reproducible, but it reflects the start of the run, not later traffic.

## Blocks are reported to the SOC

When the response engine really blocks an address (not dry-run, and the nftables call succeeded),
the detector queues a block event `{"event": "blocked", "ip", "reason" (max 500 characters),
"expires_at", "source": "auto"}`. `expires_at` is the absolute end of the block (UTC, ISO), fixed
when the block is applied, so a report delayed by an outage still shows the right end; the SOC's
Blocks page shows the block as inactive after it, so no unblock event is sent. `would_block`
decisions in dry-run and failed blocks are never reported.

Block events travel through the same sender thread as the alerts (detection never waits), in
batches of at most 100 (`POST /ingest/blocks`), and are retried while the SOC is unavailable, with
their own backoff: a failing block endpoint never holds back alerts. They wait in a small in-memory
queue of 1000: beyond that the oldest are dropped and counted in `dropped.blocks`, as are events
whose block ended before they could be sent (the SOC refuses a past `expires_at`). A permanent 4xx
answer (for example 422) drops the batch (`dropped.blocks_rejected_by_soc`). Retryable answers
(5xx, 408/425/429) and configuration errors (401/403/404, e.g. an older SOC without the endpoint)
keep the events queued; the failure is logged once per streak. The queue is **not** saved in the
outbox file, so a crash, or a stop while the SOC is down, loses the unsent block reports (the block
itself stays in nftables and in the audit log). Without a SOC, block events are appended to the
alerts file as lines with `"type": "block"`.

## Analyst actions

When a SOC is configured and the sensor captures live (`--interface`; there is no poller in
`--pcap` replay: it can apply real blocks and no analyst waits on a capture file), a daemon thread polls `GET /sensor/actions` every
`IDPS_LIVE_ACTION_POLL_SECONDS` (default 5, range 1 to 300), with a doubling backoff (up to 300 s)
while the SOC is unreachable; a failure streak is logged once. It never blocks detection and is
stopped on shutdown before the sink closes (it checks for the stop request between actions and
reports, and is given up to 15 s to finish the request in progress; results applied but not yet
reported are logged and lost). At most 50 actions are handled per poll. It carries out the `block_ip` / `unblock_ip` requests
an analyst makes (Blocks page "Unblock", Alert page "Block source IP", confirmed assistant
proposals) and reports each outcome with `POST /sensor/actions/{id}/result`.

* **Untrusted input.** Kind, address and `ttl_seconds` are validated; an unknown kind, an invalid
  address or a bad TTL is reported as failed. The TTL defaults to `IDPS_BLOCK_TTL_SECONDS` and is
  capped at 86400. Scoped IPv6 addresses (`fe80::1%eth0`) and text over 45 characters are
  refused everywhere (`normalise_ip`, and again in the nft backend).
* **Same safety rules as automatic blocks**, because everything goes through the response engine:
  the sensor's own `IDPS_ALLOWLIST` (and non-blockable addresses) is checked first and a refused
  block is reported as failed with the reason.
* **Dry-run.** Nothing is applied and the action is reported as failed with
  `sensor is in dry-run: not applied`, so the analyst is not told a block exists when it does not.
* **The override sticks.** After an analyst unblock, the automatic policy does not block that
  address for `IDPS_UNBLOCK_GRACE_SECONDS` (default 3600; 0 disables). Alerts for it are still
  produced and sent; the suppressed block is logged as `block_suppressed_by_analyst` and counted in
  `blocks_suppressed`. An analyst `block_ip` for the address ends the grace period. The window
  restarts counting flows afterwards. The grace period runs on the sensor's own monotonic clock
  while the auto policy's windows use flow time, so in a fast `--pcap` replay the grace covers the
  whole capture.
* **Analyst blocks win over automatic ones.** While an analyst block is active, the auto policy
  does not touch that address (no nft call, no block event), so it can never shorten a 24 h
  block to the default TTL. An unblock clears it. At most `IDPS_MAX_ANALYST_BLOCKS` (default
  1000) analyst blocks are active at once; further ones are reported failed.
* **Blocks page.** A real analyst block is queued like an automatic one (`"source": "analyst"`,
  absolute `expires_at`); a real unblock queues `{"event": "unblocked", "ip"}`.
* **Delivery.** If reporting a result fails (SOC unreachable, 5xx), the outcome is kept (at most
  1000) and re-reported on the next poll without applying the action again. A 409 or 404 means
  the SOC no longer lists the action: forgotten. Any other 4xx (for example 422) gets one minimal
  failed result `{"error": "result refused by the SOC (HTTP n)"}`, because the action would
  otherwise stay confirmed. Ids already executed (at most 5000 remembered) are never executed
  again, including duplicates within one response.
  Counters: `actions.executed`, `actions.failed`.
* **Limitations.** The grace period and the unreported outcomes are in memory: a sensor restart
  forgets them (an action the SOC still lists would then be applied again), and the analyst
  block map with them: after a restart the auto policy may refresh such a block. An analyst unblock only removes the nftables entry; it does not
  stop alerts. Block and unblock events for the Blocks page are not persisted across a restart (see above).

## Metrics

Every `IDPS_LIVE_METRICS_SECONDS` and once at the end, one JSON line on logger `idps.live`:

```json
{"event": "metrics", "uptime_s": 12.0, "flows": 62, "flows_per_s": 422.1, "alerts": 60,
 "dry_run": true, "blocks": 1, "would_block": 1, "blocked": 0,
 "dropped": {"explanations": 0, "alerts": 0, "alerts_rejected_by_soc": 0, "blocks": 0,
             "blocks_rejected_by_soc": 0}, "blocks_sent": 0,
 "shap_ms_per_alert": {"p50": 0.3, "p95": 0.4, "n": 60},
 "latency_flow_end_to_alert_s": {"p50": 1.1, "p95": 2.3, "n": 60}, "outbox_pending": 0}
```

`blocks` is would-block in dry-run and real blocks otherwise. Percentiles cover the last 2000
samples. The plan's budget is SHAP under 50 ms per alert: XGBoost TreeExplainer takes well under
1 ms in the replay test; a kernel explainer would not meet it. `latency_flow_end_to_alert_s` is
recorded in live mode only; in replay the flows are old, so it would just measure the file's age.

## What latency to expect

From the end of a flow to its alert is the wait for the micro-batch (up to `IDPS_LIVE_BATCH_SECONDS`,
2 s by default) plus a few milliseconds for scoring and SHAP. But **NFStream only emits a flow when
it ends or when a timeout fires** (idle 120 s, active 120 s). In the lab a port scan's flows (a
SYN answered by a RST) were not treated as ended: they came out when the 120 s idle timeout fired,
so their alerts arrived about 121 s after the scan (p50 121.2 s, p95 121.8 s). A long-lived
connection, such as a slow attack or a brute-force session kept open, is only reported when the
120 s active timeout cuts it, so its alert is also up to two minutes late. The timeouts are not changed for this: the model was trained on flows made
with 120 s timeouts, and different ones would produce different features (the startup check
refuses a model trained with other settings). If lower latency matters, the fix is to retrain
with shorter timeouts, not to change them here.

### The heartbeat (live mode)

NFStream's flow clock only moves when a packet arrives. On a quiet link (the lab right after an
attack) nothing arrives, so finished flows are never emitted: a scan followed by silence produced
no flows at all in 200 s. In live mode with the NFStream backend, the loop therefore sends one
1-byte UDP broadcast (`255.255.255.255:9`, the discard port) out of the capture interface every
second. NFStream captures it and its clock moves on.

Only the heartbeat's own flow is dropped before scoring: UDP from the heartbeat socket's own
address and port to that broadcast address, with nothing coming back. It is counted in
`heartbeat_flows` and never reaches the model, the SOC or the response engine. Anyone else's
traffic to `255.255.255.255:9`, an attacker's broadcast flood included, is scored as usual, and
nothing is dropped when no heartbeat is running.

It needs Linux (`SO_BINDTODEVICE`). If it can't start for good (no such interface, no permission)
the loop logs a warning and runs without it; if the interface is only down for a while, it keeps
retrying every second. The scapy backend expires flows on a wall-clock timer and doesn't need
it. Turn it off with `--no-heartbeat`.

Replay uses the flows' own timestamps for the response engine's windows, so blocks in a replay are
deterministic.

## Known limitations

* **Heuristic direction.** See above; spoofable, which is why the allowlist is mandatory for servers.
* **Late alerts for long flows** (NFStream timeouts, see above).
* **The SHAP background is the first N benign flows**, not a rolling sample.
* **A batch that fails unexpectedly is skipped**, not retried, so its alerts are lost (counted in
  `errors.batch`).
* **A crash loses the unsent block reports** (they are not in the outbox file).
* **A crash loses the unsent alerts** since the last checkpoint (every metrics period) and the
  batch that was in flight; a clean stop saves them.
* **The outbox file is rewritten whole** at each checkpoint, which costs a little I/O when the
  backlog is large.
* **Dropped alerts are not spilled to disk** when the outbox is over its cap: only counted.
* **NFStream starts its worker processes from the reader thread**, which Python 3.12 reports as a
  "multi-threaded fork" warning. It has caused no problem in replay or in the lab.
* **The heartbeat is visible on the link**: one 1-byte broadcast a second from the sensor's
  address, so it shows that a sensor is there. A host that listens on UDP 9 receives it.
* **The heartbeat needs an IPv4 address on the capture interface.** On a port without one (a
  SPAN port) Linux may pick another interface's address as the source. Not tested.
* **Heartbeat flows count towards `--max-flows`**: about one per 120 s, so slightly fewer real
  flows are scored than the number given.
* **Latency is per flow end**, not per packet: nothing is detected before a flow is emitted.
* **Detection of the same attacker is per flow**: the response engine decides on N flows in a
  window, so the first flows of an attack are alerted but not yet blocked.
* **Shutdown race with a slow SOC.** If the sender thread is still posting when the 30 s join
  times out, the batch in flight may end up neither delivered nor saved. A crash right after a
  successful post re-sends that batch on restart, and the SOC has no idempotency key, so it may
  store the same alerts twice.
* **MLP models only:** the SHAP background for the kernel explainer is fixed when the first BENIGN
  flow arrives, so it can be a single row.
* **Collector log text:** in the cloud collector, `CollectorError` is now an alias of `SocError`,
  so S3 failures are logged as `SocError`. Its behaviour is unchanged.
* **Flows NFStream is still tracking at shutdown are never scored.** On the way out the loop
  stops NFStream's capture process itself (SIGTERM, then SIGKILL after 2 s), because that process
  ignores SIGTERM and Python would otherwise wait for it forever at exit. Before this fix a live
  run with `--duration` stopped detecting on time but never exited (found in the lab, 12 Nov).
* **Redirects from the SOC URL are retried forever** as "SOC unavailable" instead of being
  reported as a configuration error. Fix the URL.
* **`live_alerts.jsonl` is not rotated.** Rotate it with logrotate or a similar tool on long runs.

## Friday replay check (12 Nov 2026)

`python -m idps.live --pcap Friday-WorkingHours.pcap --model models/friday_xgboost.joblib`, run
in dry-run:

- **Speed:** 513,501 flows in about 2 min 16 s, about 3,800–5,000 flows/s. SHAP p50 0.12 ms and
  p95 0.28 ms per alert, with no errors.
- **Alerts:** 223,421.
- **Reply detection:** it moved 1,127 detections to the other side of the flow.
- **Without the allowlist:** the protected web server 192.168.10.50 still collected 2 would-blocks.
  These came from scan replies sent from high ports (for example 58080 → 39492), which port
  numbers alone can't tell apart from real attacks.
- **With `IDPS_ALLOWLIST=192.168.10.50,192.168.10.3`:** only the attacker 172.16.0.1 and the five
  bot-infected hosts were marked for blocking.

## Lab sensor check (12 Nov 2026)

Live capture on `lab_attack` in the Docker lab, `models/friday_xgboost.joblib`,
`IDPS_ALLOWLIST=10.10.1.1,10.10.1.2,10.10.2.0/24`, attack `lab/attacks/portscan.sh` (nmap SYN scan
of ports 1–1024 on the victim):

- **Dry-run (180 s):** all 1,024 scan flows were scored and alerted as PortScan, 121 s after the
  scan (the idle timeout). One `would_block`, for the attacker 10.10.1.10 (confidence 0.99999);
  no victim, gateway or sensor address was marked. 810 alerts had a SHAP explanation (p95 0.42 ms),
  214 went out without one because of the 50-per-batch cap. No errors.
- **Real blocking** (`IDPS_DRY_RUN=false`, `IDPS_BLOCK_TTL_SECONDS=60`): 10.10.1.10 was added to
  `inet idps blocked4` with a 60 s timeout. While it was blocked the attacker got no answer from
  DVWA (HTTP timeout) or the victim (ping 100% loss), and the drop rule counted 6 packets. At
  exactly 60 s nftables removed the element by itself, and DVWA (HTTP 302) and ping worked again.
- **Without the heartbeat** the same scan produced no flows at all, which is why it exists.

### With the lab SOC and dashboard (12 Nov 2026)

`lab/sensor/live.sh` with the lab SOC (`lab/README.md`):

- **Dry-run:** a port scan's 1,024 PortScan alerts reached the SOC about 2 minutes after the scan
  (all sent, none left in the outbox) and appeared on the dashboard's Alerts page through its live
  feed, each with its SHAP explanation.
- **Real blocking** (60 s): the block of 10.10.1.10 appeared on the Blocks page without a reload,
  with the same 60 s end time as nftables, and left the "active only" list when nftables removed
  it. The Metrics page showed the alerts by class, top source and a detection latency of 2.0 min.

### Analyst actions in the lab (12 Nov 2026)

Live loop with real blocking (`IDPS_DRY_RUN=false`), actions sent through the SOC API as the
dashboard buttons send them:

- **Analyst block** of 10.10.1.10 (5 min): applied by the sensor 5 s after the request (one
  poll), reported `executed`, added to `inet idps blocked4` with a 5 min timeout, listed on the
  Blocks page with source `analyst`. The attacker got no answer from DVWA.
- **Analyst unblock**: applied within a second, reported `executed`; the element left nftables,
  the Blocks page showed the block as ended, and DVWA answered the attacker again (HTTP 302).
- **Grace period**: a new port scan right after produced 1,024 alerts, all delivered to the SOC,
  but no new block: the automatic block decisions (204) were suppressed because an analyst had
  unblocked that address.

This run used the new code copied into the running sensor container, because Docker's network
kept timing out while rebuilding the image; the image picks the code up on its next build.
