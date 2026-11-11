# Cloud collector (`idps/cloud`)

Reads VPC Flow Logs of the target VPC from S3, scores them with a cloud model, sends alerts to the
SOC, and blocks attacker addresses with network ACL deny entries. The AWS side (VPC, flow logs,
network ACL, IAM role) is in `infra/`; the cost budget is a separate stack in `infra/budget/`; read `infra/README.md` first.

```
target VPC --flow logs (every 60 s window, delivered in batches)--> S3 bucket
                                                                       |
   idps.cloud collector  <---------- list + read new objects -----------+
     parse -> NetFlow-style rows -> cloud model -> alerts --POST /ingest/alerts--> SOC
                                        |
                                  response engine (allowlist, threshold, N flows, dry-run)
                                        |
                              NaclBlocker: DENY /32 entries, rule numbers 1-90
```

## Install and run

```bash
pip install -e ".[dev,cloud]"          # boto3 is an optional extra, imported only when used

python -m idps.cloud parse tests/data/flowlogs_sample.log          # summary and first rows
python -m idps.cloud collect --once                                # one cycle, then exit
python -m idps.cloud collect --interval 60                         # loop (Ctrl+C to stop)
```

AWS credentials come from the usual boto3 chain. Use the collector role from
`terraform output collector_role_arn` (it exists once `collector_trusted_principal_arns` is set;
for example a profile with `role_arn` and `source_profile` in `~/.aws/config`), not your admin
credentials. Install with `pip install -c requirements-cloud.lock -e ".[dev,cloud]"`: use that
file instead of `requirements.lock` (botocore needs `python-dateutil<3`, the main lock pins 4).

| Variable | Meaning |
|---|---|
| `IDPS_CLOUD_BUCKET` | Flow-log bucket (`terraform output flow_log_bucket`). Required |
| `IDPS_CLOUD_PREFIX` | Key prefix `AWSLogs/<account-id>/vpcflowlogs/<region>/` (`terraform output flow_log_prefix`). **Required**: real keys continue with `YYYY/MM/DD/`, so a shorter prefix such as `AWSLogs/` lists nothing. It must end in `vpcflowlogs/<region>/` and the region must match `IDPS_CLOUD_REGION` if that is set |
| `IDPS_CLOUD_NACL_ID` | Target network ACL (`terraform output target_nacl_id`); needed only for real blocking |
| `IDPS_CLOUD_REGION` | Region (else `AWS_REGION`) |
| `IDPS_CLOUD_MODEL` | Cloud model bundle; without it flow logs are only counted and logged |
| `IDPS_CLOUD_STATE_DIR` | Checkpoint and block state, default `./cloud_state` |
| `IDPS_CLOUD_MAX_DENIES` | Active deny cap, default and maximum 10 (a network ACL allows 20 rules per direction) |
| `IDPS_CLOUD_MIN_FLOWS` | Malicious rows from one source before a block, default 5 |
| `IDPS_CLOUD_LOOKBACK_HOURS` | How far back the very first run looks, default 1 |
| `IDPS_CLOUD_MIN_ALERT_CONFIDENCE` | Alerts below this are not sent, default 0.5 |
| `IDPS_SOC_URL`, `IDPS_SOC_SENSOR_TOKEN` | SOC base URL (must be `https://`, except localhost) and a sensor token (`python -m soc.api create-sensor`). Without them alerts are not sent |
| `IDPS_SOC_CA_FILE` | PEM file of the CA that signed the SOC's certificate. The lab SOC uses Caddy's own CA: copy its root certificate (`infra/README.md`, "Trust the SOC certificate"). Verification is never disabled; without this the system trust store is used and the lab SOC is not trusted |
| `IDPS_DRY_RUN`, `IDPS_ALLOWLIST`, `IDPS_CONFIDENCE_THRESHOLD`, `IDPS_BLOCK_TTL_SECONDS` | The same settings as the lab sensor (`idps/config.py`) |

The collector's own machine must be in the SOC security group (`sensor_cidrs` in Terraform).

## Flow logs are much coarser than the lab features

A flow log record is one line per interface, 5-tuple, direction and **capture window** (60 s here):
addresses, ports, protocol, packets, bytes, start, end, ACCEPT or REJECT. There are no TCP flags,
no packet sizes (only a byte total), no inter-arrival times, and a long connection appears as one
record per window. The lab sensor (`idps/features`) computes about 40 CICFlowMeter-style features
from every packet. The two feature sets are therefore **not interchangeable**, and a model trained
on the lab data cannot score flow logs.

`idps.cloud.flowlogs` turns records into rows with a stable list of columns,
`CLOUD_FEATURE_COLUMNS` (identity columns, then `duration_ms`, `fwd_/bwd_packets`, `fwd_/bwd_bytes`,
`bytes_per_s`, `packets_per_s`, `down_up_ratio`, `fwd_/bwd_pkt_len_mean`, `rejected`). The two
directions of a connection are paired into one row. Real flow logs give each direction its own
`start` and `end` (first and last packet seen in that direction), which differ by a second or two,
so records are paired on interface, protocol and the unordered endpoint pair when they are in the
same 60 s window (same aligned minute, or overlapping `[start, end]`). The initiator is the side
whose destination is a well-known port (below 1024), else the side with the higher source port
(both heuristics); a REJECTed or one-way record has zero `bwd_*`. `fwd` is NetFlow's
`IN_*` and `bwd` is `OUT_*`.

So the cloud needs **its own model**, trained later on NetFlow-style datasets such as
NF-UNSW-NB15 or NF-CSE-CIC-IDS2018 (map their `IN_BYTES`, `OUT_BYTES`, `IN_PKTS`, `OUT_PKTS`,
`FLOW_DURATION_MILLISECONDS`, `L4_DST_PORT`, `PROTOCOL` onto `CLOUD_MODEL_FEATURES`; features
that have no flow-log equivalent must be dropped from the dataset, not guessed). A bundle for the
collector must be saved with `extraction_meta=cloud_extraction_meta()` and features from
`CLOUD_MODEL_FEATURES`. The collector loads it with the same integrity checks as
`idps.detect.bundle.load_bundle` (sha256 file, permissions) but checks the cloud column layout
instead of the lab one, and refuses a lab bundle.

Latency: flow logs are written per 60 s window and delivered to S3 every few minutes, so cloud
detection is near-real-time at best (minutes), unlike the lab sensor. Measure and report it.

## Blocking with the network ACL

`NaclBlocker` (`idps/cloud/nacl.py`) plugs into the same `ResponseEngine` as the nftables blocker,
so the **same policy code** decides: allowlist first (and loopback, multicast, link-local,
reserved, unspecified), confidence threshold, N malicious rows in a window, TTL. Dry-run is the
default (`IDPS_DRY_RUN` true): it logs `would_block`, makes **no EC2 calls at all**, and writes no
state. Turning dry-run off requires `IDPS_ALLOWLIST` and `IDPS_CLOUD_NACL_ID`. Put the target VPC
CIDR on the allowlist: a flow row can have the victim as its source (an unpaired reply), and the
victim must never be denied.

- A block is two DENY entries (ingress and egress, protocol all) for one `/32` (or `/128`) in rule
  numbers **1 to 90**. The code refuses to create, replace or delete any other number. Terraform
  owns 100 and up (see `infra/README.md`), so they never fight.
- Network ACL entries cannot expire, so expiry times are in a JSON state file
  (`<state dir>/nacl_state.json`, mode 600). The collector deletes expired entries at the start of
  every cycle.
- **Reconciliation** at start-up (`DescribeNetworkAcls`): an expired block is deleted; a deny in
  1 to 90 that the state does not know is adopted with a fresh TTL; a deny for an address that is
  now allowlisted is deleted; a block whose entry someone removed is recreated; entries in 1 to 90
  that are not single-host denies are left alone (their numbers count as taken).
- **Cap.** At most `IDPS_CLOUD_MAX_DENIES` (default 10) addresses are denied at once, because
  network ACLs default to 20 rules per direction and Terraform's allow rules count against that.
  At the cap a new block is **refused** (logged as `nacl_block_refused`; the engine records a failed
  block and tries again on a later flow), so an attacker spraying many source addresses cannot
  flush the real blocks. Only a block with less than 2 minutes left may be evicted for a new one
  (its entries are replaced with `ReplaceNetworkAclEntry`), and an evicted address is released in
  the policy so it can be blocked again. `NetworkAclEntryLimitExceeded` from AWS counts as "at the
  cap" and pauses new blocks for 5 minutes instead of retrying. A block that was only half
  installed (ingress without egress) is completed by the next `block()` call for that address.
  **Put the addresses you administer from (admin IP, sensors, the SOC host, the target VPC) on
  `IDPS_ALLOWLIST`**: allowlisted addresses are never blocked, so they cannot fill the cap.
- One collector process per network ACL; the state file is not locked.

## Checkpoint and delivery

S3 can publish an object after newer ones, so the collector does not use a "newest LastModified"
mark. `<state dir>/checkpoint.json` holds the keys of processed objects (with their
`LastModified`) for a sliding 2 hours behind the newest one, and each cycle lists the day folders
(`.../YYYY/MM/DD/`) from 2 hours before that and processes every unseen object. Only objects
older than 5 minutes are read, because delivery may still be writing earlier-stamped objects. The
first run looks back `IDPS_CLOUD_LOOKBACK_HOURS`. An object published more than 2 hours late is
not read. A corrupt, oversized (64 MB decompressed) or out-of-range object is logged and skipped. A
version 1 checkpoint is converted on load.

Each object is handled in this order: score, **response engine**, queue the alerts, mark the
object processed. Blocking therefore never waits for the SOC. Alerts go to
`<state dir>/outbox.json` (at most 20,000; the oldest are dropped beyond that) and are sent in
batches of 500, oldest first, at the end of every cycle:

- accepted batch: removed from the outbox at once, so it is never sent twice;
- 5xx, timeout or network error (and 408/425/429): retried 3 times with backoff, then the rest
  stays queued for the next cycle;
- other 4xx (a rejected batch, a bad token): permanent, so the batch is logged and dropped, not
  retried forever.

`run_forever` never exits on an error: any exception in a cycle (S3, AWS throttling, a full disk)
is logged and the loop pauses with a growing delay (up to 15 minutes) before the next cycle. A
`BlockerError` while expiring old blocks is logged and the cycle continues. Hive-style
partitioned keys are not supported (the Terraform flow log uses the default layout).

## The SOC payload

`POST /ingest/alerts` with `Authorization: Bearer <sensor token>` and
`{"alerts": [...]}`, at most 500 per request. Each alert is one flow row: `src_ip`, `src_port`,
`dst_ip`, `dst_port`, `protocol`, `start_ms`, `end_ms` (window start and end), `predicted_class`,
`confidence`, optional `anomaly_score`, and an `explanation` with no features yet (there is no
SHAP for the cloud model). The tests validate the payload against the SOC's own `AlertIn` model.
Rows that would make the SOC reject the whole batch (confidence outside 0 to 1, times beyond
year 2100) are dropped by the collector.

Not done yet: reporting blocks to `POST /ingest/blocks` (blocks appear in the collector's log
only), and polling `GET /sensor/actions` for analyst block requests.

## Tests

`tests/test_cloud_*.py` use local sample files (`tests/data/flowlogs_sample.log`) and botocore's
`Stubber`: no network, no AWS, no credentials. They are skipped if boto3 is not installed
(`pip install -e ".[dev,cloud]"`).
