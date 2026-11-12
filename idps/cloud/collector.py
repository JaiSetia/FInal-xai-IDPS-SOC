"""Read new VPC Flow Log objects from S3, score them, alert the SOC, block via the network ACL.

One cycle (`Collector.run_once`):
  1. delete expired network ACL denies (a failing AWS call is logged, not fatal);
  2. list flow-log objects that have settled (older than SETTLE_SECONDS) and were not processed;
  3. for each: parse -> NetFlow-style rows -> score with the cloud model (if configured) ->
     give the detections to the response engine (dry-run by default) -> queue the alerts in the
     outbox -> remember the object as processed;
  4. send the outbox to the SOC, batch by batch.

The response engine never waits for the SOC: an unreachable SOC delays the alerts (they stay in
`outbox.json` and are retried every cycle, 5xx and network errors with backoff), it does not delay
blocking. A batch the SOC refuses with a 4xx is permanent (retrying cannot help): it is logged
and dropped. An accepted batch leaves the outbox at once, so it is never sent twice.

An object that cannot be read at all (corrupt, too large) is logged and skipped so one bad file
cannot block the rest. Objects are identified by key, not by a LastModified high-water mark: S3
can publish an object late, so processed keys are remembered for REMEMBER_WINDOW.
"""

from __future__ import annotations

import io
import json
import logging
import os
import re
import time
from collections import Counter
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

import joblib

from idps.cloud.flowlogs import (
    CLOUD_EXTRACTOR,
    CLOUD_FEATURE_COLUMNS,
    FlowLogError,
    ParseStats,
    read_s3_object,
    rows_to_frame,
    to_flow_rows,
)
from idps.cloud.nacl import NaclBlocker, _aws_errors
from idps.respond.engine import ResponseEngine
from idps.respond.nft import BlockerError
from idps.respond.policy import BENIGN_LABELS, Action, Detection
from idps.soc_client import (  # noqa: F401  re-exported: the SOC client moved to idps.soc_client
    MAX_BATCH,
    MAX_MS,
    MAX_OUTBOX_ALERTS,
    Outbox,
    Prediction,
    SocClient,
    SocError,
    SocRejectedError,
    alert_payload,
    score_frame,
)
from idps.soc_client import write_json as _write_json

log = logging.getLogger("idps.cloud.collector")

CollectorError = SocError  # the cloud collector's name for "outside our control, retry next cycle"

MAX_LOOKBACK_DAYS = 31
LOG_SUFFIXES = (".log", ".log.gz")
SETTLE_SECONDS = 300.0  # only objects older than this are read (delivery can lag)
REMEMBER_WINDOW = timedelta(hours=2)  # processed keys are remembered this long
SEND_ATTEMPTS = 3
RETRY_BASE_SECONDS = 2.0
MAX_CYCLE_BACKOFF_SECONDS = 900.0


# --- Configuration ----------------------------------------------------------------------------

@dataclass
class CollectorConfig:
    bucket: str
    prefix: str = ""  # required: AWSLogs/<account-id>/vpcflowlogs/<region>/
    nacl_id: str | None = None
    region: str | None = None
    state_dir: Path = Path("cloud_state")
    model_path: str | None = None
    soc_url: str | None = None
    sensor_token: str | None = field(default=None, repr=False)  # never printed
    soc_ca_file: str | None = None  # PEM file that signed the SOC's certificate
    max_denies: int = 10
    min_flows: int = 5
    initial_lookback_hours: float = 1.0
    min_alert_confidence: float = 0.5

    def validate(self) -> None:
        """Raise ValueError for a configuration that cannot work."""
        self.prefix = validate_prefix(self.prefix, self.region)

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> CollectorConfig:
        env = os.environ if env is None else env

        def get(name: str) -> str | None:
            value = env.get(name, "").strip()
            return value or None

        def number(name: str, cast, default):
            raw = get(name)
            if raw is None:
                return default
            try:
                return cast(raw)
            except ValueError:
                raise ValueError(f"{name} must be a number, got {raw!r}") from None

        return cls(
            bucket=get("IDPS_CLOUD_BUCKET") or "",
            prefix=get("IDPS_CLOUD_PREFIX") or "",
            nacl_id=get("IDPS_CLOUD_NACL_ID"),
            region=get("IDPS_CLOUD_REGION") or get("AWS_REGION") or get("AWS_DEFAULT_REGION"),
            state_dir=Path(get("IDPS_CLOUD_STATE_DIR") or "cloud_state"),
            model_path=get("IDPS_CLOUD_MODEL"),
            soc_url=get("IDPS_SOC_URL"),
            sensor_token=get("IDPS_SOC_SENSOR_TOKEN"),
            soc_ca_file=get("IDPS_SOC_CA_FILE"),
            max_denies=number("IDPS_CLOUD_MAX_DENIES", int, 10),
            min_flows=number("IDPS_CLOUD_MIN_FLOWS", int, 5),
            initial_lookback_hours=number("IDPS_CLOUD_LOOKBACK_HOURS", float, 1.0),
            min_alert_confidence=number("IDPS_CLOUD_MIN_ALERT_CONFIDENCE", float, 0.5),
        )


_PREFIX_RE = re.compile(r"(?:^|/)vpcflowlogs/([a-z0-9-]+)/$")


def validate_prefix(prefix: str, region: str | None = None) -> str:
    """The S3 prefix of the flow logs: AWSLogs/<account-id>/vpcflowlogs/<region>/ (a trailing
    slash is added). Real keys continue with YYYY/MM/DD/, so a shorter prefix such as "AWSLogs/"
    would list nothing. If the region is known it must match the one in the prefix."""
    prefix = (prefix or "").strip()
    if not prefix:
        raise ValueError("set IDPS_CLOUD_PREFIX (or --prefix) to AWSLogs/<account-id>/vpcflowlogs/"
                         "<region>/ (terraform output flow_log_prefix)")
    if not prefix.endswith("/"):
        prefix += "/"
    match = _PREFIX_RE.search(prefix)
    if match is None:
        raise ValueError(f"IDPS_CLOUD_PREFIX {prefix!r} must end in vpcflowlogs/<region>/, "
                         "e.g. AWSLogs/123456789012/vpcflowlogs/eu-west-1/")
    if region and match.group(1) != region:
        raise ValueError(f"IDPS_CLOUD_PREFIX is for region {match.group(1)!r} but the region "
                         f"is {region!r}")
    return prefix


def make_client(service: str, region: str | None = None):
    """A boto3 client. boto3 is an optional dependency, so it is imported here."""
    try:
        import boto3
    except ImportError as exc:
        raise CollectorError('boto3 is not installed: pip install -e ".[cloud]"') from exc
    return boto3.client(service, region_name=region)


# --- Model ------------------------------------------------------------------------------------

def load_cloud_bundle(path: str | Path):
    """Load a cloud model bundle with the same integrity checks as idps.detect.bundle.load_bundle
    (sha256 file, permissions), but against CLOUD_FEATURE_COLUMNS instead of the lab layout."""
    from idps.detect.bundle import BUNDLE_FORMAT, Bundle, _read_verified

    path = Path(path)
    bundle = joblib.load(io.BytesIO(_read_verified(path)))
    if not isinstance(bundle, Bundle):
        raise TypeError(f"{path} is not an IDPS model bundle")
    if bundle.format != BUNDLE_FORMAT:
        raise ValueError(f"unsupported bundle format {bundle.format}")
    meta = bundle.extraction_meta
    if meta.get("extractor") != CLOUD_EXTRACTOR or meta.get("feature_columns") != CLOUD_FEATURE_COLUMNS:
        raise ValueError(
            f"{path} was not trained on VPC flow log features (extractor {meta.get('extractor')!r}); "
            "the cloud collector needs a model trained with the CLOUD_FEATURE_COLUMNS layout")
    missing = [c for c in bundle.features if c not in CLOUD_FEATURE_COLUMNS]
    if missing:
        raise ValueError(f"model uses features the flow logs do not provide: {missing}")
    return bundle


# --- Checkpoint and listing -------------------------------------------------------------------

def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


class Checkpoint:
    """Which flow-log objects were already processed.

    S3 publishes objects late and not in LastModified order, so a "newest LastModified" high-water
    mark would skip a late object for good. Instead the processed keys are remembered (with their
    LastModified) for REMEMBER_WINDOW behind the newest one; `high_water` only bounds how far back
    the next listing has to look.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.high_water: datetime | None = None
        self.processed: dict[str, datetime] = {}
        self._load()

    @property
    def last_modified(self) -> datetime | None:  # the newest processed object
        return self.high_water

    def _load(self) -> None:
        try:
            data = json.loads(self.path.read_text())
            if "processed" in data:
                self.processed = {k: _aware(datetime.fromisoformat(v))
                                  for k, v in data["processed"].items()}
                self.high_water = _aware(datetime.fromisoformat(data["high_water"]))
            else:  # version 1: the newest timestamp and the keys that share it
                self.high_water = _aware(datetime.fromisoformat(data["last_modified"]))
                self.processed = {k: self.high_water for k in data.get("keys", [])}
        except FileNotFoundError:
            pass
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
            log.error("ignoring unreadable checkpoint %s: %s", self.path, exc)
            self.high_water, self.processed = None, {}

    def is_new(self, last_modified: datetime, key: str) -> bool:
        return key not in self.processed

    def horizon(self) -> datetime | None:
        """Objects last modified before this are not looked at again."""
        return None if self.high_water is None else self.high_water - REMEMBER_WINDOW

    def advance(self, last_modified: datetime, key: str) -> None:
        last_modified = _aware(last_modified)
        self.processed[key] = last_modified
        if self.high_water is None or last_modified > self.high_water:
            self.high_water = last_modified
        cutoff = self.horizon()
        self.processed = {k: v for k, v in self.processed.items() if v >= cutoff}
        _write_json(self.path, {
            "version": 2, "high_water": self.high_water.isoformat(),
            "processed": {k: v.isoformat() for k, v in sorted(self.processed.items())},
        })


def list_new_objects(s3, bucket: str, prefix: str, checkpoint: Checkpoint, now: datetime,
                     lookback: timedelta, settle: timedelta | None = None) -> list[dict]:
    """Flow-log objects that have settled and were not processed, oldest first.

    S3 keys are `<prefix>YYYY/MM/DD/...`, so only the day folders from the look-back start to
    today are listed. The start is `lookback` before now on the first run, afterwards
    REMEMBER_WINDOW before the newest processed object (a late object older than that is given
    up). An object younger than `settle` is left for a later cycle: delivery may still be writing
    objects with earlier timestamps.
    """
    if not prefix.endswith("/"):
        prefix += "/"
    settle = timedelta(seconds=SETTLE_SECONDS) if settle is None else settle
    start = checkpoint.horizon() or (now - lookback)
    start = max(start, now - timedelta(days=MAX_LOOKBACK_DAYS))
    ready = now - settle
    day = (start - timedelta(days=1)).date()  # a window that ended after midnight is in the earlier folder
    found: list[dict] = []
    while day <= now.date():
        token = None
        while True:
            params = {"Bucket": bucket, "Prefix": f"{prefix}{day:%Y/%m/%d}/"}
            if token:
                params["ContinuationToken"] = token
            response = s3.list_objects_v2(**params)
            for obj in response.get("Contents", []):
                key = obj["Key"]
                if not key.endswith(LOG_SUFFIXES):
                    continue
                modified = obj["LastModified"]
                if modified >= start and modified <= ready and checkpoint.is_new(modified, key):
                    found.append({"Key": key, "LastModified": modified})
            if not response.get("IsTruncated"):
                break
            token = response.get("NextContinuationToken")
        day += timedelta(days=1)
    found.sort(key=lambda o: (o["LastModified"], o["Key"]))
    return found


# --- The collector ----------------------------------------------------------------------------

@dataclass
class CycleResult:
    objects: int = 0
    skipped_objects: int = 0
    records: int = 0
    malformed: int = 0
    rows: int = 0
    alerts_queued: int = 0
    alerts_sent: int = 0
    alerts_pending: int = 0
    batches_rejected: int = 0
    would_block: int = 0
    blocked: int = 0
    expired: int = 0

    def as_dict(self) -> dict:
        return dict(self.__dict__)


class Collector:
    def __init__(
        self,
        config: CollectorConfig,
        s3,
        *,
        bundle=None,
        engine: ResponseEngine | None = None,
        blocker: NaclBlocker | None = None,
        post: Callable[[list[dict]], dict] | None = None,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        config.validate()
        self.config = config
        self.s3 = s3
        self.bundle = bundle
        self.engine = engine
        self.blocker = blocker
        self.post = post
        self._now = now
        self._sleep = sleep
        self.checkpoint = Checkpoint(config.state_dir / "checkpoint.json")
        self.outbox = Outbox(config.state_dir / "outbox.json")
        if bundle is None:
            log.warning("no model configured (IDPS_CLOUD_MODEL): flow logs are only counted, "
                        "no alerts are produced")
        if post is None:
            log.warning("no SOC configured (IDPS_SOC_URL, IDPS_SOC_SENSOR_TOKEN): "
                        "alerts are not sent")

    def run_once(self) -> CycleResult:
        result = CycleResult()
        if self.blocker is not None:
            try:
                result.expired = len(self.blocker.expire())
            except BlockerError as exc:  # e.g. RequestLimitExceeded: try again next cycle
                log.error("could not expire network ACL entries, will retry: %s", exc)
        aws_errors = _aws_errors()
        try:
            objects = list_new_objects(
                self.s3, self.config.bucket, self.config.prefix, self.checkpoint, self._now(),
                timedelta(hours=self.config.initial_lookback_hours))
            for obj in objects:
                try:
                    self._process(obj["Key"], result)
                except (FlowLogError, OverflowError) as exc:
                    log.error("skipping unreadable object %s: %s", obj["Key"], exc)
                    result.skipped_objects += 1
                self.checkpoint.advance(obj["LastModified"], obj["Key"])
                result.objects += 1
        except aws_errors as exc:  # S3 trouble: keep the checkpoint where it is, retry later
            raise CollectorError(f"S3 request failed: {exc}") from exc
        finally:
            self._flush_outbox(result)  # alerts of finished objects go out even if a later one failed
        log.info(json.dumps({"event": "cycle", **result.as_dict()}))
        return result

    def run_forever(self, interval_seconds: float, sleep: Callable[[float], None] | None = None) -> None:
        """Run cycles until interrupted. Nothing but KeyboardInterrupt/SystemExit stops it: a
        failing cycle is logged and retried after a growing pause (up to MAX_CYCLE_BACKOFF)."""
        sleep = sleep or self._sleep
        failures = 0
        while True:
            try:
                self.run_once()
                failures = 0
            except Exception as exc:
                failures += 1
                log.error("cycle failed (%d in a row), will retry: %s: %s", failures,
                          type(exc).__name__, exc, exc_info=not isinstance(exc, CollectorError))
            pause = interval_seconds
            if failures:
                pause = min(interval_seconds * 2 ** min(failures, 10), MAX_CYCLE_BACKOFF_SECONDS)
            sleep(pause)

    def _flush_outbox(self, result: CycleResult) -> None:
        """Send queued batches oldest first. A 5xx or network error is retried with backoff and,
        if it persists, leaves the rest queued for the next cycle; a 4xx drops that one batch."""
        if self.post is None:
            return
        while self.outbox.batches:
            batch = self.outbox.batches[0]
            for attempt in range(1, SEND_ATTEMPTS + 1):
                try:
                    self.post(batch)
                except SocRejectedError as exc:
                    log.error("SOC refused a batch of %d alerts, dropping it: %s", len(batch), exc)
                    result.batches_rejected += 1
                    break
                except CollectorError as exc:
                    if attempt == SEND_ATTEMPTS:
                        log.error("SOC unavailable, %d alerts stay queued: %s", len(self.outbox), exc)
                        result.alerts_pending = len(self.outbox)
                        return
                    self._sleep(RETRY_BASE_SECONDS * 2 ** (attempt - 1))
                else:
                    result.alerts_sent += len(batch)
                    break
            self.outbox.pop_first()
        result.alerts_pending = 0

    def _process(self, key: str, result: CycleResult) -> None:
        stats = ParseStats()
        records = read_s3_object(self.s3, self.config.bucket, key, stats)
        rows = to_flow_rows(records)
        result.records += stats.records
        result.malformed += stats.malformed
        result.rows += len(rows)
        if stats.malformed:
            log.warning("%s: %d malformed line(s), e.g. %s", key, stats.malformed, stats.errors[:3])
        if self.bundle is None or not rows:
            self._log_counts(key, rows)
            return
        predictions = score_frame(self.bundle, rows_to_frame(rows))
        flagged = [(row, p) for row, p in zip(rows, predictions, strict=True)
                   if p.label.strip().lower() not in BENIGN_LABELS]
        alerts = [a for row, p in flagged
                  if p.confidence >= self.config.min_alert_confidence
                  and (a := alert_payload(row, p)) is not None]
        if self.engine is not None:  # blocking never waits for the SOC
            for row, p in flagged:
                decision = self.engine.handle(Detection(
                    src_ip=row["src_ip"], label=p.label, confidence=p.confidence,
                    timestamp=row["end_ms"] / 1000.0))
                if decision.action is Action.BLOCK:
                    if self.engine.dry_run:
                        result.would_block += 1
                    else:
                        result.blocked += 1
        if self.post is not None and alerts:
            self.outbox.add(alerts)
            result.alerts_queued += len(alerts)

    @staticmethod
    def _log_counts(key: str, rows: list[dict]) -> None:
        rejected = Counter(r["src_ip"] for r in rows if r["rejected"])
        log.info(json.dumps({"event": "counted", "object": key, "rows": len(rows),
                             "rejected": sum(rejected.values()),
                             "top_rejected_sources": rejected.most_common(3)}))
