"""What every sensor needs to talk to the SOC: the alert payload, the HTTPS client and the outbox.

Shared by the cloud collector (idps.cloud.collector) and the live detection loop (idps.live).
Standard library only (no extra dependency).
"""

from __future__ import annotations

import json
import logging
import math
import os
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pandas as pd

log = logging.getLogger("idps.soc_client")

MAX_BATCH = 500  # soc/api/routes/alerts.py MAX_BATCH: the SOC refuses a bigger POST
MAX_BLOCK_EVENTS = 100  # soc/api/routes/blocks.py MAX_EVENTS (idps does not import soc: mirrored)
MAX_RESPONSE_BYTES = 1024 * 1024  # an answer bigger than this is refused (SocError)
MAX_MS = 4_102_444_800_000  # soc/api/routes/alerts.py MAX_MS (year 2100)
MAX_OUTBOX_ALERTS = 20_000  # default: oldest unsent alerts are dropped beyond this
RETRYABLE_4XX = frozenset({408, 425, 429})
CONFIG_ERROR_STATUSES = frozenset({401, 403, 404})  # wrong token, revoked sensor, wrong URL
MAX_OUTBOX_FILE_BYTES = 64 * 1024 * 1024  # a bigger outbox file is not read (treated as corrupt)


class SocError(RuntimeError):
    """Something outside our control failed (SOC unreachable, 5xx): retry later."""

    status: int | None = None  # the HTTP status, when there was an answer


class SocRejectedError(SocError):
    """The SOC answered with a 4xx: the batch itself is refused, retrying cannot help.

    For 401/403/404 (`is_config_error`) the batch is fine and the sensor's configuration is
    not: a long-running sensor should keep its alerts and tell the operator."""

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status

    @property
    def is_config_error(self) -> bool:
        return self.status in CONFIG_ERROR_STATUSES


def validate_token(token: str) -> str:
    """The token without surrounding whitespace; ValueError if it still contains whitespace or
    control characters (they would be sent in an HTTP header). The message never shows the token."""
    token = token.strip()
    if not token:
        raise ValueError("the sensor token is empty")
    if any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in token):
        raise ValueError("the sensor token contains whitespace or control characters")
    return token


# --- Predictions and the alert payload ---------------------------------------------------------

@dataclass(frozen=True)
class Prediction:
    label: str
    confidence: float
    anomaly_score: float | None = None


def score_frame(bundle, df: pd.DataFrame) -> list[Prediction]:
    """Classify every row. Works with any object shaped like idps.detect.bundle.Bundle."""
    if df.empty:
        return []
    X = df[bundle.features].astype(float)
    proba = np.asarray(bundle.predict_proba(X))
    classes = [str(c) for c in bundle.label_encoder.classes_]
    idx = proba.argmax(axis=1)
    conf = proba[np.arange(len(idx)), idx]
    anomaly = None
    if getattr(bundle, "anomaly", None) is not None:
        anomaly = np.asarray(bundle.anomaly_scores(X), dtype=float)
    return [
        Prediction(classes[i], float(c), None if anomaly is None else float(anomaly[n]))
        for n, (i, c) in enumerate(zip(idx, conf, strict=True))
    ]


def alert_payload(row: dict, pred: Prediction, explanation: dict | None = None) -> dict | None:
    """One entry of the POST /ingest/alerts body (soc.api.routes.alerts.AlertIn), or None if the
    row could not be accepted (one bad alert would make the SOC reject the whole batch).

    `explanation` is an idps.explain record; without one the alert carries an explanation with
    no features, which still names the class and confidence."""
    if not (math.isfinite(pred.confidence) and 0.0 <= pred.confidence <= 1.0):
        return None
    if not (0 <= row["start_ms"] <= row["end_ms"] <= MAX_MS):
        return None
    payload = {
        "src_ip": row["src_ip"], "src_port": int(row["src_port"]),
        "dst_ip": row["dst_ip"], "dst_port": int(row["dst_port"]),
        "protocol": int(row["protocol"]),
        "start_ms": int(row["start_ms"]), "end_ms": int(row["end_ms"]),
        "predicted_class": pred.label[:64].strip() or "unknown",
        "confidence": round(pred.confidence, 6),
        "explanation": explanation if explanation is not None else {
            "predicted_class": pred.label[:64], "confidence": round(pred.confidence, 6),
            "output_space": "probability", "top_features": []},
    }
    if pred.anomaly_score is not None and math.isfinite(pred.anomaly_score):
        payload["anomaly_score"] = pred.anomaly_score
    return payload


# --- HTTPS client --------------------------------------------------------------------------------

class SocClient:
    """POST /ingest/alerts with a sensor token. Standard library only (no extra dependency).

    The SOC's certificate is issued by Caddy's own CA (infra/templates/soc-user-data.sh.tftpl), so
    pass `ca_file` (IDPS_SOC_CA_FILE): the PEM of that root certificate. Without it the system
    trust store is used and verification fails for the lab SOC. Verification is never switched off.
    """

    def __init__(self, url: str, token: str, timeout: float = 15.0, ca_file: str | None = None) -> None:
        parsed = urllib.parse.urlsplit(url)
        loopback = parsed.hostname in ("localhost", "127.0.0.1", "::1")
        if parsed.scheme != "https" and not (parsed.scheme == "http" and loopback):
            raise ValueError("IDPS_SOC_URL must be https:// (plain http only for localhost): "
                             "the sensor token would travel in clear text")
        self.base = url.rstrip("/")
        self.endpoint = self.base + "/ingest/alerts"
        self._token = validate_token(token)
        self.timeout = timeout
        handlers: list = [_NoRedirect]  # never send the token elsewhere
        if parsed.scheme == "https":
            try:
                context = ssl.create_default_context(cafile=ca_file)
            except (OSError, ssl.SSLError) as exc:
                raise ValueError(f"cannot load IDPS_SOC_CA_FILE {ca_file!r}: {exc}") from exc
            handlers.append(urllib.request.HTTPSHandler(context=context))
        self._opener = urllib.request.build_opener(*handlers)

    def post_alerts(self, alerts: list[dict]) -> dict:
        """POST one batch (at most MAX_BATCH alerts; the Outbox hands out batches of that size)."""
        if len(alerts) > MAX_BATCH:  # the SOC would answer 422; never send it
            raise SocRejectedError(f"at most {MAX_BATCH} alerts per POST, got {len(alerts)}", 422)
        return self._post("/ingest/alerts", {"alerts": alerts}, "alerts")

    def post_blocks(self, events: list[dict]) -> dict:
        """POST one batch of block events (at most MAX_BLOCK_EVENTS) to /ingest/blocks."""
        if len(events) > MAX_BLOCK_EVENTS:
            raise SocRejectedError(
                f"at most {MAX_BLOCK_EVENTS} block events per POST, got {len(events)}", 422)
        return self._post("/ingest/blocks", {"events": events}, "block events")

    def post_status(self, payload: dict) -> dict:
        """POST the sensor's status snapshot to /sensor/status (one small JSON object)."""
        return self._post("/sensor/status", payload, "status report")

    def get_actions(self) -> list[dict]:
        """GET /sensor/actions: the confirmed analyst actions for this sensor (oldest first)."""
        answer = self._request("GET", "/sensor/actions", None, "action poll")
        if not isinstance(answer, list):
            raise SocError("the SOC's action list was not a JSON list")
        return [a for a in answer if isinstance(a, dict)]

    def post_action_result(self, action_id: int, success: bool, result: dict) -> dict:
        """POST /sensor/actions/{id}/result. A 409 (already reported) is a SocRejectedError."""
        return self._post(f"/sensor/actions/{int(action_id)}/result",
                          {"success": bool(success), "result": result}, "action result")

    def _post(self, path: str, payload: dict, what: str) -> dict:
        return self._request("POST", path, payload, what)

    def _request(self, method: str, path: str, payload: dict | None, what: str):
        headers = {"Authorization": f"Bearer {self._token}"}
        body = None
        if payload is not None:
            body = json.dumps(payload).encode()
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(self.base + path, data=body, method=method,
                                         headers=headers)
        try:
            with self._opener.open(request, timeout=self.timeout) as resp:
                body = resp.read(MAX_RESPONSE_BYTES + 1)
            if len(body) > MAX_RESPONSE_BYTES:
                raise SocError(f"the SOC's answer to the {what} is over {MAX_RESPONSE_BYTES} bytes")
        except urllib.error.HTTPError as exc:
            message = f"SOC rejected the {what}: HTTP {exc.code}"
            if 400 <= exc.code < 500 and exc.code not in RETRYABLE_4XX:
                raise SocRejectedError(message, exc.code) from exc
            error = SocError(message)
            error.status = exc.code
            raise error from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise SocError(f"cannot reach the SOC: {exc}") from exc
        except ValueError as exc:
            # http.client's header errors quote the header, which holds the token: say nothing.
            raise SocError(f"the request could not be sent ({type(exc).__name__}; details "
                           "withheld so the token is not logged)") from None
        try:
            return json.loads(body or b"{}")
        except ValueError as exc:
            raise SocError("the SOC's answer was not JSON") from exc


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


# --- Outbox: alerts waiting for the SOC ---------------------------------------------------------

def _refuse_symlink(path: Path) -> None:
    if path.is_symlink():
        raise OSError(f"{path} is a symbolic link; refusing to follow it")


def write_json(path: Path, payload) -> None:
    """Write atomically (temp file + rename), mode 0600, never following a symlink."""
    path.parent.mkdir(parents=True, exist_ok=True)
    _refuse_symlink(path)
    tmp = path.with_name(path.name + ".tmp")
    tmp.unlink(missing_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(tmp, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(json.dumps(payload))
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def _move_aside(path: Path, why: str) -> None:
    target = path.with_name(f"{path.name}.corrupt-{time.strftime('%Y%m%dT%H%M%S')}")
    try:
        os.replace(path, target)
        log.error("outbox %s is unusable (%s); moved to %s, starting empty", path, why, target)
    except OSError as exc:
        log.error("outbox %s is unusable (%s) and could not be moved aside: %s", path, why, exc)


class Outbox:
    """Batches of alerts that the SOC has not accepted yet, persisted in a JSON file.

    `path=None` keeps it in memory only. `max_alerts` caps it: beyond that the oldest alerts
    are dropped (and counted by the caller from add()'s return value). `merge=True` tops
    up the newest batch before starting a new one, so many small additions still leave full
    POSTs; every batch is at most MAX_BATCH. The cloud collector's single thread uses
    peek/pop_first; the live loop's sender thread uses take_first/requeue_front, so a batch that
    is in flight cannot be dropped or extended underneath it. All methods are thread-safe.

    The file is validated when loaded: it must be a regular file under MAX_OUTBOX_FILE_BYTES
    holding batches of JSON objects; they are re-chunked to MAX_BATCH and trimmed to max_alerts.
    A file that fails is moved aside (`<name>.corrupt-<timestamp>`), never overwritten.
    """

    def __init__(self, path: str | Path | None, *, max_alerts: int = MAX_OUTBOX_ALERTS,
                 merge: bool = False) -> None:
        self.path = None if path is None else Path(path)
        self.max_alerts = max_alerts
        self.merge = merge
        self.batches: list[list[dict]] = []
        self._lock = threading.RLock()
        if self.path is not None:
            self._load()

    def _load(self) -> None:
        path = self.path
        try:
            if path.is_symlink():
                raise OSError("it is a symbolic link")  # not moved: we do not touch the target
            if not path.exists():
                return
            if path.stat().st_size > MAX_OUTBOX_FILE_BYTES:
                raise ValueError(f"file over {MAX_OUTBOX_FILE_BYTES} bytes")
            batches = json.loads(path.read_text())["batches"]
            if not isinstance(batches, list) or not all(
                    isinstance(b, list) and all(isinstance(a, dict) for a in b) for b in batches):
                raise TypeError("batches must be lists of JSON objects")
        except OSError as exc:
            if not path.is_symlink() and path.exists():
                _move_aside(path, str(exc))
            else:
                log.error("ignoring outbox %s: %s", path, exc)
            return
        except (ValueError, KeyError, TypeError) as exc:
            _move_aside(path, f"{type(exc).__name__}: {exc}")
            return
        alerts = [a for b in batches for a in b]
        if len(alerts) > self.max_alerts:
            log.error("outbox %s holds %d alerts, over the cap of %d: dropping the %d oldest",
                      path, len(alerts), self.max_alerts, len(alerts) - self.max_alerts)
            alerts = alerts[len(alerts) - self.max_alerts:]
        self.batches = [alerts[i:i + MAX_BATCH] for i in range(0, len(alerts), MAX_BATCH)]

    def __len__(self) -> int:
        with self._lock:
            return sum(len(b) for b in self.batches)

    def add(self, alerts: list[dict], *, save: bool = True) -> int:
        """Queue alerts in batches of MAX_BATCH; returns how many old alerts had to be dropped."""
        with self._lock:
            for i in range(0, len(alerts), MAX_BATCH):
                chunk = alerts[i:i + MAX_BATCH]
                if self.merge and self.batches and len(self.batches[-1]) + len(chunk) <= MAX_BATCH:
                    self.batches[-1].extend(chunk)
                else:
                    self.batches.append(chunk)
            dropped = 0
            excess = len(self) - self.max_alerts
            while excess > 0 and self.batches:  # drop exactly the oldest `excess` alerts
                first = self.batches[0]
                if len(first) <= excess:
                    self.batches.pop(0)
                    cut = len(first)
                else:
                    cut = excess
                    del first[:cut]
                dropped += cut
                excess -= cut
            if dropped:
                log.error("outbox over %d alerts: dropped the %d oldest", self.max_alerts, dropped)
            if save:
                self.save()
            return dropped

    def pop_first(self) -> None:
        with self._lock:
            self.batches.pop(0)
            self.save()

    def take_first(self) -> list[dict] | None:
        """Remove and return the oldest batch (None if empty). Give it back with requeue_front
        if sending failed."""
        with self._lock:
            return self.batches.pop(0) if self.batches else None

    def requeue_front(self, batch: list[dict]) -> None:
        """Put a batch that could not be sent back first. It may exceed max_alerts by up to
        MAX_BATCH until the next add() trims the oldest."""
        with self._lock:
            self.batches.insert(0, batch)

    def save(self) -> None:
        if self.path is None:
            return
        with self._lock:
            write_json(self.path, {"version": 1, "batches": self.batches})
