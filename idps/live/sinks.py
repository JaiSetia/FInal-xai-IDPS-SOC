"""Where alerts go: a JSON-lines file (no SOC) or the SOC through an outbox and a sender thread."""

from __future__ import annotations

import json
import logging
import os
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Protocol

from idps.live.metrics import Metrics
from idps.soc_client import Outbox, SocRejectedError

log = logging.getLogger("idps.live")


class Sink(Protocol):
    def submit(self, alerts: list[dict]) -> None: ...
    def pending(self) -> int: ...
    def checkpoint(self) -> None: ...
    def close(self) -> None: ...


class JsonlSink:
    """Append each alert as one JSON line. A write error (disk full, permissions) is counted and
    logged; it never stops detection."""

    def __init__(self, path: str | Path, metrics: Metrics) -> None:
        self.path = Path(path)
        self.metrics = metrics
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # 0600: alerts name internal hosts. Opened once; flushed after every batch.
        # O_NOFOLLOW: a symlink planted at this path is an error, not a way to write elsewhere.
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(self.path, flags, 0o600)
        self._file = os.fdopen(fd, "a", encoding="utf-8")

    def submit(self, alerts: list[dict]) -> None:
        if not alerts:
            return
        try:
            self._file.write("".join(json.dumps(a, separators=(",", ":")) + "\n" for a in alerts))
            self._file.flush()
        except (OSError, ValueError) as exc:
            self.metrics.add("alerts_dropped", len(alerts))
            log.error("cannot write %d alert(s) to %s: %s", len(alerts), self.path, exc)

    def pending(self) -> int:
        return 0

    def checkpoint(self) -> None:
        pass

    def close(self) -> None:
        try:
            self._file.close()
        except OSError as exc:
            log.error("closing %s failed: %s", self.path, exc)


class SocSink:
    """Queue alerts in the outbox; a background thread posts them in batches of at most
    MAX_BATCH. A SOC outage only makes the outbox grow (up to its cap, then the oldest alerts are
    dropped and counted); the detection loop never waits for the network.

    Failed rounds are retried with a growing pause (`retry_seconds` doubling up to
    `max_retry_seconds`). A batch the SOC refuses with a 4xx is dropped and counted: retrying
    cannot help. On close() one last attempt is made and what is still unsent is written to the
    outbox file, which the next run loads and sends first."""

    def __init__(self, post: Callable[[list[dict]], dict], outbox: Outbox, metrics: Metrics, *,
                 retry_seconds: float = 2.0, max_retry_seconds: float = 60.0,
                 start: bool = True) -> None:
        self.post = post
        self.outbox = outbox
        self.metrics = metrics
        self.retry_seconds = retry_seconds
        self.max_retry_seconds = max_retry_seconds
        self._config_error_streak = False  # log a 401/403/404 once per streak, not per retry
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="soc-sender", daemon=True)
        if len(outbox):
            log.info("outbox has %d alert(s) from an earlier run; sending them first", len(outbox))
        if start:
            self._thread.start()
            self._wake.set()

    def submit(self, alerts: list[dict]) -> None:
        if alerts:
            dropped = self.outbox.add(alerts, save=False)
            if dropped:
                self.metrics.add("alerts_dropped", dropped)
            self._wake.set()

    def pending(self) -> int:
        return len(self.outbox)

    def checkpoint(self) -> None:
        self._save()

    def _save(self) -> None:
        try:
            self.outbox.save()
        except OSError as exc:
            log.error("cannot save the outbox to %s: %s", self.outbox.path, exc)

    def drain(self) -> bool:
        """Send queued batches, oldest first. False if the SOC could not be reached."""
        while (batch := self.outbox.take_first()) is not None:
            try:
                self.post(batch)
            except SocRejectedError as exc:
                if exc.is_config_error:
                    # The batch is fine; the sensor's URL, token or registration is not. Keep
                    # the alerts (the operator can fix the setting) and say so, once per streak.
                    self.outbox.requeue_front(batch)
                    self.metrics.add("soc_config_errors")
                    if not self._config_error_streak:
                        self._config_error_streak = True
                        log.error("SOC answered HTTP %s: check IDPS_SOC_URL and the sensor token. "
                                  "Alerts are kept and retried; nothing is dropped", exc.status)
                    return False
                log.error("SOC refused a batch of %d alerts, dropping it: %s", len(batch), exc)
                self.metrics.add("alerts_rejected", len(batch))
            except Exception as exc:  # noqa: BLE001  the sender thread must survive anything
                self.outbox.requeue_front(batch)
                log.warning("SOC unavailable, %d alert(s) stay queued: %s: %s",
                            len(self.outbox), type(exc).__name__, exc)
                return False
            else:
                self._config_error_streak = False
                self.metrics.add("alerts_sent", len(batch))
        return True

    def _run(self) -> None:
        delay = 0.0
        while not self._stop.is_set():
            self._wake.wait(timeout=1.0)
            self._wake.clear()
            if self._stop.is_set() or not len(self.outbox):
                continue
            if self.drain():
                delay = 0.0
            else:
                delay = min(delay * 2, self.max_retry_seconds) if delay else self.retry_seconds
                self._stop.wait(delay)

    def close(self) -> None:
        self._stop.set()
        self._wake.set()
        if self._thread.is_alive():
            self._thread.join(timeout=30)
        if len(self.outbox):
            self.drain()
        self._save()
        left = len(self.outbox)
        if left:
            log.warning("%d alert(s) were not delivered; kept in %s for the next run", left,
                        self.outbox.path)
