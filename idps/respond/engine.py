"""Response engine: feed detections in, get blocks (or dry-run log lines) out."""

from __future__ import annotations

import json
import logging
from typing import Protocol

from idps.config import Settings
from idps.respond.nft import BlockerError, NftBlocker
from idps.respond.policy import Action, Decision, Detection, ResponsePolicy, normalise_ip

log = logging.getLogger("idps.respond")


class Blocker(Protocol):
    def ensure_ruleset(self) -> None: ...
    def block(self, ip: str, ttl_seconds: int) -> None: ...
    def unblock(self, ip: str) -> None: ...


class ResponseEngine:
    def __init__(
        self,
        settings: Settings,
        blocker: Blocker | None = None,
        policy: ResponsePolicy | None = None,
        **policy_options,
    ) -> None:
        self.dry_run = settings.dry_run
        self.policy = policy or ResponsePolicy.from_settings(settings, **policy_options)
        self.blocker = blocker if blocker is not None else NftBlocker()
        if not self.dry_run:
            self.blocker.ensure_ruleset()  # fail at startup, not on the first attack

    def handle(self, detection: Detection) -> Decision:
        decision = self.policy.evaluate(detection)
        if decision.action is Action.BLOCK:
            decision = self._apply(decision)
        return decision

    def _apply(self, decision: Decision) -> Decision:
        if self.dry_run:
            self._audit("would_block", decision)
            return decision
        try:
            self.blocker.block(decision.ip, decision.ttl_seconds)
        except BlockerError as exc:
            self.policy.release(decision.ip)  # so the next flow retries
            self._audit("block_failed", decision, error=str(exc))
            return Decision(
                Action.OBSERVE, decision.ip, f"block failed: {exc}",
                flows_in_window=decision.flows_in_window, detection=decision.detection,
            )
        self._audit("blocked", decision)
        return decision

    def unblock(self, ip: str) -> None:
        """Analyst unblock. Safe to call in dry-run (nothing was blocked)."""
        addr = normalise_ip(ip)
        if addr is None:
            raise ValueError(f"not an IP address: {ip!r}")
        if not self.dry_run:
            self.blocker.unblock(str(addr))
        self.policy.release(str(addr))
        log.info(json.dumps({"event": "unblocked", "ip": str(addr), "dry_run": self.dry_run}))

    def _audit(self, event: str, d: Decision, **extra) -> None:
        det = d.detection
        record = {
            "event": event, "ip": d.ip, "dry_run": self.dry_run, "ttl_seconds": d.ttl_seconds,
            "reason": d.reason, "flows": d.flows_in_window,
            "label": det.label if det else None,
            "confidence": det.confidence if det else None,
            "explanation": det.explanation if det else None,  # every block is logged with its why
            **extra,
        }
        log.warning(json.dumps(record, default=str))
