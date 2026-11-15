"""Request body size limits, enforced before anything reads or parses the body.

FastAPI reads and JSON-parses a whole body before the authentication dependency runs, so without
this a 64 MiB POST from anyone (even a revoked sensor) would be buffered and parsed before the 401.
The middleware is plain ASGI: it refuses a request whose Content-Length is over the path's limit
with 413 without reading it, and counts the bytes of a streamed body (chunked, or a lying
Content-Length) and aborts at the limit.

All limits are here. They sit above what the schemas allow, so a valid request always fits:
500 alerts x (16 KiB explanation + 4 KiB features) = 10 MiB (soc/api/routes/alerts.py) plus
the other fields.
"""

from __future__ import annotations

import json

KiB = 1024
MiB = 1024 * KiB

# Longest matching prefix wins; (prefix, limit in bytes). Paths are compared exactly or as
# `prefix/...`, so "/actions" covers "/actions/3/confirm" but not "/actionsx".
LIMITS: tuple[tuple[str, int], ...] = (
    ("/ingest/alerts", 12 * MiB),        # 500 alerts x (16 KiB explanation + 4 KiB features + ~1 KiB)
    ("/ingest/blocks", 128 * KiB),       # 100 events x ~1 KiB
    ("/sensor/status", 64 * KiB),        # 100 allowlist entries + policy + faithfulness ~ 8 KiB
    ("/sensor/actions", 16 * KiB),       # a result is at most 4 KiB (MAX_RESULT_BYTES)
    ("/actions", 16 * KiB),
    ("/auth/login", 4 * KiB),            # username 64 + password 256
    ("/assistant", 64 * KiB),            # a 4000 character message, escaped
    ("/cases", 128 * KiB),               # a 10,000 character note, escaped; 100 alert ids
    ("/admin", 16 * KiB),
)
DEFAULT_LIMIT = 256 * KiB  # everything else


def limit_for(path: str) -> int:
    best, size = -1, DEFAULT_LIMIT
    for prefix, limit in LIMITS:
        if (path == prefix or path.startswith(prefix + "/")) and len(prefix) > best:
            best, size = len(prefix), limit
    return size


class _TooLarge(BaseException):
    """Not an Exception on purpose: FastAPI turns any Exception raised while it reads a body into
    its own 400, which would hide the 413."""


class BodyLimitMiddleware:
    """Pure ASGI (no BaseHTTPMiddleware: that buffers the body itself)."""

    def __init__(self, app, limits=limit_for) -> None:
        self.app = app
        self.limits = limits

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        limit = self.limits(scope["path"])
        declared = None
        for name, value in scope["headers"]:
            if name == b"content-length":
                try:
                    declared = int(value)
                except ValueError:
                    declared = -1
                break
        if declared is not None and (declared < 0 or declared > limit):
            await self._reject(send, 400 if declared < 0 else 413, limit)
            return

        seen = 0
        started = False

        async def counting_receive():
            nonlocal seen
            message = await receive()
            if message["type"] == "http.request":
                seen += len(message.get("body", b""))
                if seen > limit:
                    raise _TooLarge
            return message

        async def tracking_send(message):
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, counting_receive, tracking_send)
        except _TooLarge:
            if not started:
                await self._reject(send, 413, limit)

    @staticmethod
    async def _reject(send, status: int, limit: int) -> None:
        detail = ("invalid Content-Length" if status == 400
                  else f"request body is over the {limit} byte limit for this path")
        body = json.dumps({"detail": detail}).encode()
        await send({"type": "http.response.start", "status": status, "headers": [
            (b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()),
            (b"connection", b"close")]})
        await send({"type": "http.response.body", "body": body})
