"""Clock ticks for NFStream live capture.

NFStream's flow clock only moves forward when a packet arrives: it expires idle flows by
comparing them with the newest packet's timestamp. On a quiet link (the lab right after an
attack, a server at night) nothing arrives, so finished flows are never emitted and never scored.
Measured in the lab sensor: a port scan followed by silence produced no flows at all in 200 s;
the same scan followed by one packet every 2 s produced all its flows right after the idle
timeout.

So in live mode the loop sends one tiny UDP broadcast out of the capture interface every second.
NFStream sees it (outgoing packets are captured too) and its clock advances. The heartbeat's own
flow is dropped before scoring, so it never reaches the model, the SOC or the response engine.

Only that exact flow is dropped: UDP from the socket's own address and port (`Heartbeat.key`,
known once the socket is connected) to 255.255.255.255:9, with no packet coming back. Anyone
else's traffic to that address, an attacker's broadcast flood included, is scored like any other
flow. Nothing is dropped when the heartbeat isn't running (replay, --no-heartbeat, a failed start).

The datagram goes to the limited broadcast address on the discard port (9): no ARP, no reply,
and hosts with nothing listening on UDP 9 ignore it. Its payload is a single zero byte, so it
doesn't announce what it is. Linux only (SO_BINDTODEVICE); elsewhere the loop runs without it.
"""

from __future__ import annotations

import errno
import logging
import socket
import threading

log = logging.getLogger("idps.live")

HEARTBEAT_DST = "255.255.255.255"
HEARTBEAT_PORT = 9  # discard
HEARTBEAT_PAYLOAD = b"\0"
UDP = 17

# Errors that won't go away by waiting: no such interface, not allowed. Anything else (the
# interface is down or has no address yet) is retried every interval.
PERMANENT_ERRNOS = {errno.ENODEV, errno.EPERM, errno.EACCES, errno.EINVAL}


def is_heartbeat(flow, key: tuple[str, int] | None) -> bool:
    """True for the flow our own heartbeat socket `key` = (source ip, source port) creates.
    With no key (no heartbeat running) nothing is a heartbeat."""
    if key is None:
        return False
    return (getattr(flow, "protocol", None) == UDP
            and getattr(flow, "dst_port", None) == HEARTBEAT_PORT
            and getattr(flow, "dst_ip", None) == HEARTBEAT_DST
            and (getattr(flow, "src_ip", None), getattr(flow, "src_port", None)) == key
            and not getattr(flow, "bwd_packets", 0))  # nothing ever answers a heartbeat


class Heartbeat:
    """Send HEARTBEAT_PAYLOAD out of `interface` every `interval` seconds until stopped."""

    def __init__(self, interface: str, interval: float = 1.0, *, sock_factory=socket.socket) -> None:
        if interval <= 0:
            raise ValueError("heartbeat interval must be positive")
        self.interface = interface
        self.interval = interval
        self._sock_factory = sock_factory
        self._sock = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.sent = 0
        self.key: tuple[str, int] | None = None  # (source ip, source port) once connected
        self.failing = False

    def start(self) -> None:
        """Open the socket and start sending. Raises OSError for problems that won't fix
        themselves (no SO_BINDTODEVICE, no such interface, no permission); the caller decides
        whether to go on without a heartbeat. A temporary failure (the interface is down) is
        logged and retried by the sending thread."""
        bind_option = getattr(socket, "SO_BINDTODEVICE", None)
        if bind_option is None:
            raise OSError("SO_BINDTODEVICE is not available on this platform (Linux only)")
        sock = self._sock_factory(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.setsockopt(socket.SOL_SOCKET, bind_option, self.interface.encode() + b"\0")
        except OSError:
            sock.close()
            raise
        self._sock = sock
        try:
            self._send(sock)
        except OSError as exc:
            if exc.errno in PERMANENT_ERRNOS:
                sock.close()
                self._sock = None
                raise
            self._failed(exc)
        self._thread = threading.Thread(target=self._loop, args=(sock,), daemon=True,
                                        name="heartbeat")
        self._thread.start()

    def _send(self, sock) -> None:
        if self.key is None:
            # connect() fixes the source address and port, which is how our flow is recognised.
            sock.connect((HEARTBEAT_DST, HEARTBEAT_PORT))
            ip, port = sock.getsockname()[:2]
            self.key = (ip, port)
        sock.send(HEARTBEAT_PAYLOAD)
        self.sent += 1
        if self.failing:
            log.info("heartbeat on %s works again", self.interface)
            self.failing = False

    def _failed(self, exc: OSError) -> None:
        if not self.failing:  # once per streak, not once a second
            log.warning("heartbeat on %s failed (%s): flows on a quiet link may be late; "
                        "retrying every %g s", self.interface, exc, self.interval)
            self.failing = True

    def _loop(self, sock) -> None:  # its own reference: stop() may clear self._sock meanwhile
        while not self._stop.wait(self.interval):
            try:
                self._send(sock)
            except OSError as exc:
                self._failed(exc)

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
        if self._sock is not None:
            self._sock.close()
            self._sock = None
