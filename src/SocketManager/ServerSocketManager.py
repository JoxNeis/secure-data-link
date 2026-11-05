"""Server side of the link: listen on a port and wait for a client.

    server = ServerSocketManager("0.0.0.0", 5000, connect_timeout=120)
    server.on_message(lambda message: print("client:", message))
    server.start()
    if server.wait_until_connected():
        server.send("hello from the server")  # no need to wait for the client to speak first

The link is point-to-point: one client at a time. While a client is
connected, anyone else who connects is turned away immediately (a
ClientSocketManager keeps retrying until the slot frees up). When the client
leaves, the server waits up to ``connect_timeout`` for the next one if
``reconnect=True``, otherwise it stops.
"""

from __future__ import annotations

import logging
import socket
import ssl
import time

from .SocketManager import (
    DEFAULT_CONNECT_TIMEOUT,
    DEFAULT_HANDSHAKE_TIMEOUT,
    DEFAULT_HEARTBEAT_INTERVAL,
    DEFAULT_HEARTBEAT_TIMEOUT,
    DEFAULT_MAX_MESSAGE_SIZE,
    Cipher,
    POLL_INTERVAL,
    SocketManager,
    _Connection,
    _Link,
    expired,
    fmt_address,
)

log = logging.getLogger(__name__)


class ServerSocketManager(SocketManager):
    """Listens on ``host:port`` and keeps a link with one client at a time.

    Args:
        host: interface to listen on. "0.0.0.0" means every IPv4 interface,
            "127.0.0.1" means this machine only.
        port: TCP port. 0 picks a free one; read it back from ``address``.
        connect_timeout: seconds to wait for a client, at start and again after
            each client leaves, before giving up (on_timeout fires and the
            server stops). None waits forever.
        reconnect: wait for a new client after the current one leaves (True),
            or stop (False).
        ssl_context: server-side TLS, e.g. ``TlsManager.from_env("server").create_context()``.
        encryption: message encryption, e.g. ``EncryptionManager.from_env()``.

    The remaining arguments are described on SocketManager.
    """

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 5000,
        *,
        connect_timeout: float | None = DEFAULT_CONNECT_TIMEOUT,
        reconnect: bool = True,
        handshake_timeout: float = DEFAULT_HANDSHAKE_TIMEOUT,
        heartbeat_interval: float | None = DEFAULT_HEARTBEAT_INTERVAL,
        heartbeat_timeout: float | None = DEFAULT_HEARTBEAT_TIMEOUT,
        max_message_size: int = DEFAULT_MAX_MESSAGE_SIZE,
        ssl_context: ssl.SSLContext | None = None,
        encryption: Cipher | None = None,
        name: str | None = None,
    ) -> None:
        super().__init__(
            connect_timeout=connect_timeout,
            reconnect=reconnect,
            handshake_timeout=handshake_timeout,
            heartbeat_interval=heartbeat_interval,
            heartbeat_timeout=heartbeat_timeout,
            max_message_size=max_message_size,
            ssl_context=ssl_context,
            encryption=encryption,
            name=name,
        )
        self.host = host
        self.port = port
        self._listener: socket.socket | None = None
        self._next_client: tuple[socket.socket, tuple[str, int]] | None = None

    @property
    def address(self) -> tuple[str, int]:
        """The address actually being listened on (shows the real port when port=0)."""
        listener = self._listener
        if listener is not None:
            try:
                return listener.getsockname()[:2]
            except OSError:
                pass
        return self.host, self.port

    # ----------------------------------------------------------------- SocketManager hooks

    def _prepare(self) -> None:
        family = socket.AF_INET6 if ":" in self.host else socket.AF_INET
        self._listener = socket.create_server((self.host, self.port), family=family)
        self._listener.settimeout(POLL_INTERVAL)  # accept() wakes up regularly to notice stop()
        log.info("%s: listening on %s", self.name, fmt_address(self.address))

    def _establish(self, deadline: float | None) -> tuple[_Link, tuple[str, int]] | None:
        log.info("%s: waiting for a client on %s", self.name, fmt_address(self.address))
        while not self._stop_event.is_set():
            if expired(deadline):
                log.warning("%s: no client connected within %gs, giving up", self.name, self.connect_timeout)
                return None
            accepted = self._next_client or self._accept()
            self._next_client = None
            if accepted is None:
                continue
            raw, peer = accepted
            try:
                return self._open_session(raw, server_side=True), peer
            except OSError as exc:  # a port scanner, a wrong protocol, a failed TLS handshake...
                log.warning("%s: turned away %s: handshake failed (%s)", self.name, fmt_address(peer), exc)
        return None

    def _hold(self, conn: _Connection) -> None:
        """Wait for the current client to leave, turning away anyone else who connects meanwhile."""
        while not conn.done.is_set():
            if self._stop_event.is_set():  # shutting down: let the link finish closing, accept no one
                conn.done.wait()
                return
            accepted = self._accept()
            if accepted is None:
                continue
            if conn.closing:  # the link is ending, so this is the next client rather than an intruder
                conn.done.wait()  # let the old link report its disconnect before the new one connects
                self._next_client = accepted
                return
            extra, peer = accepted
            extra.close()
            if not self._stop_event.is_set():  # stop() may have arrived while accept() was waiting
                log.warning(
                    "%s: turned away %s: already connected to %s",
                    self.name, fmt_address(peer), fmt_address(conn.peer),
                )

    def _cleanup(self) -> None:
        if self._next_client is not None:
            self._next_client[0].close()
            self._next_client = None
        if self._listener is not None:
            self._listener.close()
            self._listener = None
            log.info("%s: stopped listening", self.name)

    # ----------------------------------------------------------------- internals

    def _accept(self) -> tuple[socket.socket, tuple[str, int]] | None:
        """Accept one pending connection, or return None after POLL_INTERVAL."""
        assert self._listener is not None
        try:
            raw, peer = self._listener.accept()
        except TimeoutError:
            return None
        except ConnectionError:  # the client gave up between connecting and being accepted
            time.sleep(0.01)
            return None
        return raw, peer[:2]
