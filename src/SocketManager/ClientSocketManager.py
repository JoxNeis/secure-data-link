"""Client side of the link: dial a server, retrying until it answers.

    client = ClientSocketManager("192.168.1.10", 5000, connect_timeout=60)
    client.on_message(lambda message: print("server:", message))
    client.start()
    if client.wait_until_connected():
        client.send({"hello": "from the client"})  # no need to wait for the server to speak first

The client keeps retrying every ``retry_interval`` seconds until it connects,
or gives up after ``connect_timeout`` seconds or ``max_attempts`` attempts. If
the link drops later, it starts retrying again (when ``reconnect=True``).
"""

from __future__ import annotations

import logging
import socket
import ssl

from .SocketManager import (
    DEFAULT_CONNECT_TIMEOUT,
    DEFAULT_HANDSHAKE_TIMEOUT,
    DEFAULT_HEARTBEAT_INTERVAL,
    DEFAULT_HEARTBEAT_TIMEOUT,
    DEFAULT_MAX_MESSAGE_SIZE,
    Cipher,
    ProtocolError,
    SocketManager,
    _Link,
    capped,
    expired,
)

log = logging.getLogger(__name__)


def _needs_fixing(exc: OSError) -> bool:
    """True for failures that retrying won't cure: wrong key, untrusted certificate, wrong protocol...

    The server going away mid-handshake (it is busy with another client, or restarting) is transient.
    """
    if isinstance(exc, ProtocolError):
        return True
    return isinstance(exc, ssl.SSLError) and not isinstance(exc, (ssl.SSLEOFError, ssl.SSLZeroReturnError))


class ClientSocketManager(SocketManager):
    """Connects to a ServerSocketManager at ``host:port`` and keeps the link up.

    Args:
        host: server hostname or IP address.
        port: server TCP port.
        connect_timeout: seconds to keep retrying, at start and again after
            each drop, before giving up (on_timeout fires and the client
            stops). None retries forever.
        reconnect: start retrying after the link drops (True), or stop (False).
        retry_interval: seconds to wait between connection attempts.
        max_attempts: also give up after this many failed attempts in a row.
            None means only connect_timeout limits retrying.
        ssl_context: client-side TLS, e.g. ``TlsManager.from_env("client").create_context()``.
        encryption: message encryption, e.g. ``EncryptionManager.from_env()``.
        server_hostname: name the server's TLS certificate must carry. Defaults
            to ``host``. Certificates from setup-credentials.py always carry
            ``src.Security.SERVER_CERT_NAME``, which works whatever the server's IP.

    The remaining arguments are described on SocketManager.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 5000,
        *,
        connect_timeout: float | None = DEFAULT_CONNECT_TIMEOUT,
        reconnect: bool = True,
        retry_interval: float = 2.0,
        max_attempts: int | None = None,
        handshake_timeout: float = DEFAULT_HANDSHAKE_TIMEOUT,
        heartbeat_interval: float | None = DEFAULT_HEARTBEAT_INTERVAL,
        heartbeat_timeout: float | None = DEFAULT_HEARTBEAT_TIMEOUT,
        max_message_size: int = DEFAULT_MAX_MESSAGE_SIZE,
        ssl_context: ssl.SSLContext | None = None,
        encryption: Cipher | None = None,
        server_hostname: str | None = None,
        name: str | None = None,
    ) -> None:
        if retry_interval < 0:
            raise ValueError(f"retry_interval cannot be negative, got {retry_interval!r}")
        if max_attempts is not None and max_attempts < 1:
            raise ValueError(f"max_attempts must be at least 1, got {max_attempts!r}")
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
        self.retry_interval = retry_interval
        self.max_attempts = max_attempts
        self.server_hostname = server_hostname

    # ----------------------------------------------------------------- SocketManager hooks

    def _establish(self, deadline: float | None) -> tuple[_Link, tuple[str, int]] | None:
        log.info("%s: connecting to %s:%s", self.name, self.host, self.port)
        attempts = 0
        last_error: OSError | None = None
        while not self._stop_event.is_set():
            if expired(deadline) or (self.max_attempts is not None and attempts >= self.max_attempts):
                log.warning(
                    "%s: could not reach %s:%s after %d attempt(s), giving up (last error: %s)",
                    self.name, self.host, self.port, attempts, last_error,
                )
                return None
            attempts += 1
            try:
                return self._dial(deadline)
            except OSError as exc:
                if _needs_fixing(exc) and str(exc) != str(last_error):  # say it once, not every retry
                    log.warning("%s: handshake with %s:%s failed: %s", self.name, self.host, self.port, exc)
                else:
                    log.debug("%s: attempt %d failed: %s", self.name, attempts, exc)
                last_error = exc
            self._stop_event.wait(capped(self.retry_interval, deadline))
        return None

    # ----------------------------------------------------------------- internals

    def _dial(self, deadline: float | None) -> tuple[_Link, tuple[str, int]]:
        raw = socket.create_connection((self.host, self.port), timeout=capped(self.handshake_timeout, deadline))
        link = self._open_session(raw, server_side=False, server_hostname=self.server_hostname or self.host)
        return link, link.sock.getpeername()[:2]
