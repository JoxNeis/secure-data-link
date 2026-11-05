"""Shared core of the socket library, used by ServerSocketManager and ClientSocketManager.

What lives here:

* The wire protocol. Every message travels as one frame,
  ``[1-byte type][4-byte big-endian length][payload]``, so messages never
  merge or split on the way, however TCP happens to chunk the bytes.
* ``_Connection``: one live socket with a background reader thread and a
  heartbeat watchdog that keeps an idle link alive and notices a dead peer.
* ``SocketManager``: the lifecycle (establish a connection within
  ``connect_timeout``, talk, re-establish after a drop) and the public API.

Once connected the two sides are equal peers: either one may ``send`` at any
moment and nothing has to be answered, so a conversation can start from
either end.

Security is optional and pluggable. ``ssl_context`` runs the link over TLS
(see src.Security.TlsManager), and ``encryption`` adds message encryption on
top (see src.Security.EncryptionManager). With encryption, every connection
derives its own keys, one per direction, and the handshake fails unless both
ends hold the same key. Every message is numbered, so an altered, replayed or
reordered message ends the connection.
"""

from __future__ import annotations

import json
import logging
import os
import queue
import socket
import ssl
import struct
import threading
import time
from collections.abc import Callable
from enum import IntEnum
from typing import Any, NamedTuple, Protocol, Self

log = logging.getLogger(__name__)

DEFAULT_CONNECT_TIMEOUT = 60.0    # seconds to keep trying to (re)connect before giving up
DEFAULT_HANDSHAKE_TIMEOUT = 10.0  # seconds allowed for one connection attempt
DEFAULT_HEARTBEAT_INTERVAL = 5.0  # seconds between keep-alive pings
DEFAULT_HEARTBEAT_TIMEOUT = 15.0  # seconds of silence before the peer is declared dead
DEFAULT_MAX_MESSAGE_SIZE = 16 * 1024 * 1024

POLL_INTERVAL = 0.25  # how often blocking waits wake up to notice stop()


class NotConnectedError(ConnectionError):
    """``send()`` was called while there is no live connection to the peer."""


class Cipher(Protocol):
    """What the ``encryption`` option needs. src.Security.EncryptionManager provides it."""

    overhead: int  # bytes encrypt() adds to its input

    def encrypt(self, data: bytes, associated_data: bytes = b"") -> bytes: ...

    def decrypt(self, token: bytes, associated_data: bytes = b"") -> bytes:
        """Raise ValueError if the token is not authentic."""
        ...

    def derive(self, *, salt: bytes, info: bytes) -> Cipher: ...


# --------------------------------------------------------------------------- protocol


class _Frame(IntEnum):
    HELLO = 0  # first frame on every new connection; proves the peer speaks this protocol
    BYTES = 1
    TEXT = 2
    JSON = 3
    PING = 4  # keep-alive; the peer answers with PONG
    PONG = 5
    KEY_CHECK = 6  # handshake, with encryption on: proves both ends derived the same keys


_HEADER = struct.Struct("!BI")  # frame type, payload length
_DATA_FRAMES = frozenset((_Frame.BYTES, _Frame.TEXT, _Frame.JSON))

# HELLO payload: magic, flags byte, random salt (feeds this connection's key derivation)
_HELLO_MAGIC = b"secure-data-link/1"
_FLAG_ENCRYPTED = 0x01
_SALT_SIZE = 16
_HELLO_SIZE = len(_HELLO_MAGIC) + 1 + _SALT_SIZE
_KEY_CHECK = b"secure-data-link key check"
_KEY_CHECK_AAD = bytes([_Frame.KEY_CHECK])


class ProtocolError(ConnectionError):
    """The peer broke the protocol: bad frame, failed greeting, or a message that failed decryption."""


def _message_aad(kind: int, sequence: int) -> bytes:
    """Associated data for an encrypted message: binds its type and position in the stream."""
    return struct.pack("!BQ", kind, sequence)


def _pack(kind: _Frame, payload: bytes = b"") -> bytes:
    return _HEADER.pack(kind, len(payload)) + payload


_PING = _pack(_Frame.PING)
_PONG = _pack(_Frame.PONG)


def _encode(message: Any) -> tuple[_Frame, bytes]:
    if isinstance(message, (bytes, bytearray, memoryview)):
        return _Frame.BYTES, bytes(message)
    if isinstance(message, str):
        return _Frame.TEXT, message.encode("utf-8")
    text = json.dumps(message, ensure_ascii=False, separators=(",", ":"))
    return _Frame.JSON, text.encode("utf-8")


def _decode(kind: int, payload: bytes) -> Any:
    if kind == _Frame.BYTES:
        return payload
    if kind == _Frame.TEXT:
        return payload.decode("utf-8")
    if kind == _Frame.JSON:
        return json.loads(payload)
    raise ValueError(f"unknown frame type {kind}")


def _recv_exact(sock: socket.socket, size: int, on_data: Callable[[], None] | None) -> bytes | None:
    """Read exactly ``size`` bytes, or return None if the peer closed the connection first."""
    buf = bytearray()
    while len(buf) < size:
        chunk = sock.recv(min(size - len(buf), 1 << 16))
        if not chunk:
            return None
        buf += chunk
        if on_data is not None:
            on_data()
    return bytes(buf)


def _read_frame(
    sock: socket.socket, max_size: int, on_data: Callable[[], None] | None = None
) -> tuple[int, bytes] | None:
    """Read one frame, or return None if the peer closed the connection."""
    header = _recv_exact(sock, _HEADER.size, on_data)
    if header is None:
        return None
    kind, length = _HEADER.unpack(header)
    if length > max_size:
        raise ProtocolError(f"frame of {length} bytes exceeds the {max_size}-byte limit")
    payload = _recv_exact(sock, length, on_data) if length else b""
    return None if payload is None else (kind, payload)


# --------------------------------------------------------------------------- small helpers


def fmt_address(address: tuple[Any, ...]) -> str:
    return f"{address[0]}:{address[1]}"


def deadline_after(seconds: float | None) -> float | None:
    return None if seconds is None else time.monotonic() + seconds


def expired(deadline: float | None) -> bool:
    return deadline is not None and time.monotonic() >= deadline


def capped(seconds: float, deadline: float | None) -> float:
    """``seconds``, shortened so it does not run past ``deadline``."""
    if deadline is None:
        return seconds
    return max(0.01, min(seconds, deadline - time.monotonic()))


# --------------------------------------------------------------------------- one live connection


class _Link(NamedTuple):
    """A socket that has finished the handshake, with this connection's keys (None without encryption)."""

    sock: socket.socket
    send_cipher: Cipher | None
    recv_cipher: Cipher | None


class _Connection:
    """One live, greeted socket plus the threads that service it.

    Only the reader thread ever finishes a connection, so every message it
    delivers is queued before the disconnect notice. Other threads request a
    shutdown with ``close()``, which just unblocks the reader.
    """

    def __init__(
        self,
        link: _Link,
        peer: tuple[str, int],
        *,
        name: str,
        max_message_size: int,
        heartbeat_interval: float | None,
        heartbeat_timeout: float | None,
        on_message: Callable[[Any], None],
        on_closed: Callable[[_Connection, str], None],
    ) -> None:
        self.sock = link.sock
        self.peer = peer
        self.done = threading.Event()  # set after the socket is closed and on_closed has run
        self._name = name
        self._send_cipher, self._recv_cipher = link.send_cipher, link.recv_cipher
        self._send_sequence = self._recv_sequence = 0
        overhead = link.recv_cipher.overhead if link.recv_cipher is not None else 0
        self._max_frame_size = max_message_size + overhead
        self._heartbeat_interval = heartbeat_interval
        self._heartbeat_timeout = heartbeat_timeout
        self._on_message = on_message
        self._on_closed = on_closed
        self._send_lock = threading.Lock()
        self._reason_lock = threading.Lock()
        self._close_reason: str | None = None
        self._closing = threading.Event()
        self._last_recv = self._last_ping = time.monotonic()

    @property
    def closing(self) -> bool:
        """True once shutdown has begun, i.e. before anyone is told about the disconnect."""
        return self._closing.is_set()

    def start(self) -> None:
        threading.Thread(target=self._read_loop, name=f"{self._name}-reader", daemon=True).start()
        if self._heartbeat_interval is not None or self._heartbeat_timeout is not None:
            threading.Thread(target=self._heartbeat_loop, name=f"{self._name}-heartbeat", daemon=True).start()

    def send_message(self, kind: _Frame, payload: bytes) -> None:
        with self._send_lock:  # one frame at a time, so frames from different threads never interleave
            if self._send_cipher is not None:
                payload = self._send_cipher.encrypt(payload, _message_aad(kind, self._send_sequence))
                self._send_sequence += 1
            self.sock.sendall(_pack(kind, payload))

    def close(self, reason: str) -> None:
        """Ask the connection to shut down. Safe from any thread, any number of times; the first reason wins."""
        self._set_reason(reason)
        self._closing.set()
        try:
            self.sock.shutdown(socket.SHUT_RDWR)  # wakes a recv() blocked in the reader on Linux/macOS...
        except OSError:
            pass  # already closed
        self.sock.close()  # ...and this wakes it on Windows, where shutdown() alone does not

    def _set_reason(self, reason: str) -> str:
        with self._reason_lock:
            if self._close_reason is None:
                self._close_reason = reason
            return self._close_reason

    def _mark_alive(self) -> None:
        self._last_recv = time.monotonic()

    def _send_control(self, frame: bytes) -> None:
        """Send a PING/PONG, unless another send is already running.

        A busy lock means bytes are already flowing to the peer, which proves
        we are alive just as well, while waiting behind a large send would
        stall the reader or the watchdog.
        """
        if self._send_lock.acquire(blocking=False):
            try:
                self.sock.sendall(frame)
            finally:
                self._send_lock.release()

    def _read_loop(self) -> None:
        reason = "peer closed the connection"
        try:
            while (frame := _read_frame(self.sock, self._max_frame_size, self._mark_alive)) is not None:
                kind, payload = frame
                if kind == _Frame.PING:
                    self._send_control(_PONG)
                elif kind in (_Frame.PONG, _Frame.HELLO, _Frame.KEY_CHECK):
                    continue
                else:
                    if self._recv_cipher is not None:
                        payload = self._decrypt(kind, payload)
                    try:
                        message = _decode(kind, payload)
                    except ValueError as exc:
                        log.warning("%s: dropped an undecodable frame: %s", self._name, exc)
                        continue
                    self._on_message(message)
        except ProtocolError as exc:
            reason = f"protocol error: {exc}"
        except OSError as exc:
            reason = f"connection error: {exc}"
        finally:
            reason = self._set_reason(reason)
            self._closing.set()
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.sock.close()
            try:
                self._on_closed(self, reason)
            finally:
                self.done.set()

    def _decrypt(self, kind: int, payload: bytes) -> bytes:
        assert self._recv_cipher is not None
        if kind not in _DATA_FRAMES:
            raise ProtocolError(f"unexpected frame type {kind} on an encrypted link")
        try:
            plain = self._recv_cipher.decrypt(payload, _message_aad(kind, self._recv_sequence))
        except ValueError:
            raise ProtocolError("a message failed decryption: it was altered, replayed or reordered") from None
        self._recv_sequence += 1
        return plain

    def _heartbeat_loop(self) -> None:
        interval, timeout = self._heartbeat_interval, self._heartbeat_timeout
        tick = min(t for t in (interval, timeout) if t is not None) / 4
        tick = min(max(tick, 0.05), 1.0)
        while not self._closing.wait(tick):
            now = time.monotonic()
            silence = now - self._last_recv
            if timeout is not None and silence > timeout:
                self.close(f"nothing heard from peer for {silence:.1f}s (heartbeat timeout)")
                return
            if interval is not None and now - self._last_ping >= interval:
                self._last_ping = now
                try:
                    self._send_control(_PING)
                except OSError as exc:
                    self.close(f"heartbeat failed: {exc}")
                    return


# --------------------------------------------------------------------------- public base class


class SocketManager:
    """A point-to-point, full-duplex message link that keeps itself connected.

    Don't create this directly: use ServerSocketManager (waits for a client)
    or ClientSocketManager (dials a server). Both share this API.

    Lifecycle
        start()                    connect in the background; returns self
        wait_until_connected(t)    block until connected; False on timeout or if it gave up
        stop()                     disconnect and stop reconnecting
        ``with manager: ...``      start() on enter, stop() on exit

    Talking: either side, any time, no reply required
        send(message)              bytes, str, or anything JSON-serialisable (dict, list, number...)
        receive(timeout)           next message, if you prefer pulling over callbacks

    Callbacks: plain methods that also work as decorators
        on_connect(fn)             fn(peer_address), each time a link comes up
        on_message(fn)             fn(message), for every message received
        on_disconnect(fn)          fn(reason), each time a link goes down
        on_timeout(fn)             fn(), gave up connecting; the manager has stopped

    Callbacks run one at a time, in order, on a dedicated thread, so a slow
    callback never stalls the network side, and calling send() or stop()
    inside one is fine. While an on_message callback is registered, messages
    go to it instead of to receive().

    Args:
        connect_timeout: seconds to keep trying to establish a connection, on
            start and again after every drop, before giving up and firing
            on_timeout. None waits forever.
        reconnect: after the link drops, establish a new one (True) or stop (False).
        handshake_timeout: seconds allowed for a single connection attempt
            (TCP connect, optional TLS handshake, protocol greeting).
        heartbeat_interval: seconds between keep-alive pings. None disables pinging.
        heartbeat_timeout: seconds without hearing anything from the peer before
            the link is declared dead and dropped. None disables the check.
            Must be longer than the peer's heartbeat_interval.
        max_message_size: largest message payload, in bytes, sent or accepted.
        ssl_context: optional ``ssl.SSLContext`` to run the link over TLS, e.g.
            ``TlsManager.from_env("server").create_context()``.
        encryption: optional cipher that encrypts every message on top of TLS,
            e.g. ``EncryptionManager.from_env()``. Both ends need it, with the same key.
        name: label for log messages and thread names (defaults to the class name).
    """

    def __init__(
        self,
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
        for label, value in (
            ("connect_timeout", connect_timeout),
            ("handshake_timeout", handshake_timeout),
            ("heartbeat_interval", heartbeat_interval),
            ("heartbeat_timeout", heartbeat_timeout),
            ("max_message_size", max_message_size),
        ):
            if value is not None and value <= 0:
                raise ValueError(f"{label} must be positive (or None where allowed), got {value!r}")
        if heartbeat_interval is not None and heartbeat_timeout is not None and heartbeat_timeout <= heartbeat_interval:
            raise ValueError("heartbeat_timeout must be longer than heartbeat_interval")

        self.connect_timeout = connect_timeout
        self.reconnect = reconnect
        self.handshake_timeout = handshake_timeout
        self.heartbeat_interval = heartbeat_interval
        self.heartbeat_timeout = heartbeat_timeout
        self.max_message_size = max_message_size
        self.ssl_context = ssl_context
        self.encryption = encryption
        self.name = name or type(self).__name__

        self._handlers: dict[str, Callable[..., Any] | None] = dict.fromkeys(
            ("connect", "message", "disconnect", "timeout")
        )
        self._inbox: queue.Queue[Any] = queue.Queue()
        self._events: queue.Queue[tuple[str, tuple[Any, ...]] | None] = queue.Queue()
        self._state = threading.Condition()  # guards _conn and _running
        self._conn: _Connection | None = None
        self._running = False
        self._stop_event = threading.Event()
        self._supervisor: threading.Thread | None = None
        self._dispatcher: threading.Thread | None = None

    # ----------------------------------------------------------------- callbacks

    def on_connect(self, handler: Callable[[tuple[str, int]], Any]) -> Callable[[tuple[str, int]], Any]:
        """Call ``handler(peer_address)`` each time a connection is established."""
        self._handlers["connect"] = handler
        return handler

    def on_message(self, handler: Callable[[Any], Any]) -> Callable[[Any], Any]:
        """Call ``handler(message)`` for every message the peer sends."""
        self._handlers["message"] = handler
        return handler

    def on_disconnect(self, handler: Callable[[str], Any]) -> Callable[[str], Any]:
        """Call ``handler(reason)`` each time the connection is lost or closed."""
        self._handlers["disconnect"] = handler
        return handler

    def on_timeout(self, handler: Callable[[], Any]) -> Callable[[], Any]:
        """Call ``handler()`` when no connection could be made within connect_timeout."""
        self._handlers["timeout"] = handler
        return handler

    # ----------------------------------------------------------------- state

    @property
    def is_running(self) -> bool:
        """True from start() until stop(), or until it gives up after a timeout."""
        return self._running

    @property
    def is_connected(self) -> bool:
        """True while a peer is connected and messages can be sent."""
        return self._conn is not None

    @property
    def peer_address(self) -> tuple[str, int] | None:
        """``(host, port)`` of the connected peer, or None."""
        conn = self._conn
        return conn.peer if conn is not None else None

    def __repr__(self) -> str:
        peer = self.peer_address
        status = f"connected to {fmt_address(peer)}" if peer else ("waiting" if self._running else "stopped")
        return f"<{self.name} {status}>"

    # ----------------------------------------------------------------- lifecycle

    def start(self) -> Self:
        """Start connecting in the background and return immediately (returns self)."""
        with self._state:
            if self._running:
                raise RuntimeError(f"{self.name} is already running")
            self._prepare()  # e.g. bind the server port, so "address in use" surfaces right here
            self._running = True
            self._stop_event = threading.Event()
            self._events = queue.Queue()
        self._dispatcher = threading.Thread(
            target=self._dispatch_loop, args=(self._events,), name=f"{self.name}-callbacks", daemon=True
        )
        self._supervisor = threading.Thread(target=self._supervise, name=f"{self.name}-supervisor", daemon=True)
        self._dispatcher.start()
        self._supervisor.start()
        return self

    def stop(self, timeout: float | None = 5.0) -> bool:
        """Close the connection and stop reconnecting. Returns True once fully stopped."""
        with self._state:
            self._stop_event.set()
            conn = self._conn
        if conn is not None:
            conn.close("stopped locally")
        return self.wait_until_stopped(timeout)

    def wait_until_connected(self, timeout: float | None = None) -> bool:
        """Block until a peer is connected. False if ``timeout`` passed or the manager stopped."""
        with self._state:
            self._state.wait_for(lambda: self._conn is not None or not self._running, timeout)
            return self._conn is not None

    def wait_until_stopped(self, timeout: float | None = None) -> bool:
        """Block until the manager has stopped and every pending callback has run."""
        deadline = deadline_after(timeout)
        current = threading.current_thread()
        for thread in (self._supervisor, self._dispatcher):
            if thread is not None and thread is not current:  # a callback may call stop() on its own thread
                thread.join(None if deadline is None else max(0.0, deadline - time.monotonic()))
        return not self._running

    def __enter__(self) -> Self:
        return self.start()

    def __exit__(self, *exc_info: object) -> None:
        self.stop()

    # ----------------------------------------------------------------- talking

    def send(self, message: Any) -> None:
        """Send one message to the peer. Never waits for a reply.

        ``bytes`` arrive as bytes, ``str`` as str, and anything else is sent as
        JSON (dict, list, int, float, bool, None). Thread-safe.

        Raises:
            NotConnectedError: no peer is connected, or the link broke mid-send.
            TypeError: the message is not JSON-serialisable.
            ValueError: the message is larger than max_message_size.
        """
        kind, payload = _encode(message)
        if len(payload) > self.max_message_size:
            raise ValueError(f"message is {len(payload)} bytes; max_message_size is {self.max_message_size}")
        conn = self._conn
        if conn is None:
            raise NotConnectedError(f"{self.name} is not connected")
        try:
            conn.send_message(kind, payload)
        except OSError as exc:
            conn.close(f"send failed: {exc}")
            raise NotConnectedError(f"connection lost while sending: {exc}") from exc

    def receive(self, timeout: float | None = None) -> Any:
        """Return the next received message, waiting up to ``timeout`` seconds (None = forever).

        Only used when no on_message callback is registered.

        Raises:
            TimeoutError: nothing arrived within ``timeout``.
        """
        try:
            return self._inbox.get(timeout=timeout)
        except queue.Empty:
            raise TimeoutError(f"no message received within {timeout}s") from None

    # ----------------------------------------------------------------- for subclasses

    def _prepare(self) -> None:
        """Called by start() before any thread launches. Raise to abort start()."""

    def _establish(self, deadline: float | None) -> tuple[_Link, tuple[str, int]] | None:
        """Return a link that finished the handshake plus the peer address, or None on deadline or stop()."""
        raise NotImplementedError

    def _hold(self, conn: _Connection) -> None:
        """Return once ``conn`` has closed."""
        conn.done.wait()

    def _cleanup(self) -> None:
        """Called once the manager has stopped, on the supervisor thread."""

    def _open_session(self, sock: socket.socket, *, server_side: bool, server_hostname: str | None = None) -> _Link:
        """Turn a fresh TCP socket into a link: TLS (if configured), then the greeting.

        Closes the socket and raises OSError (ProtocolError, ssl.SSLError, TimeoutError...)
        if the peer doesn't complete it within handshake_timeout.
        """
        try:
            sock.settimeout(self.handshake_timeout)
            if self.ssl_context is not None:
                sock = self.ssl_context.wrap_socket(
                    sock, server_side=server_side, server_hostname=None if server_side else server_hostname
                )
            return _Link(sock, *self._greet(sock, server_side))
        except BaseException:
            sock.close()
            raise

    def _greet(self, sock: socket.socket, server_side: bool) -> tuple[Cipher | None, Cipher | None]:
        """Exchange HELLOs. With encryption, derive this connection's keys and check both ends hold the same key."""
        my_salt = os.urandom(_SALT_SIZE)
        my_flags = _FLAG_ENCRYPTED if self.encryption is not None else 0
        sock.sendall(_pack(_Frame.HELLO, _HELLO_MAGIC + bytes([my_flags]) + my_salt))
        frame = _read_frame(sock, _HELLO_SIZE)
        if frame is None:
            raise ConnectionResetError("peer closed the connection during the greeting")
        kind, hello = frame
        if kind != _Frame.HELLO or len(hello) != _HELLO_SIZE or not hello.startswith(_HELLO_MAGIC):
            raise ProtocolError("peer did not send a valid greeting")
        peer_flags, peer_salt = hello[len(_HELLO_MAGIC)], hello[len(_HELLO_MAGIC) + 1 :]
        if (peer_flags & _FLAG_ENCRYPTED) != my_flags:
            here, there = ("on", "off") if my_flags else ("off", "on")
            raise ProtocolError(f"message encryption is {here} here but {there} at the peer")
        if self.encryption is None:
            return None, None

        salt = my_salt + peer_salt if server_side else peer_salt + my_salt  # server's salt first, on both ends
        to_client = self.encryption.derive(salt=salt, info=b"secure-data-link/1 server->client")
        to_server = self.encryption.derive(salt=salt, info=b"secure-data-link/1 client->server")
        send, recv = (to_client, to_server) if server_side else (to_server, to_client)

        sock.sendall(_pack(_Frame.KEY_CHECK, send.encrypt(_KEY_CHECK, _KEY_CHECK_AAD)))
        frame = _read_frame(sock, len(_KEY_CHECK) + recv.overhead)
        if frame is None:
            raise ConnectionResetError("peer closed the connection during the key check")
        try:
            matched = frame[0] == _Frame.KEY_CHECK and recv.decrypt(frame[1], _KEY_CHECK_AAD) == _KEY_CHECK
        except ValueError:
            matched = False
        if not matched:
            raise ProtocolError("the two ends use different encryption keys")
        return send, recv

    # ----------------------------------------------------------------- internals

    def _emit(self, event: str, *args: Any) -> None:
        self._events.put((event, args))

    def _supervise(self) -> None:
        stop = self._stop_event
        try:
            while not stop.is_set():
                established = self._establish(deadline_after(self.connect_timeout))
                if established is None:
                    if not stop.is_set():
                        self._emit("timeout")
                    return
                conn = self._attach(*established)
                if conn is None:
                    return
                self._hold(conn)
                if not self.reconnect or stop.is_set():
                    return
                log.info("%s: link lost, re-establishing", self.name)
        except Exception:
            log.exception("%s: unexpected error; stopping", self.name)
        finally:
            conn = self._conn
            if conn is not None:
                conn.close("manager stopped")
                conn.done.wait(self.handshake_timeout)
            self._cleanup()
            with self._state:
                self._running = False
                self._state.notify_all()
            self._events.put(None)  # lets the callback thread drain what's left, then exit

    def _attach(self, link: _Link, peer: tuple[str, int]) -> _Connection | None:
        sock = link.sock
        sock.settimeout(None)
        for level, option in ((socket.IPPROTO_TCP, socket.TCP_NODELAY), (socket.SOL_SOCKET, socket.SO_KEEPALIVE)):
            try:
                sock.setsockopt(level, option, 1)
            except OSError:
                pass
        conn = _Connection(
            link,
            peer,
            name=self.name,
            max_message_size=self.max_message_size,
            heartbeat_interval=self.heartbeat_interval,
            heartbeat_timeout=self.heartbeat_timeout,
            on_message=lambda message: self._emit("message", message),
            on_closed=self._connection_closed,
        )
        with self._state:
            if self._stop_event.is_set():  # stop() raced with the handshake
                sock.close()
                return None
            self._conn = conn
            self._state.notify_all()
        log.info("%s: connected to %s", self.name, fmt_address(peer))
        self._emit("connect", peer)  # queued before the reader starts, so it precedes every message
        conn.start()
        return conn

    def _connection_closed(self, conn: _Connection, reason: str) -> None:
        with self._state:
            if self._conn is conn:
                self._conn = None
            self._state.notify_all()
        log.info("%s: disconnected from %s (%s)", self.name, fmt_address(conn.peer), reason)
        self._emit("disconnect", reason)

    def _dispatch_loop(self, events: queue.Queue[tuple[str, tuple[Any, ...]] | None]) -> None:
        while (item := events.get()) is not None:
            event, args = item
            handler = self._handlers[event]
            if handler is None:
                if event == "message":
                    self._inbox.put(args[0])
                continue
            try:
                handler(*args)
            except Exception:
                log.exception("%s: on_%s callback raised", self.name, event)
