"""Interactive demo: a mutual-TLS, encrypted link configured from .env.

Run `python setup-credentials.py` once, start this, then app-client.py, and
type on either side at any time.
"""

import logging
import sys

from src.Security import ConfigurationError, EncryptionManager, EnvironmentManager, TlsManager
from src.SocketManager import NotConnectedError, ServerSocketManager


def create_server() -> ServerSocketManager:
    """Build the server from the settings in .env."""
    env = EnvironmentManager()
    return ServerSocketManager(
        env.get("LISTEN_HOST", "0.0.0.0"),
        env.get_int("SERVER_PORT", 5000),
        connect_timeout=env.get_timeout("CONNECT_TIMEOUT", 300),
        ssl_context=TlsManager.from_env("server", env).create_context(),
        encryption=EncryptionManager.from_env(env),
    )


def main() -> None:
    logging.basicConfig(level=logging.WARNING, format="%(asctime)s %(levelname)s %(message)s", datefmt="%H:%M:%S")
    try:
        server = create_server()
    except ConfigurationError as exc:
        sys.exit(f"Configuration problem: {exc}")

    server.on_connect(lambda peer: print(f"[+] client connected from {peer[0]}:{peer[1]}"))
    server.on_message(lambda message: print(f"client> {message}"))
    server.on_disconnect(lambda reason: print(f"[-] client disconnected: {reason}"))
    server.on_timeout(lambda: print("[!] no client came in time, server stopped. Press Enter to exit."))

    try:
        server.start()
    except OSError as exc:
        sys.exit(f"Could not listen on {server.host}:{server.port}: {exc}")
    try:
        print(f"Listening on {server.host}:{server.port} with mutual TLS and encrypted messages.")
        print("Type a message and press Enter; /quit to exit.")
        while server.is_running:
            try:
                line = input()
            except (EOFError, KeyboardInterrupt):
                break
            if line.strip() == "/quit" or not server.is_running:
                break
            if line:
                try:
                    server.send(line)
                except NotConnectedError:
                    print("[!] no client connected, message not sent")
    finally:
        server.stop()


if __name__ == "__main__":
    main()
