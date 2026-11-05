"""Interactive demo: a mutual-TLS, encrypted link configured from .env.

Run `python setup-credentials.py` once, start app-server.py, then this, and
type on either side at any time.
"""

import logging
import sys

from src.Security import ConfigurationError, EncryptionManager, EnvironmentManager, TlsManager
from src.SocketManager import ClientSocketManager, NotConnectedError


def create_client() -> ClientSocketManager:
    """Build the client from the settings in .env."""
    env = EnvironmentManager()
    return ClientSocketManager(
        env.get("SERVER_HOST", "127.0.0.1"),
        env.get_int("SERVER_PORT", 5000),
        connect_timeout=env.get_timeout("CONNECT_TIMEOUT", 300),
        retry_interval=env.get_float("RETRY_INTERVAL", 2.0),
        ssl_context=TlsManager.from_env("client", env).create_context(),
        server_hostname=env.get("TLS_SERVER_NAME", None),
        encryption=EncryptionManager.from_env(env),
    )


def main() -> None:
    logging.basicConfig(level=logging.WARNING, format="%(asctime)s %(levelname)s %(message)s", datefmt="%H:%M:%S")
    try:
        client = create_client()
    except ConfigurationError as exc:
        sys.exit(f"Configuration problem: {exc}")

    client.on_connect(lambda peer: print(f"[+] connected to server {peer[0]}:{peer[1]}"))
    client.on_message(lambda message: print(f"server> {message}"))
    client.on_disconnect(lambda reason: print(f"[-] disconnected: {reason}"))
    client.on_timeout(lambda: print("[!] could not reach the server, client stopped. Press Enter to exit."))

    client.start()
    try:
        print(f"Connecting to {client.host}:{client.port} with mutual TLS and encrypted messages.")
        print("Type a message and press Enter; /quit to exit.")
        while client.is_running:
            try:
                line = input()
            except (EOFError, KeyboardInterrupt):
                break
            if line.strip() == "/quit" or not client.is_running:
                break
            if line:
                try:
                    client.send(line)
                except NotConnectedError:
                    print("[!] not connected, message not sent")
    finally:
        client.stop()


if __name__ == "__main__":
    main()
