# secure-data-link

Secure point-to-point data transfer between devices over Ethernet using mutual TLS.

## Quick start

```shell
pip install -r requirements.txt
python setup-credentials.py      # creates certs/ and .env (with a fresh ENCRYPTION_KEY)
python app-server.py             # terminal 1
python app-client.py             # terminal 2: type on either side, at any time
```

For two devices, give the server `certs/ca.crt`, `server.crt`, `server.key` and the client
`certs/ca.crt`, `client.crt`, `client.key`. Both need a `.env` with the **same** `ENCRYPTION_KEY`.
On the client, set `SERVER_HOST` to the server's IP. All settings are described in `.env.example`.

## How the link is protected

- **Mutual TLS 1.3** (`src/Security/TlsManager.py`): each side presents its own certificate, and each
  only accepts one signed by the project's private CA. The CA's private key is discarded once
  it has signed the two certificates.
- **Message encryption** (`src/Security/EncryptionManager.py`): AES-256-GCM on every message, on top
  of TLS. Each connection derives fresh keys for each direction from `ENCRYPTION_KEY`. Altered, replayed or
  reordered messages are rejected, and the handshake fails if the two ends hold different keys.
- **Settings** (`src/Security/EnvironmentManager.py`): read from `.env`; real environment variables
  override it.

## Using the library

```python
from src.Security import EncryptionManager, EnvironmentManager, TlsManager
from src.SocketManager import ServerSocketManager

env = EnvironmentManager()
server = ServerSocketManager(
    "0.0.0.0", env.get_int("SERVER_PORT", 5000),
    ssl_context=TlsManager.from_env("server", env).create_context(),
    encryption=EncryptionManager.from_env(env),
)
server.on_message(lambda message: print("client:", message))
server.start()
server.wait_until_connected()
server.send({"hello": "client"})   # either side may send first; no reply needed
```

`ClientSocketManager` works the same way. It retries until it connects (or `connect_timeout`
passes) and reconnects by itself if the link drops. See `src/SocketManager/SocketManager.py`
for the full API.
