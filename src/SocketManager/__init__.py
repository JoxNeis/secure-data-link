"""Point-to-point socket link that stays connected and talks both ways.

Quick start::

    # on the server machine
    from src.SocketManager import ServerSocketManager

    server = ServerSocketManager("0.0.0.0", 5000)
    server.on_message(lambda message: print("client says:", message))
    server.start()
    server.wait_until_connected()
    server.send("hi client")             # the server may speak first...

    # on the client machine
    from src.SocketManager import ClientSocketManager

    client = ClientSocketManager("192.168.1.10", 5000)
    client.on_message(lambda message: print("server says:", message))
    client.start()
    client.wait_until_connected()
    client.send({"temperature": 21.5})   # ...and so may the client, at any time

See SocketManager for the full API.
"""

from .SocketManager import NotConnectedError, SocketManager
from .ServerSocketManager import ServerSocketManager
from .ClientSocketManager import ClientSocketManager

__all__ = ["ClientSocketManager", "NotConnectedError", "ServerSocketManager", "SocketManager"]
