"""Authenticated encryption (AES-256-GCM) with a key shared by both devices.

    crypto = EncryptionManager.from_env()           # reads ENCRYPTION_KEY from .env
    token = crypto.encrypt(b"secret data")
    crypto.decrypt(token)                           # b"secret data"

Handing it to a socket manager encrypts every message on the link, on top of TLS:

    ServerSocketManager(..., encryption=EncryptionManager.from_env())

The link never uses the shared key directly. Each connection derives two fresh
keys from it, one per direction, and numbers every message, so a message that
is altered, replayed, reordered or dropped fails to decrypt and ends the
connection.

Token layout: ``[1-byte version][12-byte random nonce][ciphertext][16-byte tag]``.
Under one key, keep below about 2**32 encrypted messages (the AES-GCM limit for
random nonces). The link's per-connection keys keep it far below that.
"""

from __future__ import annotations

import base64
import binascii
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .EnvironmentManager import ConfigurationError, EnvironmentManager

_KEY_HELP = "it must be 32 random bytes in base64; run `python setup-credentials.py` to generate one"


class DecryptionError(ValueError):
    """The data was altered, is not a token, or was encrypted with a different key or associated data."""


class EncryptionManager:
    """Encrypts and authenticates data with AES-256-GCM.

    Args:
        key: 32 raw bytes, or those bytes base64-encoded (the format of
            ``generate_key()`` and of ENCRYPTION_KEY in .env).
    """

    KEY_SIZE = 32
    NONCE_SIZE = 12
    TAG_SIZE = 16
    VERSION = 1
    overhead = 1 + NONCE_SIZE + TAG_SIZE  # bytes each token adds to the plaintext

    def __init__(self, key: bytes | str) -> None:
        self._key = self._parse_key(key)
        self._aead = AESGCM(self._key)

    @classmethod
    def generate_key(cls) -> str:
        """A new random key, base64-encoded, ready to paste into .env as ENCRYPTION_KEY."""
        return base64.urlsafe_b64encode(os.urandom(cls.KEY_SIZE)).decode("ascii")

    @classmethod
    def from_env(cls, env: EnvironmentManager | None = None, name: str = "ENCRYPTION_KEY") -> EncryptionManager:
        """Build from the key stored in .env (or the environment) under ``name``."""
        env = env or EnvironmentManager()
        try:
            return cls(env.get(name))
        except ConfigurationError as exc:
            raise ConfigurationError(f"{exc}. Run `python setup-credentials.py` to generate one") from None
        except ValueError:
            raise ConfigurationError(f"{name} is not a valid key: {_KEY_HELP}") from None

    def encrypt(self, data: bytes, associated_data: bytes = b"") -> bytes:
        """Encrypt ``data``. ``associated_data`` is authenticated too but not stored in the token."""
        nonce = os.urandom(self.NONCE_SIZE)
        header = bytes([self.VERSION])
        return header + nonce + self._aead.encrypt(nonce, bytes(data), header + associated_data)

    def decrypt(self, token: bytes, associated_data: bytes = b"") -> bytes:
        """Decrypt a token from ``encrypt``; ``associated_data`` must match what it was encrypted with.

        Raises:
            DecryptionError: the token was altered, truncated, or made with another key or associated data.
        """
        if len(token) < self.overhead or token[0] != self.VERSION:
            raise DecryptionError("not a token produced by EncryptionManager")
        nonce = token[1 : 1 + self.NONCE_SIZE]
        try:
            return self._aead.decrypt(nonce, token[1 + self.NONCE_SIZE :], token[:1] + associated_data)
        except InvalidTag:
            raise DecryptionError("data was altered or encrypted with a different key") from None

    def derive(self, *, salt: bytes, info: bytes) -> EncryptionManager:
        """A new, independent EncryptionManager whose key is derived from this one (HKDF-SHA256)."""
        key = HKDF(algorithm=hashes.SHA256(), length=self.KEY_SIZE, salt=salt, info=info).derive(self._key)
        return EncryptionManager(key)

    def __repr__(self) -> str:
        return "<EncryptionManager AES-256-GCM>"  # never show the key

    @classmethod
    def _parse_key(cls, key: bytes | str) -> bytes:
        if isinstance(key, str):
            text = key.strip().replace("-", "+").replace("_", "/")  # accept url-safe and standard base64
            try:
                key = base64.b64decode(text, validate=True)
            except (binascii.Error, ValueError):
                raise ValueError(f"the key is not valid base64: {_KEY_HELP}") from None
        if len(key) != cls.KEY_SIZE:
            raise ValueError(f"the key is {len(key)} bytes: {_KEY_HELP}")
        return bytes(key)
