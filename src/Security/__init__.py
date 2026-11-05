"""Security building blocks for the link: settings from .env, mutual TLS, and message encryption.

    env = EnvironmentManager()
    ssl_context = TlsManager.from_env("server", env).create_context()
    encryption = EncryptionManager.from_env(env)
"""

from .EnvironmentManager import PROJECT_ROOT, ConfigurationError, EnvironmentManager
from .EncryptionManager import DecryptionError, EncryptionManager
from .TlsManager import SERVER_CERT_NAME, CertificateFiles, TlsManager

__all__ = [
    "PROJECT_ROOT",
    "SERVER_CERT_NAME",
    "CertificateFiles",
    "ConfigurationError",
    "DecryptionError",
    "EncryptionManager",
    "EnvironmentManager",
    "TlsManager",
]
