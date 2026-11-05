"""Mutual TLS for the socket link: SSL contexts, plus a private CA to issue certificates.

    ssl_context = TlsManager.from_env("server").create_context()
    server = ServerSocketManager(..., ssl_context=ssl_context)

    ssl_context = TlsManager.from_env("client").create_context()
    client = ClientSocketManager(..., ssl_context=ssl_context, server_hostname=SERVER_CERT_NAME)

*Mutual* means both ends prove who they are. The server presents server.crt,
the client presents client.crt, and each side only accepts a certificate
signed by the shared ca.crt. The client also checks the server certificate's
name. Only TLS 1.3 is allowed.

``TlsManager.create_certificates()`` (used by setup-credentials.py) makes a
fresh private CA and signs one server and one client certificate with it. The
CA's private key is then discarded, so no one can issue more certificates for
this link; run it again to replace the whole set.
"""

from __future__ import annotations

import datetime
import ipaddress
import os
import ssl
from collections.abc import Iterable
from dataclasses import astuple, dataclass
from pathlib import Path
from typing import Literal

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .EnvironmentManager import ConfigurationError, EnvironmentManager

Role = Literal["server", "client"]

SERVER_CERT_NAME = "secure-data-link-server"
"""Always in the server certificate. Clients verify against it, so the server's IP may change freely."""

_SETUP_HINT = "run `python setup-credentials.py` to create the certificates"


@dataclass(frozen=True)
class CertificateFiles:
    """Where create_certificates() wrote each file."""

    ca_cert: Path
    server_cert: Path
    server_key: Path
    client_cert: Path
    client_key: Path

    @classmethod
    def in_directory(cls, directory: str | os.PathLike[str]) -> CertificateFiles:
        d = Path(directory)
        return cls(d / "ca.crt", d / "server.crt", d / "server.key", d / "client.crt", d / "client.key")

    def all(self) -> tuple[Path, ...]:
        return astuple(self)


class TlsManager:
    """Builds the SSLContext for one end of a mutual-TLS link.

    Args:
        role: "server" or "client".
        ca_cert: the CA certificate that signed the peer's certificate.
        cert: this end's certificate.
        key: this end's private key.
        key_password: password of ``key``, if it is encrypted.
    """

    def __init__(
        self,
        role: Role,
        *,
        ca_cert: str | os.PathLike[str],
        cert: str | os.PathLike[str],
        key: str | os.PathLike[str],
        key_password: str | None = None,
    ) -> None:
        if role not in ("server", "client"):
            raise ValueError(f'role must be "server" or "client", got {role!r}')
        self.role: Role = role
        self.ca_cert, self.cert, self.key = Path(ca_cert), Path(cert), Path(key)
        self._key_password = key_password
        for label, path in (("CA certificate", self.ca_cert), ("certificate", self.cert), ("private key", self.key)):
            if not path.is_file():
                raise ConfigurationError(f"TLS {label} not found at {path}; {_SETUP_HINT}")

    @classmethod
    def from_env(cls, role: Role, env: EnvironmentManager | None = None) -> TlsManager:
        """Read TLS_CA_CERT, TLS_<ROLE>_CERT, TLS_<ROLE>_KEY and TLS_KEY_PASSWORD from .env."""
        env = env or EnvironmentManager()
        prefix = f"TLS_{role.upper()}_"
        return cls(
            role,
            ca_cert=env.get_path("TLS_CA_CERT"),
            cert=env.get_path(prefix + "CERT"),
            key=env.get_path(prefix + "KEY"),
            key_password=env.get("TLS_KEY_PASSWORD", None),
        )

    def create_context(self) -> ssl.SSLContext:
        """An SSLContext for this role that requires and verifies the peer's certificate."""
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if self.role == "server" else ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.verify_mode = ssl.CERT_REQUIRED  # on the server, this is what makes the TLS *mutual*
        context.verify_flags |= ssl.VERIFY_X509_STRICT
        # PROTOCOL_TLS_CLIENT already turns on check_hostname: the server certificate must carry the expected name.
        try:
            context.load_cert_chain(self.cert, self.key, password=self._password)
            context.load_verify_locations(cafile=self.ca_cert)
        except ssl.SSLError as exc:
            raise ConfigurationError(
                f"could not load the TLS files ({exc.reason or exc}). Check that {self.key.name} belongs to "
                f"{self.cert.name}, that TLS_KEY_PASSWORD is right if the key is encrypted, "
                f"and that {self.ca_cert.name} is a CA certificate"
            ) from None
        return context

    def _password(self) -> str:
        # A callable instead of None: with None, OpenSSL would stop and prompt on the console for a password.
        if self._key_password is None:
            raise ConfigurationError(f"{self.key} is password-protected; set TLS_KEY_PASSWORD")
        return self._key_password

    # ----------------------------------------------------------------- issuing certificates

    @staticmethod
    def create_certificates(
        directory: str | os.PathLike[str],
        *,
        server_names: Iterable[str] = (),
        valid_days: int = 825,
        overwrite: bool = False,
    ) -> CertificateFiles:
        """Create a private CA and use it to sign a server and a client certificate.

        Args:
            directory: where to write ca.crt, server.crt/.key and client.crt/.key.
            server_names: extra hostnames or IP addresses for the server
                certificate. It always holds SERVER_CERT_NAME, localhost,
                127.0.0.1 and ::1.
            valid_days: how long the certificates stay valid.
            overwrite: replace existing files instead of raising FileExistsError.
        """
        files = CertificateFiles.in_directory(directory)
        existing = [path.name for path in files.all() if path.exists()]
        if existing and not overwrite:
            raise FileExistsError(f"{', '.join(existing)} already exist in {directory}")
        Path(directory).mkdir(parents=True, exist_ok=True)

        now = datetime.datetime.now(datetime.timezone.utc)
        not_before, not_after = now - datetime.timedelta(minutes=5), now + datetime.timedelta(days=valid_days)

        ca_key = ec.generate_private_key(ec.SECP256R1())
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "secure-data-link private CA")])
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(ca_name)
            .issuer_name(ca_name)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(_key_usage(cert_sign=True), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256())
        )

        def issue(common_name: str, usage: x509.ObjectIdentifier, names: list[x509.GeneralName]):
            key = ec.generate_private_key(ec.SECP256R1())
            cert = (
                x509.CertificateBuilder()
                .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
                .issuer_name(ca_name)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(not_before)
                .not_valid_after(not_after)
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(_key_usage(cert_sign=False), critical=True)
                # A certificate is only accepted for its own role, so the client's can't impersonate the server.
                .add_extension(x509.ExtendedKeyUsage([usage]), critical=False)
                .add_extension(x509.SubjectAlternativeName(names), critical=False)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
                .add_extension(
                    x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False
                )
                .sign(ca_key, hashes.SHA256())
            )
            return key, cert

        server_key, server_cert = issue(
            "secure-data-link server",
            ExtendedKeyUsageOID.SERVER_AUTH,
            _general_names([SERVER_CERT_NAME, "localhost", "127.0.0.1", "::1", *server_names]),
        )
        client_key, client_cert = issue(
            "secure-data-link client",
            ExtendedKeyUsageOID.CLIENT_AUTH,
            [x509.DNSName("secure-data-link-client")],
        )

        _write_cert(files.ca_cert, ca_cert)
        _write_cert(files.server_cert, server_cert)
        _write_key(files.server_key, server_key)
        _write_cert(files.client_cert, client_cert)
        _write_key(files.client_key, client_key)
        return files  # ca_key is dropped here on purpose


def _key_usage(*, cert_sign: bool) -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=not cert_sign,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=cert_sign,
        crl_sign=cert_sign,
        encipher_only=False,
        decipher_only=False,
    )


def _general_names(names: Iterable[str]) -> list[x509.GeneralName]:
    result: list[x509.GeneralName] = []
    for name in dict.fromkeys(n.strip() for n in names if n.strip()):  # de-duplicate, keep order
        try:
            result.append(x509.IPAddress(ipaddress.ip_address(name)))
        except ValueError:
            result.append(x509.DNSName(name))
    return result


def _write_cert(path: Path, cert: x509.Certificate) -> None:
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def _write_key(path: Path, key: ec.EllipticCurvePrivateKey) -> None:
    pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    if path.exists():
        path.unlink()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)  # owner-only where the OS supports it
    with os.fdopen(fd, "wb") as handle:
        handle.write(pem)
