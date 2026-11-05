"""Create the TLS certificates and encryption key the link needs, and a .env that uses them.

    python setup-credentials.py                              # testing on one machine
    python setup-credentials.py --server-name 192.168.1.10   # also valid for this name or IP
    python setup-credentials.py --force                      # replace existing certificates
    python setup-credentials.py --new-key                    # replace ENCRYPTION_KEY

Writes certs/ (a private CA certificate, plus a server and a client certificate
with their keys) and .env (copied from .env.example) with a fresh ENCRYPTION_KEY.
Existing certificates and keys are kept unless you ask to replace them.
"""

import argparse
import shutil

from dotenv import dotenv_values, set_key

from src.Security import PROJECT_ROOT, CertificateFiles, EncryptionManager, TlsManager

CERT_DIR = PROJECT_ROOT / "certs"
ENV_FILE = PROJECT_ROOT / ".env"
ENV_TEMPLATE = PROJECT_ROOT / ".env.example"

NEXT_STEPS = """
Next steps
  One machine:   python app-server.py     then, in a second terminal:   python app-client.py

  Two devices:   copy the project to both, then give each device only what it needs:
    server:  certs/ca.crt  certs/server.crt  certs/server.key
    client:  certs/ca.crt  certs/client.crt  certs/client.key
    both:    .env with the SAME ENCRYPTION_KEY (on the client, set SERVER_HOST to the server's IP)

  Keep the .key files and .env secret. Git ignores them.
"""


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--server-name", action="append", default=[], metavar="NAME_OR_IP",
        help="extra hostname or IP address the server certificate is valid for (repeatable)",
    )
    parser.add_argument("--days", type=int, default=825, help="certificate lifetime in days (default: 825)")
    parser.add_argument("--force", action="store_true", help="replace existing certificates")
    parser.add_argument("--new-key", action="store_true", help="replace the existing ENCRYPTION_KEY")
    args = parser.parse_args()

    try:
        files = TlsManager.create_certificates(
            CERT_DIR, server_names=args.server_name, valid_days=args.days, overwrite=args.force
        )
        print(f"Created certificates in {CERT_DIR}")
    except FileExistsError:
        files = CertificateFiles.in_directory(CERT_DIR)
        print(f"Kept the existing certificates in {CERT_DIR} (use --force to replace them)")
    for path in files.all():
        print(f"  {path.relative_to(PROJECT_ROOT)}")

    if not ENV_FILE.is_file() or ENV_FILE.stat().st_size == 0:
        shutil.copyfile(ENV_TEMPLATE, ENV_FILE)
        print(f"Created .env from {ENV_TEMPLATE.name}")
    if args.new_key or not dotenv_values(ENV_FILE).get("ENCRYPTION_KEY"):
        set_key(ENV_FILE, "ENCRYPTION_KEY", EncryptionManager.generate_key(), quote_mode="never")
        print("Wrote a new ENCRYPTION_KEY to .env")
    else:
        print("Kept the existing ENCRYPTION_KEY in .env (use --new-key to replace it)")

    print(NEXT_STEPS)


if __name__ == "__main__":
    main()
