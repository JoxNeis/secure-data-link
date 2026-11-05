"""Read settings from the project's .env file, with types and clear errors.

    env = EnvironmentManager()                 # loads <project root>/.env
    port = env.get_int("SERVER_PORT", 5000)    # default used when the key is unset
    key = env.get("ENCRYPTION_KEY")            # no default: raises ConfigurationError if unset
    ca = env.get_path("TLS_CA_CERT")           # relative paths resolve next to the .env file

Real environment variables win over the file, so one run can override a value
without editing .env (PowerShell: ``$env:SERVER_PORT=6000; python app-server.py``).
An empty value (``KEY=``) counts as unset.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path
from typing import Any, TypeVar

from dotenv import dotenv_values

PROJECT_ROOT = Path(__file__).resolve().parents[2]

T = TypeVar("T")
_MISSING: Any = object()
_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off"}


class ConfigurationError(ValueError):
    """A setting is missing or invalid, or a file it points to is unusable."""


class EnvironmentManager:
    """Typed access to settings from a .env file and the process environment.

    Args:
        env_file: the .env file to read. Defaults to ``.env`` in the project
            root, wherever the app is started from. A missing file is not an
            error: settings can come from real environment variables alone.
    """

    def __init__(self, env_file: str | os.PathLike[str] = PROJECT_ROOT / ".env") -> None:
        self.env_file = Path(env_file).resolve()
        self.base_dir = self.env_file.parent
        values = dotenv_values(self.env_file) if self.env_file.is_file() else {}
        self._file_values = {key: value for key, value in values.items() if value}

    def __contains__(self, key: str) -> bool:
        return self._raw(key) is not None

    def get(self, key: str, default: T = _MISSING) -> str | T:
        """The setting as a string."""
        return self._read(key, default, str, "text")

    def get_int(self, key: str, default: T = _MISSING) -> int | T:
        """The setting as an integer."""
        return self._read(key, default, int, "a whole number")

    def get_float(self, key: str, default: T = _MISSING) -> float | T:
        """The setting as a number."""
        return self._read(key, default, float, "a number")

    def get_timeout(self, key: str, default: T = _MISSING) -> float | None | T:
        """The setting as a number of seconds, where ``none`` means no limit (returns None)."""
        return self._read(key, default, lambda raw: None if raw.lower() == "none" else float(raw), 'a number or "none"')

    def get_bool(self, key: str, default: T = _MISSING) -> bool | T:
        """The setting as a boolean: true/false, yes/no, on/off or 1/0."""

        def parse(raw: str) -> bool:
            lowered = raw.lower()
            if lowered in _TRUE:
                return True
            if lowered in _FALSE:
                return False
            raise ValueError(raw)

        return self._read(key, default, parse, "true or false")

    def get_path(self, key: str, default: str | os.PathLike[str] | T = _MISSING) -> Path | T:
        """The setting as a path. Relative paths are taken relative to the .env file's folder."""
        raw = self._raw(key)
        if raw is None:
            if default is _MISSING:
                raise self._missing(key)
            if not isinstance(default, (str, os.PathLike)):
                return default
            raw = os.fspath(default)
        path = Path(raw).expanduser()
        return path if path.is_absolute() else (self.base_dir / path).resolve()

    # ----------------------------------------------------------------- internals

    def _raw(self, key: str) -> str | None:
        return os.environ.get(key) or self._file_values.get(key) or None

    def _read(self, key: str, default: Any, parse: Callable[[str], Any], expected: str) -> Any:
        raw = self._raw(key)
        if raw is None:
            if default is _MISSING:
                raise self._missing(key)
            return default
        try:
            return parse(raw.strip())
        except ValueError:
            raise ConfigurationError(f"{key}={raw!r} in {self._source(key)} is not {expected}") from None

    def _missing(self, key: str) -> ConfigurationError:
        where = self.env_file if self.env_file.is_file() else f"{self.env_file} (file not found)"
        return ConfigurationError(f"{key} is not set. Add it to {where}; see .env.example")

    def _source(self, key: str) -> str:
        return "the environment" if os.environ.get(key) else str(self.env_file)
