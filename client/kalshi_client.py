"""Authenticated Kalshi API client used by the notebooks in this repository.

Security note
-------------
This client authenticates with a long-lived email/password pair read from
``client/credentials.yaml``. That file is git-ignored, but a plaintext password
on disk is strictly weaker than the RSA API-key scheme Kalshi documents for
programmatic access (see the ``kalshi-starter-code-python`` repository, which
signs each request with an RSA-PSS signature and never stores a password). Treat
this path as legacy: prefer an API key/private key pair for anything beyond
local exploration, and never reuse your interactive account password here.
"""

import os
from pathlib import Path
from typing import Any, Dict, Optional

import kalshi_python
import yaml

# Resolved relative to this source file rather than the process working
# directory. The previous literal "client/credentials.yaml" only resolved when
# the interpreter happened to be started from the repository root, so the same
# code raised a misleading "please create a credentials file" error when run
# from a notebook in projects/.
DEFAULT_CREDENTIALS_PATH = Path(__file__).resolve().parent / "credentials.yaml"

# Optional override so callers can keep credentials outside the checkout.
CREDENTIALS_PATH_ENV_VAR = "KALSHI_CREDENTIALS_PATH"

REQUIRED_FIELDS = ("username", "password")


def _credentials_path() -> Path:
    """Returns the credentials file path, honouring the environment override."""
    override = os.getenv(CREDENTIALS_PATH_ENV_VAR)
    return Path(override).expanduser() if override else DEFAULT_CREDENTIALS_PATH


def load_credentials(path: Optional[Path] = None) -> Dict[str, Any]:
    """Loads and validates the credentials file.

    Args:
        path: Optional explicit path. Defaults to :func:`_credentials_path`.

    Returns:
        The parsed mapping, guaranteed to contain every field in
        ``REQUIRED_FIELDS``.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the file is empty, is not a YAML mapping, is not valid
            YAML, or is missing a required field. Error messages name the
            missing keys only; no credential value is ever included.
    """
    resolved = Path(path) if path is not None else _credentials_path()

    try:
        # A context manager instead of a bare open(): the previous
        # `yaml.safe_load(open(...))` leaked the file descriptor on every call
        # because nothing ever closed it, and on CPython it was only reclaimed
        # by chance when the object was garbage collected.
        with resolved.open("r", encoding="utf-8") as handle:
            creds = yaml.safe_load(handle)
    except FileNotFoundError as exc:
        raise FileNotFoundError(
            f"No credentials file at {resolved}. Create it (see README.md), or "
            f"set {CREDENTIALS_PATH_ENV_VAR} to point at one elsewhere."
        ) from exc
    except yaml.YAMLError as exc:
        # `from exc` preserves the parser's line/column context, which the
        # previous bare `raise Exception(...)` discarded.
        raise ValueError(f"{resolved} is not valid YAML") from exc

    if creds is None:
        # safe_load returns None for an empty document. Without this guard the
        # membership test below raised
        # "TypeError: argument of type 'NoneType' is not iterable"
        # instead of telling the operator the file was blank.
        raise ValueError(f"{resolved} is empty; add the username and password fields.")
    if not isinstance(creds, dict):
        raise ValueError(
            f"{resolved} must contain a YAML mapping, got {type(creds).__name__}."
        )

    missing = [field for field in REQUIRED_FIELDS if not creds.get(field)]
    if missing:
        raise ValueError(
            f"{resolved} is missing a value for: {', '.join(missing)}. "
            "See README.md for the expected format."
        )

    _warn_if_world_readable(resolved)
    return creds


def _warn_if_world_readable(path: Path) -> None:
    """Prints a warning when the credentials file is readable by other users.

    POSIX only. On Windows the permission bits reported by ``stat`` do not model
    ACLs, so the check is skipped rather than reporting a misleading result.
    """
    if os.name != "posix":
        return
    mode = path.stat().st_mode
    if mode & 0o077:
        print(
            f"WARNING: {path} is readable by group/other (mode {mode & 0o777:o}). "
            f"Run: chmod 600 {path}"
        )


class AuthedApiInstance(kalshi_python.ApiInstance):
    """A ``kalshi_python.ApiInstance`` that logs in during construction."""

    def __init__(self, credentials_path: Optional[Path] = None):
        """Reads the credentials, then exchanges them for a session token.

        Args:
            credentials_path: Optional explicit path to the credentials YAML.

        Raises:
            FileNotFoundError: If the credentials file is absent.
            ValueError: If the credentials file is malformed or incomplete.
        """
        creds = load_credentials(credentials_path)

        config = kalshi_python.Configuration()
        super().__init__(configuration=config)

        # The password is passed straight through to the SDK and is never logged,
        # printed, or stored on this instance; only the returned token is kept.
        login_response = self.login(
            kalshi_python.LoginRequest(
                email=creds["username"],
                password=creds["password"],
            )
        )
        self.set_api_token(login_response.token)

