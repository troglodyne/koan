"""One-shot Matrix password→device+token bootstrap.

Run once at first provision (the koan provisioner recipe wires this up):

    KOAN_MATRIX_HOMESERVER=https://matrix.example \
    KOAN_MATRIX_USER_ID=@koan:matrix.example \
    KOAN_MATRIX_PASSWORD='hunter2' \
    python -m app.matrix_login

It logs in over HTTPS, captures the freshly-minted device_id and
access_token, generates a pickle key if one is not already in the
environment, and writes a credentials file at
``$KOAN_ROOT/instance/matrix/credentials.env`` (0600).  The systemd
units load that file via a second ``EnvironmentFile=`` directive, so
no further bookkeeping is needed.

A device created here is guaranteed brand-new — matrix-nio's E2EE store
will not work with a reused device_id, so this is the only sanctioned
way to acquire one for the bot.

The script never logs out (that would invalidate the token); it just
closes the HTTP session.
"""

import asyncio
import os
import secrets
import socket
import sys
from pathlib import Path
from typing import Tuple


DEFAULT_CREDENTIALS_RELPATH = "instance/matrix/credentials.env"


def _short_hostname() -> str:
    try:
        return socket.gethostname().split(".", 1)[0] or "koan"
    except OSError:
        return "koan"


def _credentials_path() -> Path:
    koan_root = os.environ.get("KOAN_ROOT")
    base = Path(koan_root) if koan_root else Path.cwd()
    return base / DEFAULT_CREDENTIALS_RELPATH


def _write_credentials(path: Path, device_id: str, access_token: str, pickle_key: str) -> None:
    """Write credentials atomically with 0600 permissions."""
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        path.parent.chmod(0o700)
    except OSError:
        pass

    body = (
        "# Written by app.matrix_login — do not edit by hand.\n"
        f"KOAN_MATRIX_DEVICE_ID={device_id}\n"
        f"KOAN_MATRIX_ACCESS_TOKEN={access_token}\n"
        f"KOAN_MATRIX_PICKLE_KEY={pickle_key}\n"
    )
    tmp = path.with_suffix(path.suffix + ".tmp")
    # Open with 0600 from the start so the token never exists world-readable.
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(body)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    os.replace(tmp, path)
    os.chmod(path, 0o600)


async def _do_login(homeserver: str, user_id: str, password: str, device_name: str) -> Tuple[str, str]:
    """Log in and return (device_id, access_token).  Raises on failure."""
    from nio import AsyncClient, LoginResponse

    client = AsyncClient(homeserver, user_id)
    try:
        resp = await client.login(password, device_name=device_name)
        if not isinstance(resp, LoginResponse):
            raise RuntimeError(f"login failed: {resp}")
        return resp.device_id, resp.access_token
    finally:
        # close() releases the aiohttp session; do NOT call logout() —
        # that invalidates the token we just minted.
        await client.close()


def main(argv=None) -> int:
    homeserver = os.environ.get("KOAN_MATRIX_HOMESERVER", "").rstrip("/")
    user_id = os.environ.get("KOAN_MATRIX_USER_ID", "")
    password = os.environ.get("KOAN_MATRIX_PASSWORD", "")

    missing = [k for k, v in (
        ("KOAN_MATRIX_HOMESERVER", homeserver),
        ("KOAN_MATRIX_USER_ID", user_id),
        ("KOAN_MATRIX_PASSWORD", password),
    ) if not v]
    if missing:
        print(
            f"[matrix-login] missing required env vars: {', '.join(missing)}",
            file=sys.stderr,
        )
        return 1

    if not homeserver.startswith(("http://", "https://")):
        print(
            "[matrix-login] KOAN_MATRIX_HOMESERVER must start with http:// or https://",
            file=sys.stderr,
        )
        return 1

    device_name = f"koan-{_short_hostname()}"

    try:
        device_id, access_token = asyncio.run(
            _do_login(homeserver, user_id, password, device_name)
        )
    except Exception as exc:
        print(f"[matrix-login] login failed: {exc}", file=sys.stderr)
        return 1

    pickle_key = os.environ.get("KOAN_MATRIX_PICKLE_KEY") or secrets.token_hex(32)

    path = _credentials_path()
    try:
        _write_credentials(path, device_id, access_token, pickle_key)
    except OSError as exc:
        print(f"[matrix-login] cannot write {path}: {exc}", file=sys.stderr)
        return 1

    print(
        f"[matrix-login] success — device {device_id} written to {path}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
