"""Tests for app.matrix_login — the one-shot password→device bootstrap.

Mocks the matrix-nio AsyncClient.login surface; never makes a real HTTP
call. Asserts the credentials file is written 0600 with the three vars
the systemd unit will EnvironmentFile= load.
"""

import asyncio
import os
import stat
import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest


# ---------------------------------------------------------------------------
# Fake matrix-nio surface (mirrors test_matrix_provider but smaller)
# ---------------------------------------------------------------------------


class _FakeLoginResponse:
    def __init__(self, device_id, access_token):
        self.device_id = device_id
        self.access_token = access_token


class _FakeErrorResponse:
    def __init__(self, msg=""):
        self.message = msg

    def __repr__(self):
        return f"ErrorResponse({self.message!r})"


class _FakeAsyncClient:
    instances = []

    def __init__(self, homeserver, user_id):
        self.homeserver = homeserver
        self.user_id = user_id
        self.closed = False
        self.login_args = None
        # Tests overwrite this to control the login result.
        self.login_result = _FakeLoginResponse("BRAND_NEW_DEVICE", "syt_minted")
        type(self).instances.append(self)

    async def login(self, password, device_name=None):
        self.login_args = (password, device_name)
        if isinstance(self.login_result, BaseException):
            raise self.login_result
        return self.login_result

    async def close(self):
        self.closed = True


@pytest.fixture(autouse=True)
def fake_nio():
    mod = SimpleNamespace(
        AsyncClient=_FakeAsyncClient,
        LoginResponse=_FakeLoginResponse,
        ErrorResponse=_FakeErrorResponse,
    )
    sys.modules["nio"] = mod
    _FakeAsyncClient.instances.clear()
    yield
    sys.modules.pop("nio", None)


@pytest.fixture
def env(monkeypatch, tmp_path):
    monkeypatch.setenv("KOAN_ROOT", str(tmp_path))
    monkeypatch.setenv("KOAN_MATRIX_HOMESERVER", "https://matrix.example")
    monkeypatch.setenv("KOAN_MATRIX_USER_ID", "@koan:matrix.example")
    monkeypatch.setenv("KOAN_MATRIX_PASSWORD", "hunter2")
    monkeypatch.delenv("KOAN_MATRIX_PICKLE_KEY", raising=False)
    return tmp_path


# ---------------------------------------------------------------------------
# main() exit codes + env validation
# ---------------------------------------------------------------------------


class TestEnvValidation:
    def test_success_returns_zero(self, env):
        from app import matrix_login
        assert matrix_login.main([]) == 0

    @pytest.mark.parametrize("var", [
        "KOAN_MATRIX_HOMESERVER",
        "KOAN_MATRIX_USER_ID",
        "KOAN_MATRIX_PASSWORD",
    ])
    def test_missing_var_fails(self, env, monkeypatch, var):
        monkeypatch.delenv(var, raising=False)
        from app import matrix_login
        assert matrix_login.main([]) == 1

    def test_bad_scheme_fails(self, env, monkeypatch):
        monkeypatch.setenv("KOAN_MATRIX_HOMESERVER", "matrix.example")
        from app import matrix_login
        assert matrix_login.main([]) == 1


# ---------------------------------------------------------------------------
# Credentials file
# ---------------------------------------------------------------------------


class TestCredentialsFile:
    def test_file_written_with_three_vars(self, env):
        from app import matrix_login
        assert matrix_login.main([]) == 0
        creds = env / "instance" / "matrix" / "credentials.env"
        assert creds.is_file()
        body = creds.read_text()
        assert "KOAN_MATRIX_DEVICE_ID=BRAND_NEW_DEVICE" in body
        assert "KOAN_MATRIX_ACCESS_TOKEN=syt_minted" in body
        assert "KOAN_MATRIX_PICKLE_KEY=" in body
        # Pickle key is 32 bytes hex = 64 chars
        pickle_line = [l for l in body.splitlines() if l.startswith("KOAN_MATRIX_PICKLE_KEY=")][0]
        assert len(pickle_line.split("=", 1)[1]) == 64

    def test_file_is_0600(self, env):
        from app import matrix_login
        assert matrix_login.main([]) == 0
        creds = env / "instance" / "matrix" / "credentials.env"
        mode = stat.S_IMODE(creds.stat().st_mode)
        assert mode == 0o600, f"expected 0600, got 0o{mode:o}"

    def test_existing_pickle_key_preserved(self, env, monkeypatch):
        monkeypatch.setenv("KOAN_MATRIX_PICKLE_KEY", "deadbeef" * 8)
        from app import matrix_login
        assert matrix_login.main([]) == 0
        creds = env / "instance" / "matrix" / "credentials.env"
        body = creds.read_text()
        assert "KOAN_MATRIX_PICKLE_KEY=" + ("deadbeef" * 8) in body

    def test_login_failure_no_file_written(self, env):
        _FakeAsyncClient.instances.clear()

        # Patch AsyncClient to raise during login.
        class _BoomClient(_FakeAsyncClient):
            def __init__(self, h, u):
                super().__init__(h, u)
                self.login_result = RuntimeError("server said no")

        sys.modules["nio"].AsyncClient = _BoomClient

        from app import matrix_login
        assert matrix_login.main([]) == 1
        creds = env / "instance" / "matrix" / "credentials.env"
        assert not creds.exists()

    def test_error_response_no_file_written(self, env):
        _FakeAsyncClient.instances.clear()

        class _ErrClient(_FakeAsyncClient):
            def __init__(self, h, u):
                super().__init__(h, u)
                self.login_result = _FakeErrorResponse("bad password")

        sys.modules["nio"].AsyncClient = _ErrClient

        from app import matrix_login
        assert matrix_login.main([]) == 1
        creds = env / "instance" / "matrix" / "credentials.env"
        assert not creds.exists()


# ---------------------------------------------------------------------------
# Behaviour details
# ---------------------------------------------------------------------------


class TestBehaviour:
    def test_close_called_login_succeeds(self, env):
        from app import matrix_login
        matrix_login.main([])
        assert len(_FakeAsyncClient.instances) == 1
        assert _FakeAsyncClient.instances[0].closed is True

    def test_device_name_includes_hostname(self, env):
        from app import matrix_login
        matrix_login.main([])
        assert len(_FakeAsyncClient.instances) == 1
        password, device_name = _FakeAsyncClient.instances[0].login_args
        assert password == "hunter2"
        assert device_name.startswith("koan-")

    def test_homeserver_trailing_slash_stripped(self, env, monkeypatch):
        monkeypatch.setenv("KOAN_MATRIX_HOMESERVER", "https://matrix.example/")
        from app import matrix_login
        assert matrix_login.main([]) == 0
        assert _FakeAsyncClient.instances[0].homeserver == "https://matrix.example"
