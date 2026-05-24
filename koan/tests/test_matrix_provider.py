"""Tests for MatrixProvider — E2EE (matrix-nio) and HTTP-fallback paths.

The E2EE path is exercised against a fake ``nio`` module installed in
``sys.modules``; the HTTP-fallback path is the original synchronous
implementation kept verbatim for unencrypted-room deployments.
"""

import asyncio
import os
import queue
import sys
import threading
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import requests


# ---------------------------------------------------------------------------
# Fake matrix-nio surface
#
# Installed before `app.messaging.matrix` is reachable so that the real
# `matrix-nio[e2e]` dep (which requires libolm) is not needed to run tests.
# `_start_e2ee_loop` does its imports lazily — `from nio import ...` — so
# fake `nio` in sys.modules is all we need.
# ---------------------------------------------------------------------------


class _FakeErrorResponse:
    def __init__(self, msg=""):
        self.message = msg

    def __repr__(self):
        return f"ErrorResponse({self.message!r})"


class _FakeLoginResponse:
    def __init__(self, device_id, access_token):
        self.device_id = device_id
        self.access_token = access_token


class _FakeDeviceStore:
    """Tiny stand-in for nio.crypto.DeviceStore — only what we exercise."""

    def __init__(self):
        self._entries = {}

    def __getitem__(self, user_id):
        return self._entries.setdefault(user_id, {})

    def items(self):
        return self._entries.items()

    def active_user_devices(self, user_id):
        for d in self._entries.get(user_id, {}).values():
            yield d


class _FakeAsyncClient:
    """Construct-tracking double for nio.AsyncClient."""

    instances = []

    def __init__(self, homeserver, user_id, device_id=None, store_path=None, config=None):
        self.homeserver = homeserver
        self.user_id = user_id
        self.device_id = device_id
        self.store_path = store_path
        self.config = config
        self.should_upload_keys = False
        self.should_query_keys = False
        self.callbacks = []
        self.restored = None
        self.loaded_store = False
        self.synced = False
        self.sync_forever_started = False
        self.sent = []
        self.typing = []
        self.closed = False
        self.share_calls = []
        self.keys_query_calls = 0
        self.device_store = _FakeDeviceStore()
        self.verified_devices = []
        self.to_device_callbacks = []
        self.key_verifications = {}
        self.to_device_sent = []
        self.sas_accepted = []
        self.sas_confirmed = []

        type(self).instances.append(self)

    def verify_device(self, olm_device):
        self.verified_devices.append(getattr(olm_device, "device_id", None))

    def add_to_device_callback(self, cb, event_filter):
        self.to_device_callbacks.append((cb, event_filter))

    async def to_device(self, message, tx_id=None):
        self.to_device_sent.append(message)
        return SimpleNamespace()

    async def accept_key_verification(self, tx_id, tx=None):
        self.sas_accepted.append(tx_id)
        # Seed a Sas object so subsequent share_key / get_emoji work.
        self.key_verifications.setdefault(tx_id, _FakeSas())
        return SimpleNamespace()

    async def confirm_short_auth_string(self, tx_id, tx=None):
        self.sas_confirmed.append(tx_id)
        return SimpleNamespace()

    # sync API
    def restore_login(self, user_id, device_id, access_token):
        self.restored = (user_id, device_id, access_token)

    def load_store(self):
        self.loaded_store = True

    def add_event_callback(self, cb, event_filter):
        self.callbacks.append((cb, event_filter))

    # async API
    async def keys_upload(self):
        return None

    async def sync(self, timeout=0, full_state=False):
        self.synced = True
        return None

    async def sync_forever(self, timeout=0):
        self.sync_forever_started = True
        # Park forever (matches the real call).
        await asyncio.sleep(3600)

    async def request_room_key(self, event, tx_id=None):
        self.requested_keys = getattr(self, "requested_keys", [])
        sid = getattr(event, "session_id", None)
        self.requested_keys.append(sid)
        return SimpleNamespace()

    async def share_group_session(self, room_id, ignore_unverified_devices=False):
        self.share_calls.append((room_id, ignore_unverified_devices))
        return SimpleNamespace()

    async def keys_query(self):
        self.keys_query_calls += 1
        return SimpleNamespace()

    async def room_send(self, room_id, message_type, content, ignore_unverified_devices=False):
        self.sent.append({
            "room_id": room_id,
            "message_type": message_type,
            "content": content,
            "ignore_unverified_devices": ignore_unverified_devices,
        })
        return SimpleNamespace(event_id="$evt")

    async def room_typing(self, room_id, typing_state=True, timeout=10000):
        self.typing.append((room_id, typing_state, timeout))
        return SimpleNamespace()

    async def close(self):
        self.closed = True


class _FakeAsyncClientConfig:
    def __init__(self, encryption_enabled=False, store_sync_tokens=False, pickle_key=""):
        self.encryption_enabled = encryption_enabled
        self.store_sync_tokens = store_sync_tokens
        self.pickle_key = pickle_key


class _FakeRoomMessageText:
    pass


class _FakeMegolmEvent:
    pass


class _FakeKeyVerificationEvent:
    pass


class _FakeKeyVerificationStart(_FakeKeyVerificationEvent):
    pass


class _FakeKeyVerificationKey(_FakeKeyVerificationEvent):
    pass


class _FakeKeyVerificationMac(_FakeKeyVerificationEvent):
    pass


class _FakeKeyVerificationCancel(_FakeKeyVerificationEvent):
    pass


class _FakeUnknownToDeviceEvent:
    pass


class _FakeToDeviceError(Exception):
    pass


class _FakeToDeviceMessage:
    def __init__(self, type, recipient, recipient_device, content):
        self.type = type
        self.recipient = recipient
        self.recipient_device = recipient_device
        self.content = content


class _FakeSas:
    def __init__(self):
        self.shared = False

    def share_key(self):
        self.shared = True
        return _FakeToDeviceMessage(
            "m.key.verification.key", "x", "y", {"key": "ephemeral"},
        )

    def get_emoji(self):
        return [("🌚", "moon"), ("🎂", "cake")]


class _FakeGroupEncryptionError(Exception):
    pass


class _FakeLocalProtocolError(Exception):
    pass


def _install_fake_nio():
    """Pin a fake `nio` module into sys.modules so lazy imports resolve."""
    mod = SimpleNamespace(
        AsyncClient=_FakeAsyncClient,
        AsyncClientConfig=_FakeAsyncClientConfig,
        RoomMessageText=_FakeRoomMessageText,
        MegolmEvent=_FakeMegolmEvent,
        KeyVerificationEvent=_FakeKeyVerificationEvent,
        KeyVerificationStart=_FakeKeyVerificationStart,
        KeyVerificationKey=_FakeKeyVerificationKey,
        KeyVerificationMac=_FakeKeyVerificationMac,
        KeyVerificationCancel=_FakeKeyVerificationCancel,
        UnknownToDeviceEvent=_FakeUnknownToDeviceEvent,
        ErrorResponse=_FakeErrorResponse,
        ToDeviceError=_FakeToDeviceError,
        LoginResponse=_FakeLoginResponse,
        GroupEncryptionError=_FakeGroupEncryptionError,
        LocalProtocolError=_FakeLocalProtocolError,
    )
    # nio.exceptions submodule re-exports the same names
    exc_mod = SimpleNamespace(
        GroupEncryptionError=_FakeGroupEncryptionError,
        LocalProtocolError=_FakeLocalProtocolError,
    )
    # nio.responses.KeysUploadResponse is monkey-patched by the provider
    # at bootstrap; expose a minimal stand-in so the patch lookup works.
    class _FakeKeysUploadResponse:
        @classmethod
        def from_dict(cls, parsed_dict, *args, **kwargs):
            return cls()
    resp_mod = SimpleNamespace(KeysUploadResponse=_FakeKeysUploadResponse)
    builders_mod = SimpleNamespace(ToDeviceMessage=_FakeToDeviceMessage)
    sys.modules["nio"] = mod
    sys.modules["nio.exceptions"] = exc_mod
    sys.modules["nio.responses"] = resp_mod
    sys.modules["nio.event_builders"] = builders_mod
    _FakeAsyncClient.instances.clear()
    # Reset the once-per-process patch flag so each test gets fresh state.
    try:
        from app.messaging.matrix import MatrixProvider
        MatrixProvider._nio_keys_upload_patched = False
    except Exception:
        pass


@pytest.fixture(autouse=True)
def fake_nio():
    _install_fake_nio()
    yield
    sys.modules.pop("nio", None)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def http_provider():
    """e2ee=False — exercises the original synchronous HTTP transport."""
    from app.messaging.matrix import MatrixProvider
    p = MatrixProvider()
    p._homeserver = "https://matrix.example"
    p._access_token = "syt_token"
    p._user_id = "@koan:matrix.example"
    p._room_id = "!room:matrix.example"
    p._e2ee = False
    return p


@pytest.fixture
def loop_in_thread():
    loop = asyncio.new_event_loop()
    thread = threading.Thread(target=loop.run_forever, daemon=True)
    thread.start()
    yield loop
    loop.call_soon_threadsafe(loop.stop)
    thread.join(timeout=2)


@pytest.fixture
def e2ee_provider(loop_in_thread):
    """Provider with E2EE on, working loop, and a fake AsyncClient attached."""
    from app.messaging.matrix import MatrixProvider
    p = MatrixProvider()
    p._homeserver = "https://matrix.example"
    p._access_token = "syt_token"
    p._user_id = "@koan:matrix.example"
    p._room_id = "!room:matrix.example"
    p._device_id = "DEVICE"
    p._e2ee = True
    p._loop = loop_in_thread
    p._client = _FakeAsyncClient(
        p._homeserver, p._user_id, device_id=p._device_id,
    )
    return p


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def _set_env(monkeypatch, **overrides):
    base = {
        "KOAN_MATRIX_HOMESERVER": "https://matrix.example",
        "KOAN_MATRIX_ACCESS_TOKEN": "syt_token",
        "KOAN_MATRIX_USER_ID": "@koan:matrix.example",
        "KOAN_MATRIX_ROOM_ID": "!room:matrix.example",
        "KOAN_MATRIX_DEVICE_ID": "DEVICE",
        "KOAN_MATRIX_E2EE": "0",  # default tests stay on HTTP path
    }
    base.update(overrides)
    for k, v in base.items():
        if v is None:
            monkeypatch.delenv(k, raising=False)
        else:
            monkeypatch.setenv(k, v)


class TestConfigure:
    @patch("app.utils.load_dotenv")
    def test_valid_credentials_http(self, mock_dotenv, monkeypatch):
        _set_env(monkeypatch)
        from app.messaging.matrix import MatrixProvider
        p = MatrixProvider()
        assert p.configure() is True
        assert p._e2ee is False
        assert p._homeserver == "https://matrix.example"

    @patch("app.utils.load_dotenv")
    def test_trailing_slash_stripped(self, mock_dotenv, monkeypatch):
        _set_env(monkeypatch, KOAN_MATRIX_HOMESERVER="https://matrix.example/")
        from app.messaging.matrix import MatrixProvider
        p = MatrixProvider()
        assert p.configure() is True
        assert p._homeserver == "https://matrix.example"

    @pytest.mark.parametrize("var", [
        "KOAN_MATRIX_HOMESERVER",
        "KOAN_MATRIX_ACCESS_TOKEN",
        "KOAN_MATRIX_USER_ID",
        "KOAN_MATRIX_ROOM_ID",
    ])
    @patch("app.utils.load_dotenv")
    def test_missing_var_fails(self, mock_dotenv, monkeypatch, var):
        _set_env(monkeypatch)
        monkeypatch.delenv(var, raising=False)
        from app.messaging.matrix import MatrixProvider
        p = MatrixProvider()
        assert p.configure() is False

    @patch("app.utils.load_dotenv")
    def test_invalid_homeserver_scheme(self, mock_dotenv, monkeypatch):
        _set_env(monkeypatch, KOAN_MATRIX_HOMESERVER="matrix.example")
        from app.messaging.matrix import MatrixProvider
        p = MatrixProvider()
        assert p.configure() is False

    @patch("app.utils.load_dotenv")
    def test_e2ee_requires_device_id(self, mock_dotenv, monkeypatch):
        _set_env(monkeypatch, KOAN_MATRIX_E2EE="1", KOAN_MATRIX_DEVICE_ID=None)
        from app.messaging.matrix import MatrixProvider
        p = MatrixProvider()
        assert p.configure() is False

    @patch("app.utils.load_dotenv")
    def test_e2ee_creates_store(self, mock_dotenv, monkeypatch, tmp_path):
        monkeypatch.setenv("KOAN_ROOT", str(tmp_path))
        _set_env(monkeypatch, KOAN_MATRIX_E2EE="1")
        from app.messaging.matrix import MatrixProvider
        p = MatrixProvider()
        assert p.configure() is True
        store = tmp_path / "instance" / "matrix-store"
        assert store.is_dir()
        # Drain the worker loop before the test exits.
        p._loop.call_soon_threadsafe(p._loop.stop)

    @patch("app.utils.load_dotenv")
    def test_e2ee_restore_login_called(self, mock_dotenv, monkeypatch, tmp_path):
        monkeypatch.setenv("KOAN_ROOT", str(tmp_path))
        _set_env(monkeypatch, KOAN_MATRIX_E2EE="1")
        from app.messaging.matrix import MatrixProvider
        p = MatrixProvider()
        assert p.configure() is True
        assert len(_FakeAsyncClient.instances) == 1
        client = _FakeAsyncClient.instances[0]
        assert client.restored == ("@koan:matrix.example", "DEVICE", "syt_token")
        assert client.loaded_store is True
        assert client.synced is True
        # Two callbacks: RoomMessageText (decrypted msgs) and MegolmEvent
        # (undecryptable wrappers → triggers key request).
        assert len(client.callbacks) == 2
        kinds = {kind for _, kind in client.callbacks}
        assert kinds == {_FakeRoomMessageText, _FakeMegolmEvent}
        p._loop.call_soon_threadsafe(p._loop.stop)

    @patch("app.utils.load_dotenv")
    def test_e2ee_auto_verifies_own_devices(self, mock_dotenv, monkeypatch, tmp_path):
        """Own devices must be verified so ignore_unverified_devices=True
        on send doesn't silently skip the human's reading session."""
        monkeypatch.setenv("KOAN_ROOT", str(tmp_path))
        _set_env(monkeypatch, KOAN_MATRIX_E2EE="1")

        # Pre-stage a device_store entry that `_FakeAsyncClient.__init__`
        # exposes after construction, then point _start_e2ee_loop at it.
        _FakeAsyncClient.instances.clear()
        orig_init = _FakeAsyncClient.__init__

        def _seeded_init(self, *a, **kw):
            orig_init(self, *a, **kw)
            self.device_store = _FakeDeviceStore()
            self.device_store["@koan:matrix.example"]["OWN1"] = SimpleNamespace(device_id="OWN1")
            self.device_store["@koan:matrix.example"]["OWN2"] = SimpleNamespace(device_id="OWN2")
        monkeypatch.setattr(_FakeAsyncClient, "__init__", _seeded_init)

        from app.messaging.matrix import MatrixProvider
        p = MatrixProvider()
        assert p.configure() is True
        client = _FakeAsyncClient.instances[0]
        assert sorted(client.verified_devices) == ["OWN1", "OWN2"]
        p._loop.call_soon_threadsafe(p._loop.stop)

    @patch("app.utils.load_dotenv")
    def test_e2ee_trust_own_devices_disabled(self, mock_dotenv, monkeypatch, tmp_path):
        monkeypatch.setenv("KOAN_ROOT", str(tmp_path))
        _set_env(monkeypatch, KOAN_MATRIX_E2EE="1")
        monkeypatch.setenv("KOAN_MATRIX_TRUST_OWN_DEVICES", "0")

        _FakeAsyncClient.instances.clear()
        orig_init = _FakeAsyncClient.__init__

        def _seeded_init(self, *a, **kw):
            orig_init(self, *a, **kw)
            self.device_store = _FakeDeviceStore()
            self.device_store["@koan:matrix.example"]["OWN1"] = SimpleNamespace(device_id="OWN1")
        monkeypatch.setattr(_FakeAsyncClient, "__init__", _seeded_init)

        from app.messaging.matrix import MatrixProvider
        p = MatrixProvider()
        assert p.configure() is True
        client = _FakeAsyncClient.instances[0]
        assert client.verified_devices == []
        p._loop.call_soon_threadsafe(p._loop.stop)


# ---------------------------------------------------------------------------
# Getters
# ---------------------------------------------------------------------------


class TestGetters:
    def test_provider_name(self, http_provider):
        assert http_provider.get_provider_name() == "matrix"

    def test_channel_id(self, http_provider):
        assert http_provider.get_channel_id() == "!room:matrix.example"


# ---------------------------------------------------------------------------
# E2EE: send_message
# ---------------------------------------------------------------------------


class TestE2EESendMessage:
    def test_short_message(self, e2ee_provider):
        assert e2ee_provider.send_message("hello") is True
        assert len(e2ee_provider._client.sent) == 1
        sent = e2ee_provider._client.sent[0]
        assert sent["content"] == {"msgtype": "m.text", "body": "hello"}
        assert sent["ignore_unverified_devices"] is True
        assert sent["room_id"] == "!room:matrix.example"
        assert sent["message_type"] == "m.room.message"

    def test_long_message_chunked(self, e2ee_provider):
        assert e2ee_provider.send_message("x" * 8500) is True
        assert len(e2ee_provider._client.sent) == 3  # 4000 + 4000 + 500

    def test_error_response_returns_false(self, e2ee_provider):
        async def _err(*a, **k):
            return _FakeErrorResponse("nope")
        e2ee_provider._client.room_send = _err
        assert e2ee_provider.send_message("hi") is False

    def test_exception_returns_false(self, e2ee_provider):
        async def _boom(*a, **k):
            raise RuntimeError("transport down")
        e2ee_provider._client.room_send = _boom
        assert e2ee_provider.send_message("hi") is False

    def test_empty_message_noop(self, e2ee_provider):
        assert e2ee_provider.send_message("") is True
        assert e2ee_provider._client.sent == []


# ---------------------------------------------------------------------------
# E2EE: poll_updates / callback round-trip
# ---------------------------------------------------------------------------


class TestE2EEPolling:
    def test_callback_to_queue_to_poll(self, e2ee_provider):
        room = SimpleNamespace(room_id="!room:matrix.example")
        event = SimpleNamespace(
            sender="@alice:matrix.example",
            body="hello bot",
            server_timestamp=123,
            event_id="$evt1",
        )
        asyncio.run(e2ee_provider._on_room_message(room, event))

        updates = e2ee_provider.poll_updates()
        assert len(updates) == 1
        assert updates[0].message.text == "hello bot"
        assert updates[0].message.role == "user"

    def test_filters_own_messages(self, e2ee_provider):
        room = SimpleNamespace(room_id="!room:matrix.example")
        own = SimpleNamespace(sender="@koan:matrix.example", body="self", server_timestamp=1, event_id="$e1")
        other = SimpleNamespace(sender="@alice:matrix.example", body="hi", server_timestamp=2, event_id="$e2")
        asyncio.run(e2ee_provider._on_room_message(room, own))
        asyncio.run(e2ee_provider._on_room_message(room, other))
        updates = e2ee_provider.poll_updates()
        assert len(updates) == 1
        assert updates[0].message.text == "hi"

    def test_ignores_events_from_other_rooms(self, e2ee_provider):
        room = SimpleNamespace(room_id="!other:matrix.example")
        event = SimpleNamespace(sender="@alice:matrix.example", body="wrong", server_timestamp=1, event_id="$e1")
        asyncio.run(e2ee_provider._on_room_message(room, event))
        assert e2ee_provider.poll_updates() == []

    def test_no_token_returns_empty(self):
        from app.messaging.matrix import MatrixProvider
        p = MatrixProvider()
        assert p.poll_updates() == []


class TestE2EEUndecryptable:
    def test_request_room_key_called_on_undecryptable(self, e2ee_provider):
        room = SimpleNamespace(room_id="!room:matrix.example")
        event = SimpleNamespace(session_id="STUCK_SESSION_ID")
        asyncio.run(e2ee_provider._on_undecryptable(room, event))
        assert e2ee_provider._client.requested_keys == ["STUCK_SESSION_ID"]

    def test_other_room_ignored(self, e2ee_provider):
        room = SimpleNamespace(room_id="!other:matrix.example")
        event = SimpleNamespace(session_id="X")
        asyncio.run(e2ee_provider._on_undecryptable(room, event))
        assert getattr(e2ee_provider._client, "requested_keys", []) == []

    def test_duplicate_request_swallowed(self, e2ee_provider):
        async def _boom(event, tx_id=None):
            raise _FakeLocalProtocolError("already requested")
        e2ee_provider._client.request_room_key = _boom
        room = SimpleNamespace(room_id="!room:matrix.example")
        event = SimpleNamespace(session_id="SS")
        # Must not raise — LocalProtocolError is nio's dedup signal.
        asyncio.run(e2ee_provider._on_undecryptable(room, event))

    def test_own_user_messages_skip_request(self, e2ee_provider):
        """Self-sent undecryptable events shouldn't trigger a key request —
        that would broadcast back to us and noise up the logs."""
        room = SimpleNamespace(room_id="!room:matrix.example")
        event = SimpleNamespace(
            sender="@koan:matrix.example",  # our own user
            session_id="OWN",
        )
        asyncio.run(e2ee_provider._on_undecryptable(room, event))
        assert getattr(e2ee_provider._client, "requested_keys", []) == []


class TestSasAutoVerify:
    def test_start_triggers_accept_and_share(self, e2ee_provider):
        evt = _FakeKeyVerificationStart()
        evt.sender = "@koan:matrix.example"
        evt.transaction_id = "TX1"
        evt.short_authentication_string = ["emoji", "decimal"]
        asyncio.run(e2ee_provider._on_verification_event(evt))
        assert e2ee_provider._client.sas_accepted == ["TX1"]
        # share_key message must have been sent via to_device.
        sent_types = [m.type for m in e2ee_provider._client.to_device_sent]
        assert "m.key.verification.key" in sent_types

    def test_start_from_other_user_ignored(self, e2ee_provider):
        evt = _FakeKeyVerificationStart()
        evt.sender = "@stranger:matrix.example"
        evt.transaction_id = "TX2"
        evt.short_authentication_string = ["emoji"]
        asyncio.run(e2ee_provider._on_verification_event(evt))
        assert e2ee_provider._client.sas_accepted == []
        assert e2ee_provider._client.to_device_sent == []

    def test_start_without_emoji_method_ignored(self, e2ee_provider):
        evt = _FakeKeyVerificationStart()
        evt.sender = "@koan:matrix.example"
        evt.transaction_id = "TX3"
        evt.short_authentication_string = ["decimal"]
        asyncio.run(e2ee_provider._on_verification_event(evt))
        assert e2ee_provider._client.sas_accepted == []

    def test_key_triggers_auto_confirm(self, e2ee_provider):
        e2ee_provider._client.key_verifications["TX4"] = _FakeSas()
        evt = _FakeKeyVerificationKey()
        evt.sender = "@koan:matrix.example"
        evt.transaction_id = "TX4"
        asyncio.run(e2ee_provider._on_verification_event(evt))
        assert e2ee_provider._client.sas_confirmed == ["TX4"]

    def test_unknown_request_replies_ready(self, e2ee_provider):
        evt = _FakeUnknownToDeviceEvent()
        evt.sender = "@koan:matrix.example"
        evt.source = {
            "type": "m.key.verification.request",
            "content": {
                "transaction_id": "TXREQ",
                "from_device": "OTHER_DEV",
                "methods": ["m.sas.v1"],
            },
        }
        asyncio.run(e2ee_provider._on_unknown_to_device(evt))
        # Exactly one to-device message sent: the ready.
        sent = e2ee_provider._client.to_device_sent
        assert len(sent) == 1
        ready = sent[0]
        assert ready.type == "m.key.verification.ready"
        assert ready.recipient_device == "OTHER_DEV"
        assert ready.content["transaction_id"] == "TXREQ"
        assert ready.content["from_device"] == "DEVICE"
        assert "m.sas.v1" in ready.content["methods"]

    def test_unknown_request_from_other_user_ignored(self, e2ee_provider):
        evt = _FakeUnknownToDeviceEvent()
        evt.sender = "@stranger:matrix.example"
        evt.source = {
            "type": "m.key.verification.request",
            "content": {"transaction_id": "X", "from_device": "Y"},
        }
        asyncio.run(e2ee_provider._on_unknown_to_device(evt))
        assert e2ee_provider._client.to_device_sent == []

    def test_unknown_done_echoed(self, e2ee_provider):
        evt = _FakeUnknownToDeviceEvent()
        evt.sender = "@koan:matrix.example"
        evt.source = {
            "type": "m.key.verification.done",
            "content": {"transaction_id": "TXDONE", "from_device": "OTHER_DEV"},
        }
        asyncio.run(e2ee_provider._on_unknown_to_device(evt))
        sent = e2ee_provider._client.to_device_sent
        assert len(sent) == 1
        assert sent[0].type == "m.key.verification.done"
        assert sent[0].content["transaction_id"] == "TXDONE"


class TestSasCallbackRegistration:
    @patch("app.utils.load_dotenv")
    def test_callbacks_registered(self, mock_dotenv, monkeypatch, tmp_path):
        """Bootstrap must wire SAS callbacks for both the typed and unknown
        to-device paths."""
        monkeypatch.setenv("KOAN_ROOT", str(tmp_path))
        _set_env(monkeypatch, KOAN_MATRIX_E2EE="1")
        from app.messaging.matrix import MatrixProvider
        p = MatrixProvider()
        assert p.configure() is True
        client = _FakeAsyncClient.instances[-1]
        kinds = {kind for _, kind in client.to_device_callbacks}
        assert kinds == {_FakeKeyVerificationEvent, _FakeUnknownToDeviceEvent}
        p._loop.call_soon_threadsafe(p._loop.stop)


# ---------------------------------------------------------------------------
# E2EE: typing
# ---------------------------------------------------------------------------


class TestE2EETyping:
    def test_typing(self, e2ee_provider):
        assert e2ee_provider.send_typing() is True
        assert e2ee_provider._client.typing == [("!room:matrix.example", True, 10000)]

    def test_typing_not_configured(self):
        from app.messaging.matrix import MatrixProvider
        p = MatrixProvider()
        assert p.send_typing() is False


# ---------------------------------------------------------------------------
# HTTP fallback — original behaviour, exercised with e2ee=False
# ---------------------------------------------------------------------------


class TestHttpFallbackSend:
    @patch("app.messaging.matrix.requests.put")
    def test_short_message(self, mock_put, http_provider):
        mock_put.return_value = MagicMock(status_code=200)
        assert http_provider.send_message("hello") is True
        assert mock_put.call_count == 1
        call = mock_put.call_args
        assert call[1]["json"]["body"] == "hello"
        assert call[1]["json"]["msgtype"] == "m.text"
        assert call[1]["headers"]["Authorization"] == "Bearer syt_token"

    @patch("app.messaging.matrix.requests.put")
    def test_long_message_chunked(self, mock_put, http_provider):
        mock_put.return_value = MagicMock(status_code=200)
        assert http_provider.send_message("x" * 8500) is True
        assert mock_put.call_count == 3

    @patch("app.messaging.matrix.requests.put")
    def test_url_url_encoded(self, mock_put, http_provider):
        mock_put.return_value = MagicMock(status_code=200)
        http_provider.send_message("hi")
        url = mock_put.call_args[0][0]
        assert "%21room%3Amatrix.example" in url
        assert "/send/m.room.message/" in url

    @patch("app.messaging.matrix.requests.put")
    def test_4xx_returns_false(self, mock_put, http_provider):
        mock_put.return_value = MagicMock(status_code=403, text="forbidden")
        assert http_provider.send_message("hi") is False

    @patch("app.messaging.matrix.time.sleep")
    @patch("app.retry.time.sleep")
    @patch("app.messaging.matrix.requests.put")
    def test_5xx_retries_then_fails(self, mock_put, _r_sleep, _m_sleep, http_provider):
        mock_put.return_value = MagicMock(status_code=502, text="bad gateway")
        assert http_provider.send_message("hi") is False
        assert mock_put.call_count == 3

    def test_not_configured(self):
        from app.messaging.matrix import MatrixProvider
        p = MatrixProvider()
        p._e2ee = False
        assert p.send_message("test") is False

    def test_empty_message_noop(self, http_provider):
        with patch("app.messaging.matrix.requests.put") as mock_put:
            assert http_provider.send_message("") is True
            assert mock_put.call_count == 0


class TestHttpFallbackPolling:
    @patch("app.messaging.matrix.requests.get")
    def test_initial_sync_discards(self, mock_get, http_provider):
        mock_get.return_value = MagicMock(json=lambda: {
            "next_batch": "s100",
            "rooms": {"join": {"!room:matrix.example": {
                "timeline": {"events": [
                    {"type": "m.room.message", "sender": "@a:m.e",
                     "content": {"msgtype": "m.text", "body": "old"}},
                ]}
            }}}
        })
        assert http_provider.poll_updates() == []
        assert http_provider._sync_token == "s100"

    @patch("app.messaging.matrix.requests.get")
    def test_subsequent_sync(self, mock_get, http_provider):
        http_provider._sync_token = "s100"
        http_provider._sync_initialized = True
        mock_get.return_value = MagicMock(json=lambda: {
            "next_batch": "s101",
            "rooms": {"join": {"!room:matrix.example": {
                "timeline": {"events": [
                    {"type": "m.room.message", "sender": "@alice:m.e",
                     "content": {"msgtype": "m.text", "body": "hi"},
                     "origin_server_ts": 123},
                ]}
            }}}
        })
        updates = http_provider.poll_updates()
        assert len(updates) == 1
        assert updates[0].message.text == "hi"
        assert http_provider._sync_token == "s101"

    @patch("app.messaging.matrix.requests.get")
    def test_passes_since_after_init(self, mock_get, http_provider):
        http_provider._sync_token = "s100"
        http_provider._sync_initialized = True
        mock_get.return_value = MagicMock(json=lambda: {"next_batch": "s101"})
        http_provider.poll_updates()
        assert mock_get.call_args[1]["params"]["since"] == "s100"

    @patch("app.messaging.matrix.requests.get")
    def test_initial_zero_timeout(self, mock_get, http_provider):
        mock_get.return_value = MagicMock(json=lambda: {"next_batch": "s100"})
        http_provider.poll_updates()
        assert mock_get.call_args[1]["params"]["timeout"] == 0
        assert "since" not in mock_get.call_args[1]["params"]

    @patch("app.messaging.matrix.requests.get")
    def test_network_error_returns_empty(self, mock_get, http_provider):
        mock_get.side_effect = requests.RequestException("boom")
        assert http_provider.poll_updates() == []


class TestHttpFallbackTyping:
    @patch("app.messaging.matrix.requests.put")
    def test_send_typing(self, mock_put, http_provider):
        mock_put.return_value = MagicMock(status_code=200)
        assert http_provider.send_typing() is True
        assert "/typing/" in mock_put.call_args[0][0]
        assert mock_put.call_args[1]["json"]["typing"] is True

    @patch("app.messaging.matrix.requests.put")
    def test_send_typing_network_error(self, mock_put, http_provider):
        mock_put.side_effect = requests.RequestException("boom")
        assert http_provider.send_typing() is False


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


class TestRegistry:
    def test_matrix_registered(self):
        """Matrix should auto-register when the messaging package loads providers.

        Runs in a fresh subprocess: ``_providers`` is process-wide module
        state that other tests (notably ``clean_registry`` in
        ``test_messaging_provider.py``) can clear *after* the provider
        modules are already cached in ``sys.modules``.  Once that happens
        no in-process call to ``_ensure_providers_loaded`` can repopulate
        the registry — the decorators won't re-run for cached modules.
        A clean subprocess sidesteps the whole ordering problem.
        """
        import subprocess
        from pathlib import Path

        koan_pkg = Path(__file__).resolve().parents[1]  # …/koan
        script = (
            "from app.messaging import _ensure_providers_loaded, _providers\n"
            "_ensure_providers_loaded()\n"
            "assert 'matrix' in _providers, sorted(_providers)\n"
        )
        env = {
            **os.environ,
            "PYTHONPATH": str(koan_pkg),
            "KOAN_ROOT": os.environ.get("KOAN_ROOT", "/tmp/test-koan"),
        }
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            timeout=15,
            env=env,
        )
        assert result.returncode == 0, (
            f"subprocess failed:\nstdout={result.stdout}\nstderr={result.stderr}"
        )
