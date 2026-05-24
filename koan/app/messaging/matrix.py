"""Matrix messaging provider.

Two transports live behind a single class:

* **E2EE (default)** — `matrix-nio` `AsyncClient` driven from a dedicated
  worker thread that owns an asyncio event loop. Olm/Megolm state is
  persisted in `instance/matrix-store/`. Requires `libolm` at runtime and
  a brand-new `device_id` (reusing one silently breaks key handshake).
* **HTTP fallback** (`e2ee=false`) — the original synchronous
  Client-Server HTTP implementation, kept verbatim for hosts without
  libolm or for unencrypted rooms.

Configuration is read from instance/config.yaml under ``messaging.matrix``
with `KOAN_MATRIX_*` env vars overriding.

config.yaml keys (under ``messaging.matrix``):
    homeserver, access_token, user_id, room_id,
    device_id, pickle_key, e2ee

Environment variables (override config.yaml when set):
    KOAN_MATRIX_HOMESERVER   — Homeserver URL (e.g. https://matrix.org)
    KOAN_MATRIX_ACCESS_TOKEN — Access token for the bot account
    KOAN_MATRIX_USER_ID      — Bot's Matrix user ID (e.g. @koan:matrix.org)
    KOAN_MATRIX_ROOM_ID      — Room to operate in (e.g. !abc123:matrix.org)
    KOAN_MATRIX_DEVICE_ID    — Brand-new device id (required when e2ee=true)
    KOAN_MATRIX_PICKLE_KEY   — Optional store-encryption key
    KOAN_MATRIX_E2EE         — "0"/"false" to disable Megolm; default on
"""

import asyncio
import itertools
import os
import queue
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import List, Optional
from urllib.parse import quote

import requests

from app.messaging.base import DEFAULT_MAX_MESSAGE_SIZE, Message, MessagingProvider, Update
from app.messaging import register_provider


MAX_MESSAGE_SIZE = DEFAULT_MAX_MESSAGE_SIZE
SYNC_TIMEOUT_MS = 30000  # 30s long-poll
SYNC_HTTP_TIMEOUT = 35   # leave 5s buffer over SYNC_TIMEOUT_MS

# How long send_message/send_typing will block waiting for the worker loop.
ASYNC_CALL_TIMEOUT_S = 60
# Loop bootstrap (initial sync, key upload) gets a longer budget — keys_upload
# can be slow on first device registration.
ASYNC_INIT_TIMEOUT_S = 60


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() not in ("0", "false", "no", "off", "")


@register_provider("matrix")
class MatrixProvider(MessagingProvider):
    """Matrix provider with optional Megolm/Olm end-to-end encryption.

    With ``e2ee=true`` (default) a background thread owns an asyncio loop
    and a `matrix-nio` AsyncClient.  Incoming decrypted text events are
    pushed onto a thread-safe queue that `poll_updates()` drains.  Outgoing
    calls (`send_message`, `send_typing`) marshal coroutines onto that loop
    via ``asyncio.run_coroutine_threadsafe``.

    With ``e2ee=false`` the provider behaves like the original HTTP
    implementation — useful for hosts without libolm or unencrypted rooms.
    """

    def __init__(self):
        self._homeserver: str = ""
        self._access_token: str = ""
        self._user_id: str = ""
        self._room_id: str = ""
        self._device_id: str = ""
        self._pickle_key: str = ""
        self._e2ee: bool = True

        # HTTP-fallback state
        self._sync_token: Optional[str] = None
        self._sync_initialized: bool = False
        self._update_counter = itertools.count(1)
        self._send_lock = threading.Lock()

        # E2EE worker-loop state
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._loop_thread: Optional[threading.Thread] = None
        self._client = None  # nio.AsyncClient when e2ee enabled
        self._sync_task = None
        self._message_queue: "queue.Queue[Update]" = queue.Queue()

    # -- MessagingProvider interface ------------------------------------------

    def configure(self) -> bool:
        from app.utils import load_config, load_dotenv
        load_dotenv()
        # When koan is started without systemd (the pid_manager / `make
        # start` path) there's no EnvironmentFile= to pull the bootstrap
        # output in — the credentials file is just sitting on disk.  Load
        # it the same way as `.env` so the device_id/access_token end up
        # in os.environ regardless of how the process was launched.
        self._load_matrix_credentials()

        cfg: dict = {}
        messaging = load_config().get("messaging", {}) or {}
        if isinstance(messaging, dict):
            section = messaging.get("matrix", {}) or {}
            if isinstance(section, dict):
                cfg = section

        # env vars override config.yaml for backward compatibility
        self._homeserver = (
            os.environ.get("KOAN_MATRIX_HOMESERVER") or cfg.get("homeserver", "")
        ).rstrip("/")
        self._access_token = (
            os.environ.get("KOAN_MATRIX_ACCESS_TOKEN") or cfg.get("access_token", "")
        )
        self._user_id = (
            os.environ.get("KOAN_MATRIX_USER_ID") or cfg.get("user_id", "")
        )
        self._room_id = (
            os.environ.get("KOAN_MATRIX_ROOM_ID") or cfg.get("room_id", "")
        )
        self._device_id = (
            os.environ.get("KOAN_MATRIX_DEVICE_ID") or cfg.get("device_id", "")
        )
        self._pickle_key = (
            os.environ.get("KOAN_MATRIX_PICKLE_KEY") or cfg.get("pickle_key", "")
        )

        cfg_e2ee = cfg.get("e2ee", True)
        if isinstance(cfg_e2ee, str):
            cfg_e2ee = cfg_e2ee.strip().lower() not in ("0", "false", "no", "off", "")
        self._e2ee = _env_bool("KOAN_MATRIX_E2EE", bool(cfg_e2ee))

        missing = []
        if not self._homeserver:
            missing.append("homeserver")
        if not self._access_token:
            missing.append("access_token")
        if not self._user_id:
            missing.append("user_id")
        if not self._room_id:
            missing.append("room_id")
        if self._e2ee and not self._device_id:
            missing.append("device_id (required when e2ee=true)")
        if missing:
            print(
                f"[matrix] Missing required settings: {', '.join(missing)}. "
                f"Set in instance/config.yaml under messaging.matrix or via the "
                f"corresponding KOAN_MATRIX_* env vars.",
                file=sys.stderr,
            )
            return False

        if not self._homeserver.startswith(("http://", "https://")):
            print(
                "[matrix] KOAN_MATRIX_HOMESERVER must start with http:// or https://",
                file=sys.stderr,
            )
            return False

        if self._e2ee:
            return self._start_e2ee_loop()
        return True

    def get_provider_name(self) -> str:
        return "matrix"

    def get_channel_id(self) -> str:
        return self._room_id

    def send_message(self, text: str) -> bool:
        """Send a message to the configured Matrix room, chunked if needed."""
        if not self._access_token or not self._room_id:
            print("[matrix] Not configured — cannot send.", file=sys.stderr)
            return False

        if not text:
            return True

        if self._e2ee:
            return self._send_e2ee(text)
        return self._send_http(text)

    def poll_updates(self, offset: Optional[int] = None) -> List[Update]:
        """Return new messages since the last poll.

        Under E2EE the worker loop's `sync_forever` task pushes decrypted
        events into a queue; this method drains it non-blockingly. Under
        the HTTP fallback the same `/sync` long-poll happens here.
        """
        if not self._access_token:
            return []
        if self._e2ee:
            return self._drain_queue()
        return self._poll_http()

    def send_typing(self) -> bool:
        """Send a typing indicator (auto-expires after ~10s)."""
        if not self._access_token or not self._room_id or not self._user_id:
            return False
        if self._e2ee:
            return self._typing_e2ee()
        return self._typing_http()

    _nio_keys_upload_patched: bool = False

    @classmethod
    def _patch_nio_keys_upload_tolerance(cls) -> None:
        """Make nio.responses.KeysUploadResponse.from_dict tolerate a
        missing ``one_time_key_counts`` field by defaulting it to zero.

        See the call site in `_start_e2ee_loop` for the why.  Applied
        at most once per process.
        """
        if cls._nio_keys_upload_patched:
            return
        try:
            from nio.responses import KeysUploadResponse
        except ImportError:
            return
        _orig = KeysUploadResponse.from_dict.__func__

        def _tolerant_from_dict(klass, parsed_dict, *args, **kwargs):
            parsed_dict.setdefault(
                "one_time_key_counts",
                {"curve25519": 0, "signed_curve25519": 0},
            )
            return _orig(klass, parsed_dict, *args, **kwargs)

        KeysUploadResponse.from_dict = classmethod(_tolerant_from_dict)
        cls._nio_keys_upload_patched = True

    @staticmethod
    def _load_matrix_credentials() -> None:
        """Merge instance/matrix/credentials.env into os.environ.

        Mirrors ``load_dotenv``'s use of ``setdefault`` so the .env (and
        the live shell) still win on a collision — this is purely a
        fallback for the non-systemd startup path.
        """
        koan_root = os.environ.get("KOAN_ROOT")
        if not koan_root:
            return
        path = Path(koan_root) / "instance" / "matrix" / "credentials.env"
        if not path.exists():
            return
        try:
            text = path.read_text()
        except OSError:
            return
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip().strip("\"'"))

    # -- E2EE: event-loop worker thread --------------------------------------

    def _start_e2ee_loop(self) -> bool:
        """Bring up the asyncio loop + AsyncClient in a worker thread.

        Returns False on any startup failure (missing libolm, bad token,
        sync error). Errors print to stderr so the operator sees them.
        """
        try:
            from nio import (
                AsyncClient,
                AsyncClientConfig,
                KeyVerificationEvent,
                MegolmEvent,
                RoomMessageText,
                UnknownToDeviceEvent,
            )
        except ImportError as exc:
            print(
                f"[matrix] matrix-nio[e2e] not importable ({exc}). "
                "Install with `pip install matrix-nio[e2e]` (needs libolm).",
                file=sys.stderr,
            )
            return False

        # matrix-nio 0.25.x marks `one_time_key_counts` as a required
        # field on the /keys/upload response, but some homeservers (and
        # the response Synapse 1.152 returns when there's nothing new to
        # upload) omit it.  Without this patch, KeysUploadResponse.from_dict
        # returns an ErrorResponse → nio's `should_upload_keys` stays
        # True forever → the bot loops re-uploading and, more critically,
        # other clients trying to /keys/claim an OTK from the bot get
        # stale results → no Olm session can be set up to deliver Megolm
        # keys → incoming messages decrypt as "no session found".
        # Idempotent: only wraps the original once per process.
        self._patch_nio_keys_upload_tolerance()

        store_path = self._resolve_store_path()
        try:
            store_path.mkdir(parents=True, exist_ok=True)
            store_path.chmod(0o700)
        except OSError as exc:
            print(f"[matrix] Cannot create store at {store_path}: {exc}", file=sys.stderr)
            return False

        self._loop = asyncio.new_event_loop()
        self._loop_thread = threading.Thread(
            target=self._run_loop, name="matrix-nio-loop", daemon=True,
        )
        self._loop_thread.start()

        async def _bootstrap():
            cfg = AsyncClientConfig(
                encryption_enabled=True,
                store_sync_tokens=True,
                pickle_key=self._pickle_key or "",
            )
            client = AsyncClient(
                self._homeserver,
                self._user_id,
                device_id=self._device_id,
                store_path=str(store_path),
                config=cfg,
            )
            # restore_login is sync (it just stamps the client) — no await.
            client.restore_login(self._user_id, self._device_id, self._access_token)
            client.load_store()
            # Expose the client BEFORE registering callbacks or running
            # sync — both can fire callbacks (incoming to-device or
            # timeline events) that dereference self._client, and the
            # initial /sync in particular drains any pending events
            # that were queued server-side while we were down (a stale
            # m.key.verification.request from Element clicking "Verify"
            # earlier, for example).
            self._client = client
            client.add_event_callback(self._on_room_message, RoomMessageText)
            # When a message arrives that the bot can't decrypt — usually
            # because the sender's client established a Megolm session
            # before the bot's OTKs were reachable and is now reusing it
            # forever — ask the sender's other devices for the missing
            # session key via m.room_key_request.  nio's sync loop handles
            # the m.forwarded_room_key response automatically.  Without
            # this hook the user has to manually rotate session keys on
            # their end, which Element has been quietly hiding from the
            # UI in recent builds.
            client.add_event_callback(self._on_undecryptable, MegolmEvent)
            # SAS verification handlers — see _on_verification_event for
            # the rationale (Element's "Verify" button doesn't have a
            # human to compare emojis with on the bot side; we auto-
            # accept and auto-confirm for verifications initiated by our
            # own user).  UnknownToDeviceEvent is needed because nio
            # 0.25 doesn't model the modern m.key.verification.request /
            # ready handshake — we hand-roll that part.
            client.add_to_device_callback(
                self._on_verification_event, KeyVerificationEvent,
            )
            client.add_to_device_callback(
                self._on_unknown_to_device, UnknownToDeviceEvent,
            )

            if client.should_upload_keys:
                await client.keys_upload()

            # Initial sync to drain history and pick up room state — we
            # discard returned events so the bot doesn't replay backlog.
            # `full_state=True` is load-bearing on first boot: without it,
            # sync returns before the joined-rooms list materializes and
            # the very first room_send blows up with "no such room".
            await client.sync(timeout=10000, full_state=True)

            # Auto-verify every other device on the bot's own account.
            # With ignore_unverified_devices=True, nio refuses to encrypt
            # to devices in TrustState.ignored or .blacklisted — and a
            # human reading the bot's own messages from Element shows up
            # exactly there if they ever tapped "ignore" by accident
            # (or inherited the state from an older session).  Matches
            # the trust_own_devices pattern in matrix-eno-bot.  Skip
            # when KOAN_MATRIX_TRUST_OWN_DEVICES=0.
            if _env_bool("KOAN_MATRIX_TRUST_OWN_DEVICES", True):
                # nio.crypto.DeviceStore is iterable but not dict-like;
                # active_user_devices() yields the non-deleted devices.
                for olm_device in client.device_store.active_user_devices(self._user_id):
                    try:
                        client.verify_device(olm_device)
                    except Exception as exc:
                        print(
                            f"[matrix] verify_device({olm_device.device_id}) "
                            f"failed: {exc}",
                            file=sys.stderr,
                        )

            self._sync_task = self._loop.create_task(
                client.sync_forever(timeout=SYNC_TIMEOUT_MS)
            )
            return True

        try:
            fut = asyncio.run_coroutine_threadsafe(_bootstrap(), self._loop)
            return bool(fut.result(timeout=ASYNC_INIT_TIMEOUT_S))
        except Exception as exc:
            print(f"[matrix] E2EE bootstrap failed: {exc}", file=sys.stderr)
            return False

    def _run_loop(self):
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_forever()
        finally:
            self._loop.close()

    def _resolve_store_path(self) -> Path:
        koan_root = os.environ.get("KOAN_ROOT")
        base = Path(koan_root) if koan_root else Path.cwd()
        return base / "instance" / "matrix-store"

    async def _on_undecryptable(self, room, event):
        """Ask the sender's devices to forward the missing room key.

        Fires when nio surfaces a MegolmEvent it couldn't decrypt with
        any locally-known session.  Best-effort: nio refuses duplicate
        requests for the same session_id (raises LocalProtocolError),
        and we don't want to take down the sync loop on a transient
        send failure either way.
        """
        if getattr(room, "room_id", "") != self._room_id:
            return
        # Don't request keys for messages we sent ourselves.  Synapse
        # echoes our outbound back to us via /sync; nio decrypts from
        # our own inbound copy, but if a transient miss surfaces this
        # callback we'd request the key from ourselves and choke on
        # "Unknown requesting device <our device id>" because nio
        # excludes self from device_store.
        if getattr(event, "sender", "") == self._user_id:
            return
        try:
            from nio.exceptions import LocalProtocolError
        except ImportError:
            from nio import LocalProtocolError
        try:
            resp = await self._client.request_room_key(event)
        except LocalProtocolError:
            return  # already-requested — nio dedup'd
        except Exception as exc:
            print(
                f"[matrix] request_room_key failed for session "
                f"{getattr(event, 'session_id', '?')}: {exc}",
                file=sys.stderr,
            )
            return
        from nio import ErrorResponse
        if isinstance(resp, ErrorResponse):
            print(
                f"[matrix] request_room_key error for session "
                f"{getattr(event, 'session_id', '?')}: {resp}",
                file=sys.stderr,
            )

    async def _on_verification_event(self, event):
        """Drive emoji-SAS verification to completion without a human.

        Modern Element (cross-signing + Rust crypto SDK) won't share
        Megolm keys with devices it considers unverified, and the only
        UI it exposes for verifying a bot device is interactive emoji
        SAS.  A headless bot has no eyes to compare emojis, so we
        auto-accept and auto-confirm verifications initiated from our
        OWN user (i.e. the operator clicking "Verify" in their
        Element-as-@trogbot session).  Cross-user verification
        requests are ignored; nobody else can mark the bot trusted.

        Threat model: anyone with the bot's access token already
        controls @trogbot fully — so auto-trusting verification from
        @trogbot specifically isn't a meaningful new exposure.
        """
        if getattr(event, "sender", "") != self._user_id:
            return
        try:
            from nio import (
                KeyVerificationCancel,
                KeyVerificationKey,
                KeyVerificationMac,
                KeyVerificationStart,
                ToDeviceError,
            )
        except ImportError:
            return

        tx_id = getattr(event, "transaction_id", None)
        if not tx_id:
            return

        async def _log_err(label, resp):
            if isinstance(resp, ToDeviceError):
                print(f"[matrix] sas {label} failed: {resp}", file=sys.stderr)

        if isinstance(event, KeyVerificationStart):
            if "emoji" not in getattr(event, "short_authentication_string", []):
                print(
                    f"[matrix] sas {tx_id}: peer didn't offer emoji method; "
                    "ignoring (we only auto-handle emoji SAS)",
                    file=sys.stderr,
                )
                return
            await _log_err("accept", await self._client.accept_key_verification(tx_id))
            sas = self._client.key_verifications.get(tx_id)
            if sas is not None:
                await _log_err("share_key", await self._client.to_device(sas.share_key()))

        elif isinstance(event, KeyVerificationKey):
            sas = self._client.key_verifications.get(tx_id)
            if sas is None:
                return
            try:
                emojis = sas.get_emoji()
            except Exception:
                emojis = "?"
            print(
                f"[matrix] sas {tx_id}: auto-confirming emojis {emojis} "
                f"(verification initiated by our own user)",
                file=sys.stderr,
            )
            await _log_err(
                "confirm", await self._client.confirm_short_auth_string(tx_id),
            )

        elif isinstance(event, KeyVerificationMac):
            # nio's olm machine validates MACs and marks the device
            # verified on its own; nothing for us to send here.
            print(f"[matrix] sas {tx_id}: MAC received", file=sys.stderr)

        elif isinstance(event, KeyVerificationCancel):
            reason = getattr(event, "reason", "")
            print(f"[matrix] sas {tx_id} cancelled by peer: {reason}", file=sys.stderr)

    async def _on_unknown_to_device(self, event):
        """Hand-roll the modern m.key.verification.{request,ready,done} dance.

        nio 0.25 only models the legacy direct-Start flow.  Element
        defaults to the request/ready/start flow with cross-signing;
        without us answering the request with a ready, Element just
        sits on "Start verification on the other device" forever.
        We catch the raw events here and reply with the minimum needed
        to nudge Element into sending the Start that nio understands.
        """
        if getattr(event, "sender", "") != self._user_id:
            return
        event_dict = getattr(event, "source", None) or {}
        kind = event_dict.get("type") or getattr(event, "type", "")
        content = event_dict.get("content", {}) or {}
        tx_id = content.get("transaction_id")
        from_device = content.get("from_device")
        if not tx_id or not from_device:
            return

        try:
            from nio import ToDeviceError
            from nio.event_builders import ToDeviceMessage
        except ImportError:
            try:
                from nio.event_builders.direct_messages import ToDeviceMessage
                from nio import ToDeviceError
            except ImportError:
                return

        if kind == "m.key.verification.request":
            ready = ToDeviceMessage(
                type="m.key.verification.ready",
                recipient=self._user_id,
                recipient_device=from_device,
                content={
                    "transaction_id": tx_id,
                    "from_device": self._device_id,
                    "methods": ["m.sas.v1"],
                },
            )
            resp = await self._client.to_device(ready)
            if isinstance(resp, ToDeviceError):
                print(f"[matrix] sas ready send failed: {resp}", file=sys.stderr)
            else:
                print(f"[matrix] sas {tx_id}: replied 'ready' to {from_device}",
                      file=sys.stderr)

        elif kind == "m.key.verification.done":
            # Element expects us to echo a done so both sides can tear
            # down the verification transaction cleanly.
            done = ToDeviceMessage(
                type="m.key.verification.done",
                recipient=self._user_id,
                recipient_device=from_device,
                content={"transaction_id": tx_id},
            )
            resp = await self._client.to_device(done)
            if isinstance(resp, ToDeviceError):
                print(f"[matrix] sas done echo failed: {resp}", file=sys.stderr)

    async def _on_room_message(self, room, event):
        """Decrypted-message callback. Filters then enqueues."""
        if getattr(room, "room_id", "") != self._room_id:
            return
        sender = getattr(event, "sender", "")
        if not sender or sender == self._user_id:
            return
        body = getattr(event, "body", "")
        if not body:
            return
        # nio strips m.room.encrypted → RoomMessageText; msgtype is always text.
        update_id = next(self._update_counter)
        ts = getattr(event, "server_timestamp", "")
        # awake.py's main loop is Telegram-Bot-API-shaped (update["update_id"],
        # update["message"]["chat"]["id"], …).  We mint a wrapper here that
        # presents matrix events in that shape so the polling loop doesn't
        # care which provider it's draining — the matrix-specific bits stay
        # under "_matrix" for anything that wants them.
        raw = {
            "update_id": update_id,
            "message": {
                "message_id": getattr(event, "event_id", ""),
                "text": body,
                "date": ts,
                "chat": {"id": self._room_id, "type": "supergroup"},
                "from": {"id": sender, "username": sender},
            },
            "_matrix": {
                "sender": sender,
                "event_id": getattr(event, "event_id", ""),
                "room_id": self._room_id,
                "origin_server_ts": ts,
            },
        }
        self._message_queue.put(Update(
            update_id=update_id,
            message=Message(
                text=body,
                role="user",
                timestamp=str(ts),
                raw_data=raw,
            ),
            raw_data=raw,
        ))

    def _drain_queue(self) -> List[Update]:
        out: List[Update] = []
        while True:
            try:
                out.append(self._message_queue.get_nowait())
            except queue.Empty:
                break
        return out

    def _send_e2ee(self, text: str) -> bool:
        if not self._client or not self._loop:
            print("[matrix] E2EE loop not running.", file=sys.stderr)
            return False

        async def _send_one(chunk: str) -> bool:
            from nio import ErrorResponse
            resp = await self._client.room_send(
                room_id=self._room_id,
                message_type="m.room.message",
                content={"msgtype": "m.text", "body": chunk},
                ignore_unverified_devices=True,
            )
            if isinstance(resp, ErrorResponse):
                print(f"[matrix] room_send error: {resp}", file=sys.stderr)
                return False
            return True

        ok = True
        for chunk in self.chunk_message(text, max_size=MAX_MESSAGE_SIZE):
            try:
                fut = asyncio.run_coroutine_threadsafe(_send_one(chunk), self._loop)
                if not fut.result(timeout=ASYNC_CALL_TIMEOUT_S):
                    ok = False
            except Exception as exc:
                print(f"[matrix] room_send raised: {exc}", file=sys.stderr)
                ok = False
        return ok

    def _typing_e2ee(self) -> bool:
        if not self._client or not self._loop:
            return False

        async def _typing():
            await self._client.room_typing(self._room_id, typing_state=True, timeout=10000)
            return True

        try:
            fut = asyncio.run_coroutine_threadsafe(_typing(), self._loop)
            return bool(fut.result(timeout=10))
        except Exception:
            return False

    # -- HTTP fallback (e2ee=false) ------------------------------------------

    def _poll_http(self) -> List[Update]:
        params: dict = {"timeout": SYNC_TIMEOUT_MS}
        if self._sync_token:
            params["since"] = self._sync_token
        else:
            params["full_state"] = "false"
            params["timeout"] = 0

        headers = {"Authorization": f"Bearer {self._access_token}"}
        sync_http_timeout = SYNC_HTTP_TIMEOUT if self._sync_token else 10
        try:
            resp = requests.get(
                f"{self._homeserver}/_matrix/client/v3/sync",
                params=params,
                headers=headers,
                timeout=sync_http_timeout,
            )
            data = resp.json()
        except (requests.RequestException, ValueError) as e:
            print(f"[matrix] poll_updates error: {e}", file=sys.stderr)
            return []

        next_batch = data.get("next_batch")
        if not next_batch:
            return []

        if not self._sync_initialized:
            self._sync_token = next_batch
            self._sync_initialized = True
            return []

        updates = self._parse_room_events(data)
        self._sync_token = next_batch
        return updates

    def _parse_room_events(self, sync_data: dict) -> List[Update]:
        rooms = sync_data.get("rooms", {}).get("join", {})
        room = rooms.get(self._room_id, {})
        events = room.get("timeline", {}).get("events", [])

        updates: List[Update] = []
        for event in events:
            if event.get("type") != "m.room.message":
                continue
            sender = event.get("sender", "")
            if sender == self._user_id:
                continue

            content = event.get("content", {})
            msgtype = content.get("msgtype")
            if msgtype != "m.text":
                continue

            body = content.get("body", "")
            if not body:
                continue

            # awake.py's main loop expects Telegram-Bot-API-shaped dicts
            # (update["update_id"], update["message"]["chat"]["id"], …).
            # Mint that wrapper here so the polling loop doesn't care which
            # provider it's draining — keeps parity with the E2EE path.
            ts = event.get("origin_server_ts", "")
            update_id = next(self._update_counter)
            raw = {
                "update_id": update_id,
                "message": {
                    "message_id": event.get("event_id", ""),
                    "text": body,
                    "date": ts,
                    "chat": {"id": self._room_id, "type": "supergroup"},
                    "from": {"id": sender, "username": sender},
                },
                "_matrix": {
                    "sender": sender,
                    "event_id": event.get("event_id", ""),
                    "room_id": self._room_id,
                    "origin_server_ts": ts,
                },
            }
            updates.append(
                Update(
                    update_id=update_id,
                    message=Message(
                        text=body,
                        role="user",
                        timestamp=str(ts),
                        raw_data=raw,
                    ),
                    raw_data=raw,
                )
            )
        return updates

    def _send_http(self, text: str) -> bool:
        ok = True
        for chunk in self.chunk_message(text, max_size=MAX_MESSAGE_SIZE):
            with self._send_lock:
                if not self._send_chunk_http(chunk):
                    ok = False
        return ok

    def _send_chunk_http(self, text: str) -> bool:
        from app.retry import retry_with_backoff

        txn_id = uuid.uuid4().hex
        url = (
            f"{self._homeserver}/_matrix/client/v3/rooms/"
            f"{quote(self._room_id, safe='')}/send/m.room.message/{txn_id}"
        )
        payload = {"msgtype": "m.text", "body": text}
        headers = {"Authorization": f"Bearer {self._access_token}"}

        def _do_put():
            resp = requests.put(url, json=payload, headers=headers, timeout=10)
            if resp.status_code >= 400:
                if 400 <= resp.status_code < 500:
                    print(
                        f"[matrix] API error {resp.status_code}: {resp.text[:200]}",
                        file=sys.stderr,
                    )
                    return False
                raise requests.RequestException(
                    f"matrix HTTP {resp.status_code}: {resp.text[:200]}"
                )
            return True

        try:
            return bool(
                retry_with_backoff(
                    _do_put,
                    retryable=(requests.RequestException,),
                    label="matrix send",
                )
            )
        except requests.RequestException as e:
            print(f"[matrix] Send error after retries: {e}", file=sys.stderr)
            return False

    def _typing_http(self) -> bool:
        url = (
            f"{self._homeserver}/_matrix/client/v3/rooms/"
            f"{quote(self._room_id, safe='')}/typing/"
            f"{quote(self._user_id, safe='')}"
        )
        headers = {"Authorization": f"Bearer {self._access_token}"}
        try:
            resp = requests.put(
                url,
                json={"typing": True, "timeout": 10000},
                headers=headers,
                timeout=5,
            )
            return resp.status_code < 400
        except requests.RequestException:
            return False
