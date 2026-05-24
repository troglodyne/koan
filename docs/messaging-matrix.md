# Matrix Setup Guide

This guide covers setting up Kōan with [Matrix](https://matrix.org) as the messaging provider. Kōan supports both **end-to-end encrypted rooms** (Megolm/Olm, via `matrix-nio[e2e]` — default) and **unencrypted rooms** (raw Client-Server HTTP API).

## Prerequisites

- Access to a Matrix homeserver. You can use [matrix.org](https://matrix.org), a self-hosted Synapse/Dendrite/Conduit, or any compliant server.
- A dedicated Matrix account for the bot (recommended — don't reuse your personal account).
- An Element (or other Matrix client) login for the bot account, to invite it into the operating room.

## Step 1: Create a Bot Account

Either register a new account directly on the homeserver or use an existing dedicated account. The user ID will look like `@koan:matrix.org`.

## Step 2: Obtain an Access Token

The easiest way is to log in via Element with the bot account, then:

1. Open Element → **Settings → Help & About**
2. Scroll to the bottom and expand **Access Token**
3. Copy the token (long string starting with `syt_`, `mat_`, or similar)

Alternatively, use the `/login` API endpoint:

```bash
curl -XPOST -d '{
  "type": "m.login.password",
  "user": "koan",
  "password": "YOUR_BOT_PASSWORD"
}' "https://matrix.org/_matrix/client/v3/login"
```

The response contains an `access_token` field.

> **Security note:** The access token grants full account access. Treat it like a password — never commit it. If leaked, log out the session via Element (**Settings → Sessions**) to invalidate it.

## Step 3: Create or Choose a Room

Pick the room Kōan will operate in. Either:

- Create a new private room in Element and invite the bot.
- Use an existing room and invite the bot.

Get the room ID:

1. In Element, open the room
2. Click the room name → **Settings → Advanced**
3. Copy the **Internal room ID** (e.g., `!abcdefghijk:matrix.org`)

Make sure the bot account has joined the room (accept the invite from the bot's session, or call `/_matrix/client/v3/join/{roomId}`).

## Step 4: Configure Kōan

The recommended approach is to put Matrix settings in `instance/config.yaml`:

```yaml
messaging:
  provider: "matrix"
  matrix:
    homeserver: "https://matrix.org"
    user_id: "@koan:matrix.org"
    room_id: "!abcdefghijk:matrix.org"
    access_token: "syt_your_token_here"
```

> Treat `instance/config.yaml` like a secret file — it's gitignored by default. If you commit your `instance/` directory to a separate private repo, that's fine; never commit the access token to a public repo.

### Legacy: environment variables

The four `KOAN_MATRIX_*` env vars are still supported and override `config.yaml` when set. Use them only if you have a workflow built around `.env`:

```bash
# .env (legacy alternative)
KOAN_MESSAGING_PROVIDER=matrix
KOAN_MATRIX_HOMESERVER=https://matrix.org
KOAN_MATRIX_ACCESS_TOKEN=syt_your_token_here
KOAN_MATRIX_USER_ID=@koan:matrix.org
KOAN_MATRIX_ROOM_ID=!abcdefghijk:matrix.org
```

Precedence: env var > `config.yaml` value > error.

## Step 5: Start Kōan

```bash
make start
```

You should see in the logs:

```
[init] Messaging provider: MATRIX, Channel: !abcdefghijk:matrix.org
```

## How it works

- **Sending**: `PUT /_matrix/client/v3/rooms/{roomId}/send/m.room.message/{txnId}` with `msgtype: m.text`. Long messages are chunked to 4000 characters per event.
- **Receiving**: Long-polls `GET /_matrix/client/v3/sync` with a 30-second timeout. The first sync discards historical events and records the `next_batch` cursor; subsequent syncs return only new events.
- **Filtering**: Only `m.room.message` events with `msgtype: m.text` are surfaced. Messages sent by the bot's own user ID are ignored so it doesn't reply to itself.

## Troubleshooting

### "Missing required settings"

All four values (`homeserver`, `access_token`, `user_id`, `room_id`) must be set — either under `messaging.matrix` in `instance/config.yaml` or via the corresponding `KOAN_MATRIX_*` env vars.

### `[matrix] API error 401` / `403`

- The access token is invalid or has been revoked. Generate a new one (Step 2).
- The bot account isn't joined to the room. Accept the invite first.

### `[matrix] API error 404`

- The room ID is wrong, or the homeserver doesn't know about it.
- Ensure the room ID starts with `!` and includes the homeserver suffix (e.g., `!abc:matrix.org`).

### Bot replies to its own messages

- Double-check `KOAN_MATRIX_USER_ID` exactly matches the bot's user ID (including the leading `@` and the homeserver part).

### Encrypted rooms

E2EE is supported. See the next section.

---

## End-to-End Encryption (Megolm/Olm)

E2EE is **on by default**. To turn it off, set `messaging.matrix.e2ee: false` in `config.yaml` (or `KOAN_MATRIX_E2EE=0`) and skip the rest of this section.

### Build requirements

The E2EE transport rides on [`matrix-nio[e2e]`](https://github.com/poljar/matrix-nio), which links against `libolm`. On Debian/Ubuntu:

```bash
sudo apt install python3-matrix-nio
```
Or via pip with
```bash
pip install matrix-nio
```

If installing with pip, you'll likely need to install libolm, etc. separately.

### The brand-new-device rule

E2EE requires a Matrix `device_id` that has **never been seen by the homeserver before**. Reusing an existing device — even one you just minted in Element — silently breaks Megolm session setup: messages will send but every recipient sees "unable to decrypt".

The safest way to get one is the bundled bootstrap helper. From the koan repo root:

```bash
KOAN_MATRIX_HOMESERVER=https://matrix.example \
KOAN_MATRIX_USER_ID=@koan:matrix.example \
KOAN_MATRIX_PASSWORD='hunter2' \
make matrix-login
```

That's the recommended invocation — `make` handles the `KOAN_ROOT` / `PYTHONPATH` plumbing that `app.matrix_login` needs (the `app` package lives at `koan/app/`, not the repo root). If you'd rather invoke Python directly:

```bash
cd koan && KOAN_ROOT=$(realpath ..) PYTHONPATH=. \
    KOAN_MATRIX_HOMESERVER=https://matrix.example \
    KOAN_MATRIX_USER_ID=@koan:matrix.example \
    KOAN_MATRIX_PASSWORD='hunter2' \
    ../.venv/bin/python -m app.matrix_login
```

Either way: it logs in once over HTTPS, captures the freshly-minted `device_id` and `access_token`, and writes them — plus an auto-generated `pickle_key` — to `instance/matrix/credentials.env` (mode 0600). The systemd unit picks that file up via `EnvironmentFile=` on next start. The password leaves the process the moment the script exits.

You can run the helper again to mint a new device, but **only do so when migrating to a fresh box**: rotating the device on a working install invalidates all previously-exchanged Megolm sessions and your history goes dark.

### Trust posture and verification

The provider sends with `ignore_unverified_devices=True` so the bot will encrypt to devices it knows about even when they aren't verified. With **cross-signing enabled on your account** (which is the modern Element default), other users' clients still won't share Megolm keys with the bot until its device is cross-signed — so until you verify it once, you'll see *its* messages decrypt fine in your clients but *your* messages will arrive at the bot as "unable to decrypt".

The bot includes some help on the verification handshake: it auto-accepts SAS starts from its own user, auto-confirms the emoji match, and answers the modern `m.key.verification.request` → `ready` handshake that nio doesn't model itself. That's enough for **non-Element clients** (Cinny, FluffyChat, Nheko, etc.) — clicking Verify on the bot device in those works end-to-end without any further action.

#### Element specifically: use the sign-koan-device script

`matrix-nio 0.25.x` and modern Element can't complete SAS together. nio computes the SAS MAC using the legacy direct-Start transcript; modern Element uses an extended transcript that includes the original `m.key.verification.request` event. The MACs never match, so Element always cancels every verification with `The expected key did not match the verified one`. There's no fix for this without re-implementing nio's verification protocol against the modern flow. Tracking issue: [matrix-nio/matrix-nio#430](https://github.com/matrix-nio/matrix-nio/issues/430).

The workaround is to skip SAS entirely and sign the bot's device directly using your self-signing private key (which lives in Secure Secret Storage — 4S). The bundled script `scripts/sign-koan-device.py` does this:

1. Make sure your matrix account has cross-signing + secure backup set up (Element → Settings → Encryption → Set up secure backup). Save the recovery key Element gives you.
2. From the koan repo root, with your environment loaded:

   ```bash
   set -a; . instance/matrix/credentials.env; . .env; set +a

   KOAN_4S_RECOVERY_KEY='EsT5 wByp …'   # the 48-char string Element gave you
   .venv/bin/python scripts/sign-koan-device.py
   ```

   You can use `KOAN_4S_PASSPHRASE='…'` instead if you set up a passphrase rather than (or in addition to) the recovery key.
3. Script output looks like:

   ```
   → Using 4S recovery key
   → Default 4S key id: <key_id>
   → 4S recovery key verified
   → Self-signing pubkey: ed25519:<pubkey>
   → Signing device bundle for @bot:server / DEVICEID (ed25519:abcd…)
   ✓ Signature uploaded.  @bot:server/DEVICEID is now cross-signed by your self-signing key.
   ```

The bot's device is now cross-signed and every other client in shared rooms will treat it as verified on their next sync. Re-run the script after any `make matrix-login` (which mints a fresh device), or after a deliberate device rotation.

The recovery key never persists — pass it as an env var only when running the script, and clear it from your shell history (`history -d`) afterward.

The script needs no extra pip installs — it uses pycryptodome and requests, both of which `matrix-nio[e2e]` already brings in.

**Security note on the auto-SAS path** (relevant for non-Element clients): auto-confirming SAS bypasses the emoji-comparison check that normally protects against MITM. The bot only does this when the verification is initiated by its own matrix account, on the reasoning that anyone with the bot's access token already has full account control — so auto-trusting verifications *from* that same account doesn't change the threat model. Cross-user verification still requires real interactive comparison (and currently fails against Element for the same nio limitation above; use the script for those too).

### Persisting the key store

Olm/Megolm state lives in `KOAN_ROOT/instance/matrix-store/`. **Back this directory up** along with `instance/`: if you lose it, the bot loses every Megolm session and can no longer decrypt past messages from anyone.

### Operational gotchas

- **History visibility**: set the room to `invited` or `joined` (not `world_readable`) — E2EE assumes you control room membership.
- **One bot device per room**: don't run two koan instances pointed at the same account/device_id concurrently. They will fight over the Olm account state.
- **No cross-signing**: this implementation does not publish a master key. Devices verify each other directly.
- **Recovery key**: not implemented. If the store is lost, mint a new device and accept the history loss.

### Disabling E2EE

If you'd rather run in an unencrypted room (e.g., for a public command channel), set:

```yaml
messaging:
  matrix:
    e2ee: false
```

In that mode the provider falls back to the original synchronous HTTP transport — `device_id`, `pickle_key`, and the store directory are all unused.
