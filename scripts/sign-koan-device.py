#!/usr/bin/env python3
"""One-shot Matrix cross-signature minter for the koan bot device.

Why this exists
---------------
With cross-signing enabled, modern Element refuses to send Megolm room
keys to devices that aren't cross-signed.  The "Verify session" UI only
exposes interactive emoji SAS, and matrix-nio 0.25's SAS implementation
doesn't compute the verification MAC the same way modern Element does
when the verification goes through the m.key.verification.request →
ready → start flow (see matrix-nio/matrix-nio#430).  Element cancels
every verification with "The expected key did not match the verified
one", and the bot's device stays unsigned forever.

This script sidesteps the SAS protocol entirely.  It pulls your own
self-signing private key out of Secure Secret Storage (4S, aka SSSS)
using your recovery key or passphrase, signs the bot's device key bundle
with it, and uploads the signature.  The result is functionally identical
to what a working SAS verification would have produced: the bot's device
appears cross-signed to every other client in the room.

Inputs (all env vars)
---------------------
    KOAN_MATRIX_HOMESERVER    Same as the bot's
    KOAN_MATRIX_USER_ID       Same as the bot's (must be the account
                              whose self-signing key signs the device)
    KOAN_MATRIX_ACCESS_TOKEN  Any access token belonging to that account
                              (the bot's token works — it's the same
                              account)
    KOAN_MATRIX_DEVICE_ID     The device to sign (the bot's device)
    KOAN_4S_RECOVERY_KEY      4S recovery key (the "EsT5 wByp …" string
                              Element gave you when you set up secure
                              backup) — OR set KOAN_4S_PASSPHRASE
    KOAN_4S_PASSPHRASE        4S passphrase, if you set one up instead
                              of (or in addition to) the recovery key

No persistent state.  Run once after `make matrix-login` mints a new
device.  Re-run after re-bootstrapping.

Dependencies
------------
Uses only what `matrix-nio[e2e]` already pulls in: `requests` and
`pycryptodome` (imported as `Crypto`).  No new pip installs.
"""

from __future__ import annotations

import argparse
import base64
import hmac as stdlib_hmac
import json
import os
import sys
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

import requests
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256, SHA512
from Crypto.Protocol.KDF import HKDF, PBKDF2
from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa


# --- base64 + canonical JSON helpers ----------------------------------------


def _b64decode(s: str) -> bytes:
    """Standard base64 decode, padding-tolerant."""
    s = s.strip()
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s)


def _unpadded_b64(b: bytes) -> str:
    """Matrix's preferred output form: standard base64, no '=' padding."""
    return base64.b64encode(b).decode("ascii").rstrip("=")


def _canonical_json(value: Any) -> bytes:
    """Matrix canonical JSON (sorted keys, no spaces, UTF-8 raw)."""
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


# --- recovery key parsing ---------------------------------------------------


# Bitcoin / Matrix base58 alphabet (no 0, O, I, l).
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(_B58)}

# Two-byte prefix that recovery keys always carry.
_RECOVERY_KEY_PREFIX = b"\x8b\x01"


def _b58decode(s: str) -> bytes:
    n = 0
    for ch in s:
        if ch not in _B58_INDEX:
            raise ValueError(f"non-base58 character in recovery key: {ch!r}")
        n = n * 58 + _B58_INDEX[ch]
    # Decode integer back to bytes (big-endian).
    out = bytearray()
    while n:
        n, rem = divmod(n, 256)
        out.append(rem)
    # Leading '1' chars in base58 are leading 0x00 bytes.
    pad = 0
    for ch in s:
        if ch != "1":
            break
        pad += 1
    return bytes(reversed(out)) + (b"\x00" * 0)  # leading zero padding handled below


def _decode_recovery_key(text: str) -> bytes:
    """Parse a Matrix 4S recovery key into its raw 32-byte key.

    Format: spaces stripped, then base58 of (0x8B 0x01 | key[32] | parity[1])
    where parity = XOR of all preceding bytes.
    """
    compact = "".join(text.split())
    raw = _b58decode(compact)
    if len(raw) != 35:
        raise ValueError(
            f"recovery key decoded to {len(raw)} bytes; expected 35 "
            f"(2-byte prefix + 32-byte key + 1-byte parity)"
        )
    if raw[:2] != _RECOVERY_KEY_PREFIX:
        raise ValueError(
            f"recovery key prefix {raw[:2].hex()} != expected 8b01 — "
            "probably the wrong string"
        )
    parity = 0
    for b in raw[:-1]:
        parity ^= b
    if parity != raw[-1]:
        raise ValueError("recovery key parity byte mismatch — typo in the key?")
    return raw[2:34]


def _key_from_passphrase(passphrase: str, key_info: Dict[str, Any]) -> bytes:
    """Derive the 32-byte raw key from a passphrase using key_info's PBKDF2 params."""
    pp = key_info.get("passphrase") or {}
    if pp.get("algorithm") != "m.pbkdf2":
        raise ValueError(
            f"key_info passphrase algorithm {pp.get('algorithm')!r} not supported"
        )
    iterations = int(pp.get("iterations", 0))
    bits = int(pp.get("bits", 256))
    salt = pp.get("salt", "")
    if not (iterations and salt):
        raise ValueError("key_info passphrase block missing iterations/salt")
    return PBKDF2(
        passphrase,
        salt.encode("utf-8"),
        dkLen=bits // 8,
        count=iterations,
        hmac_hash_module=SHA512,
    )


# --- SSSS verify + decrypt --------------------------------------------------


def _derive_subkeys(raw_key: bytes, info: str) -> Tuple[bytes, bytes]:
    """HKDF-SHA256 → (aes_key, hmac_key) using the SSSS scheme."""
    okm = HKDF(
        master=raw_key,
        key_len=64,
        salt=b"\x00" * 32,
        hashmod=SHA256,
        context=info.encode("utf-8"),
    )
    return okm[:32], okm[32:]


def _aes_ctr(key: bytes, iv: bytes) -> "AES":
    """AES-CTR using a full 16-byte IV as the initial counter value."""
    return AES.new(
        key,
        AES.MODE_CTR,
        nonce=b"",
        initial_value=int.from_bytes(iv, "big"),
    )


def _verify_storage_key(raw_key: bytes, key_info: Dict[str, Any]) -> None:
    """Check the raw_key against the key_info MAC; raise if it's wrong."""
    iv_b64 = key_info.get("iv")
    expected_mac_b64 = key_info.get("mac")
    if not (iv_b64 and expected_mac_b64):
        raise ValueError("storage key info missing iv/mac fields")
    aes_key, hmac_key = _derive_subkeys(raw_key, "")
    iv = _b64decode(iv_b64)
    encrypted_zeros = _aes_ctr(aes_key, iv).encrypt(b"\x00" * 32)
    computed = HMAC.new(hmac_key, encrypted_zeros, SHA256).digest()
    expected = _b64decode(expected_mac_b64)
    if not stdlib_hmac.compare_digest(computed, expected):
        raise ValueError(
            "storage key MAC mismatch — recovery key/passphrase is wrong "
            "(or you're using the wrong default key)"
        )


def _decrypt_secret(raw_key: bytes, secret_name: str, encrypted: Dict[str, Any]) -> bytes:
    """Decrypt an SSSS-encrypted secret entry and return the plaintext bytes."""
    aes_key, hmac_key = _derive_subkeys(raw_key, secret_name)
    iv = _b64decode(encrypted["iv"])
    ciphertext = _b64decode(encrypted["ciphertext"])
    expected_mac = _b64decode(encrypted["mac"])
    computed_mac = HMAC.new(hmac_key, ciphertext, SHA256).digest()
    if not stdlib_hmac.compare_digest(computed_mac, expected_mac):
        raise ValueError(
            f"ciphertext MAC mismatch on {secret_name!r} — wrong key, or "
            "the encrypted secret was modified"
        )
    return _aes_ctr(aes_key, iv).decrypt(ciphertext)


# --- signing ----------------------------------------------------------------


def _ed25519_from_seed(seed: bytes) -> "ECC.EccKey":
    if len(seed) != 32:
        raise ValueError(f"ed25519 seed must be 32 bytes, got {len(seed)}")
    return ECC.construct(curve="ed25519", seed=seed)


def _ed25519_pubkey_b64(seed: bytes) -> str:
    """Raw 32-byte ed25519 public key, unpadded base64."""
    key = _ed25519_from_seed(seed)
    return _unpadded_b64(key.public_key().export_key(format="raw"))


def sign_device_bundle(
    bundle: Dict[str, Any],
    signing_seed: bytes,
    signing_user: str,
    signing_pubkey_b64: str,
) -> Dict[str, Any]:
    """Return a copy of `bundle` with our signature added under signatures.

    The signature is computed over the bundle with `signatures` and
    `unsigned` removed, serialized as Matrix canonical JSON.
    """
    to_sign = {k: v for k, v in bundle.items() if k not in ("signatures", "unsigned")}
    signer = eddsa.new(_ed25519_from_seed(signing_seed), mode="rfc8032")
    raw_sig = signer.sign(_canonical_json(to_sign))
    sig_b64 = _unpadded_b64(raw_sig)
    signed = json.loads(json.dumps(bundle))  # deep copy
    sigs = signed.setdefault("signatures", {})
    user_sigs = sigs.setdefault(signing_user, {})
    user_sigs[f"ed25519:{signing_pubkey_b64}"] = sig_b64
    return signed


# --- HTTP shim --------------------------------------------------------------


@dataclass
class Client:
    homeserver: str
    user_id: str
    access_token: str

    def _headers(self) -> Dict[str, str]:
        return {"Authorization": f"Bearer {self.access_token}"}

    def get_account_data(self, name: str) -> Optional[Dict[str, Any]]:
        url = (
            f"{self.homeserver}/_matrix/client/v3/user/"
            f"{self.user_id}/account_data/{name}"
        )
        resp = requests.get(url, headers=self._headers(), timeout=15)
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return resp.json()

    def keys_query(self, target_user: str, target_device: str) -> Dict[str, Any]:
        url = f"{self.homeserver}/_matrix/client/v3/keys/query"
        resp = requests.post(
            url,
            headers={**self._headers(), "Content-Type": "application/json"},
            json={"device_keys": {target_user: [target_device]}},
            timeout=15,
        )
        resp.raise_for_status()
        device_keys = resp.json().get("device_keys", {})
        try:
            return device_keys[target_user][target_device]
        except KeyError:
            raise SystemExit(
                f"Server returned no device_keys for {target_user}/{target_device}"
            )

    def upload_signatures(
        self, target_user: str, target_device: str, signed_bundle: Dict[str, Any]
    ) -> Dict[str, Any]:
        url = f"{self.homeserver}/_matrix/client/v3/keys/signatures/upload"
        # The upload endpoint takes the full signed bundle for each device.
        payload = {target_user: {target_device: signed_bundle}}
        resp = requests.post(
            url,
            headers={**self._headers(), "Content-Type": "application/json"},
            json=payload,
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()


# --- entry point ------------------------------------------------------------


def _resolve_recovery() -> Tuple[bytes, str]:
    """Return (raw_key, source_label) from env, deferring passphrase derivation
    to the caller (it needs key_info for PBKDF2 params)."""
    rk = (os.environ.get("KOAN_4S_RECOVERY_KEY") or "").strip()
    pp = os.environ.get("KOAN_4S_PASSPHRASE") or ""
    if rk:
        return _decode_recovery_key(rk), "recovery key"
    if pp:
        # Marker — actual key derivation needs key_info, done in main().
        return b"", "passphrase"
    raise SystemExit(
        "Set KOAN_4S_RECOVERY_KEY (the 48-character string Element gave you "
        "when you set up secure backup) or KOAN_4S_PASSPHRASE."
    )


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--target-user",
        default=os.environ.get("KOAN_MATRIX_USER_ID", ""),
        help="User who owns the device to sign (default: $KOAN_MATRIX_USER_ID)",
    )
    parser.add_argument(
        "--target-device",
        default=os.environ.get("KOAN_MATRIX_DEVICE_ID", ""),
        help="Device id to sign (default: $KOAN_MATRIX_DEVICE_ID)",
    )
    args = parser.parse_args(argv)

    homeserver = (os.environ.get("KOAN_MATRIX_HOMESERVER") or "").rstrip("/")
    user_id = os.environ.get("KOAN_MATRIX_USER_ID", "")
    token = os.environ.get("KOAN_MATRIX_ACCESS_TOKEN", "")
    target_user = args.target_user
    target_device = args.target_device

    missing = [
        name
        for name, val in [
            ("KOAN_MATRIX_HOMESERVER", homeserver),
            ("KOAN_MATRIX_USER_ID", user_id),
            ("KOAN_MATRIX_ACCESS_TOKEN", token),
            ("--target-user", target_user),
            ("--target-device", target_device),
        ]
        if not val
    ]
    if missing:
        print(f"missing required input(s): {', '.join(missing)}", file=sys.stderr)
        return 1

    raw_key, source = _resolve_recovery()
    print(f"→ Using 4S {source}", file=sys.stderr)

    client = Client(homeserver, user_id, token)

    # 1. Default storage key id, then key_info for that id.
    default = client.get_account_data("m.secret_storage.default_key")
    if not default or not default.get("key"):
        print(
            "Your account has no m.secret_storage.default_key set — that "
            "means you haven't enabled secure backup / cross-signing on "
            "this account.  Do that from Element's Settings → Security "
            "first, then re-run.",
            file=sys.stderr,
        )
        return 1
    key_id = default["key"]
    print(f"→ Default 4S key id: {key_id}", file=sys.stderr)
    key_info = client.get_account_data(f"m.secret_storage.key.{key_id}")
    if not key_info:
        print(f"key_info for {key_id} not found on server", file=sys.stderr)
        return 1
    if key_info.get("algorithm") != "m.secret_storage.v1.aes-hmac-sha2":
        print(
            f"unsupported 4S algorithm: {key_info.get('algorithm')!r}", file=sys.stderr,
        )
        return 1

    # If we got here via passphrase, finish key derivation now that we have the params.
    if source == "passphrase":
        raw_key = _key_from_passphrase(os.environ["KOAN_4S_PASSPHRASE"], key_info)

    try:
        _verify_storage_key(raw_key, key_info)
    except ValueError as exc:
        print(f"→ {exc}", file=sys.stderr)
        return 1
    print("→ 4S recovery key verified", file=sys.stderr)

    # 2. Pull the encrypted self-signing key and decrypt it.
    secret = client.get_account_data("m.cross_signing.self_signing")
    if not secret:
        print(
            "m.cross_signing.self_signing not found in account data — "
            "either cross-signing isn't bootstrapped on this account, "
            "or the secret is stored under a different key.",
            file=sys.stderr,
        )
        return 1
    encrypted_for_key = (secret.get("encrypted") or {}).get(key_id)
    if not encrypted_for_key:
        print(
            f"self_signing secret isn't encrypted under {key_id} — "
            f"available: {sorted((secret.get('encrypted') or {}).keys())}",
            file=sys.stderr,
        )
        return 1
    try:
        plaintext = _decrypt_secret(raw_key, "m.cross_signing.self_signing", encrypted_for_key)
    except ValueError as exc:
        print(f"→ {exc}", file=sys.stderr)
        return 1

    # Plaintext is unpadded-base64 of the 32-byte ed25519 seed.
    seed = _b64decode(plaintext.decode("ascii"))
    if len(seed) != 32:
        print(f"unexpected self-signing seed length: {len(seed)}", file=sys.stderr)
        return 1
    signing_pubkey_b64 = _ed25519_pubkey_b64(seed)
    print(f"→ Self-signing pubkey: ed25519:{signing_pubkey_b64}", file=sys.stderr)

    # 3. Fetch the target device's key bundle and sign it.
    bundle = client.keys_query(target_user, target_device)
    print(
        f"→ Signing device bundle for {target_user}/{target_device} "
        f"(ed25519:{bundle.get('keys', {}).get(f'ed25519:{target_device}', '?')[:16]}…)",
        file=sys.stderr,
    )
    signed = sign_device_bundle(bundle, seed, target_user, signing_pubkey_b64)

    # 4. Upload.
    result = client.upload_signatures(target_user, target_device, signed)
    failures = result.get("failures") or {}
    if failures:
        print(f"→ Upload returned failures: {failures}", file=sys.stderr)
        return 1
    print(
        f"✓ Signature uploaded.  {target_user}/{target_device} is now "
        "cross-signed by your self-signing key.  Other clients in any "
        "shared room will treat it as verified on their next sync.",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
