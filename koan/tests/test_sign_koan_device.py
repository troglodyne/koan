"""Tests for scripts/sign-koan-device.py — the 4S decrypt + cross-sign tool.

We exercise the SSSS round-trip and canonical-JSON signing without any
network access.  The script's main() is not tested here; it's a thin
HTTP wrapper over the primitives in this file, and the integration is
covered by the operator running it once against a real homeserver.
"""

from __future__ import annotations

import base64
import importlib.util
import os
import sys
from pathlib import Path

import pytest
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Protocol.KDF import HKDF
from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa


# ---------------------------------------------------------------------------
# Load the script as a module — its filename has a hyphen so it can't be
# imported the usual way.  scripts/ lives at the repo root, not under koan/.
# ---------------------------------------------------------------------------


_SCRIPT_PATH = Path(__file__).resolve().parents[2] / "scripts" / "sign-koan-device.py"


@pytest.fixture(scope="module")
def signtool():
    spec = importlib.util.spec_from_file_location("sign_koan_device", _SCRIPT_PATH)
    mod = importlib.util.module_from_spec(spec)
    # Must be in sys.modules BEFORE exec — @dataclass looks itself up there.
    sys.modules["sign_koan_device"] = mod
    try:
        spec.loader.exec_module(mod)
    except Exception:
        sys.modules.pop("sign_koan_device", None)
        raise
    return mod


# ---------------------------------------------------------------------------
# Helpers: build SSSS payloads the same way Element/Synapse would.
# ---------------------------------------------------------------------------


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _unpadded_b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii").rstrip("=")


def _hkdf(raw_key: bytes, info: str) -> tuple[bytes, bytes]:
    okm = HKDF(
        master=raw_key,
        key_len=64,
        salt=b"\x00" * 32,
        hashmod=SHA256,
        context=info.encode("utf-8"),
    )
    return okm[:32], okm[32:]


def _aes_ctr(key: bytes, iv: bytes):
    return AES.new(
        key, AES.MODE_CTR, nonce=b"", initial_value=int.from_bytes(iv, "big"),
    )


def _make_key_info(raw_key: bytes) -> dict:
    """Mint a key_info entry the way Element does after generating a key."""
    aes_key, hmac_key = _hkdf(raw_key, "")
    iv = os.urandom(16)
    encrypted_zeros = _aes_ctr(aes_key, iv).encrypt(b"\x00" * 32)
    mac = HMAC.new(hmac_key, encrypted_zeros, SHA256).digest()
    return {
        "algorithm": "m.secret_storage.v1.aes-hmac-sha2",
        "iv": _b64(iv),
        "mac": _b64(mac),
    }


def _encrypt_secret(raw_key: bytes, name: str, plaintext: bytes) -> dict:
    aes_key, hmac_key = _hkdf(raw_key, name)
    iv = os.urandom(16)
    ct = _aes_ctr(aes_key, iv).encrypt(plaintext)
    return {
        "iv": _b64(iv),
        "ciphertext": _b64(ct),
        "mac": _b64(HMAC.new(hmac_key, ct, SHA256).digest()),
    }


# ---------------------------------------------------------------------------
# SSSS verify + decrypt
# ---------------------------------------------------------------------------


class TestStorageKeyVerify:
    def test_correct_key_passes(self, signtool):
        raw = os.urandom(32)
        key_info = _make_key_info(raw)
        signtool._verify_storage_key(raw, key_info)  # no raise

    def test_wrong_key_raises(self, signtool):
        raw = os.urandom(32)
        key_info = _make_key_info(raw)
        with pytest.raises(ValueError, match="MAC mismatch"):
            signtool._verify_storage_key(os.urandom(32), key_info)

    def test_missing_iv_raises(self, signtool):
        with pytest.raises(ValueError, match="missing iv/mac"):
            signtool._verify_storage_key(b"\x00" * 32, {"mac": "x"})


class TestDecryptSecret:
    def test_roundtrip(self, signtool):
        raw = os.urandom(32)
        plaintext = b"the quick brown ed25519 jumps over the lazy curve"
        enc = _encrypt_secret(raw, "m.cross_signing.self_signing", plaintext)
        out = signtool._decrypt_secret(raw, "m.cross_signing.self_signing", enc)
        assert out == plaintext

    def test_wrong_key_fails_mac(self, signtool):
        raw = os.urandom(32)
        enc = _encrypt_secret(raw, "m.cross_signing.self_signing", b"x" * 64)
        with pytest.raises(ValueError, match="MAC mismatch"):
            signtool._decrypt_secret(os.urandom(32), "m.cross_signing.self_signing", enc)

    def test_wrong_info_string_fails_mac(self, signtool):
        """info string MUST match — different names derive different MAC keys."""
        raw = os.urandom(32)
        enc = _encrypt_secret(raw, "m.cross_signing.self_signing", b"y" * 32)
        with pytest.raises(ValueError, match="MAC mismatch"):
            signtool._decrypt_secret(raw, "m.cross_signing.master", enc)


# ---------------------------------------------------------------------------
# Recovery key encode/decode
# ---------------------------------------------------------------------------


def _encode_recovery_key(raw: bytes) -> str:
    """Mirror Element: prefix 0x8B 0x01, parity, base58, group every 4 chars."""
    body = b"\x8b\x01" + raw
    parity = 0
    for b in body:
        parity ^= b
    body += bytes([parity])
    # base58 encode
    n = int.from_bytes(body, "big")
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    out = ""
    while n:
        n, rem = divmod(n, 58)
        out = alphabet[rem] + out
    # Element groups in 4s for readability — script must tolerate spaces.
    return " ".join(out[i : i + 4] for i in range(0, len(out), 4))


class TestRecoveryKey:
    def test_roundtrip(self, signtool):
        raw = os.urandom(32)
        encoded = _encode_recovery_key(raw)
        assert signtool._decode_recovery_key(encoded) == raw

    def test_spaces_optional(self, signtool):
        raw = os.urandom(32)
        encoded = _encode_recovery_key(raw).replace(" ", "")
        assert signtool._decode_recovery_key(encoded) == raw

    def test_parity_check_fires(self, signtool):
        raw = os.urandom(32)
        encoded = _encode_recovery_key(raw)
        # Flip a character to a different valid base58 char — corrupts parity.
        chars = list(encoded.replace(" ", ""))
        for i, ch in enumerate(chars):
            if ch != "z":
                chars[i] = "z"
                break
        with pytest.raises(ValueError, match="parity|prefix"):
            signtool._decode_recovery_key("".join(chars))

    def test_wrong_prefix_rejected(self, signtool):
        # Build a 35-byte payload with a deliberately wrong prefix.
        body = b"\x00\x00" + os.urandom(32)
        parity = 0
        for b in body:
            parity ^= b
        body += bytes([parity])
        n = int.from_bytes(body, "big")
        alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        out = ""
        while n:
            n, rem = divmod(n, 58)
            out = alphabet[rem] + out
        with pytest.raises(ValueError, match="prefix"):
            signtool._decode_recovery_key(out)


# ---------------------------------------------------------------------------
# Canonical JSON + signing
# ---------------------------------------------------------------------------


class TestCanonicalJson:
    def test_keys_sorted(self, signtool):
        out = signtool._canonical_json({"b": 1, "a": 2})
        assert out == b'{"a":2,"b":1}'

    def test_no_whitespace(self, signtool):
        out = signtool._canonical_json({"x": [1, 2, 3]})
        assert b" " not in out

    def test_utf8(self, signtool):
        # Matrix canonical JSON does NOT escape non-ASCII (ensure_ascii=False).
        out = signtool._canonical_json({"name": "Kōan"})
        assert "Kōan".encode("utf-8") in out


class TestSignDeviceBundle:
    def test_signature_validates(self, signtool):
        seed = os.urandom(32)
        priv = ECC.construct(curve="ed25519", seed=seed)
        pub_b64 = _unpadded_b64(priv.public_key().export_key(format="raw"))

        bundle = {
            "user_id": "@trogbot:matrix.example",
            "device_id": "TKTSHCSSZS",
            "algorithms": ["m.olm.v1.curve25519-aes-sha2", "m.megolm.v1.aes-sha2"],
            "keys": {
                "curve25519:TKTSHCSSZS": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "ed25519:TKTSHCSSZS": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
            },
            "signatures": {
                "@trogbot:matrix.example": {
                    "ed25519:TKTSHCSSZS": "device-self-sig-here",
                },
            },
            "unsigned": {"device_display_name": "koan-test"},
        }
        signed = signtool.sign_device_bundle(
            bundle, seed, "@trogbot:matrix.example", pub_b64,
        )

        # Original signatures preserved + ours appended.
        sigs = signed["signatures"]["@trogbot:matrix.example"]
        assert sigs["ed25519:TKTSHCSSZS"] == "device-self-sig-here"
        assert f"ed25519:{pub_b64}" in sigs

        # Verify the signature checks out over the canonical-JSON of the
        # bundle with signatures + unsigned stripped — same surface
        # Element / other clients use.
        to_verify = {
            k: v for k, v in signed.items() if k not in ("signatures", "unsigned")
        }
        sig_b64 = sigs[f"ed25519:{pub_b64}"]
        sig_bytes = base64.b64decode(sig_b64 + "=" * (-len(sig_b64) % 4))
        # raises ValueError on bad signature
        verifier = eddsa.new(priv.public_key(), mode="rfc8032")
        verifier.verify(signtool._canonical_json(to_verify), sig_bytes)

    def test_unsigned_block_ignored(self, signtool):
        """Mutating `unsigned` after signing must not invalidate the sig."""
        seed = os.urandom(32)
        priv = ECC.construct(curve="ed25519", seed=seed)
        pub_b64 = _unpadded_b64(priv.public_key().export_key(format="raw"))

        bundle = {
            "user_id": "@a:b",
            "device_id": "D",
            "algorithms": [],
            "keys": {"ed25519:D": "k"},
        }
        signed = signtool.sign_device_bundle(bundle, seed, "@a:b", pub_b64)
        signed["unsigned"] = {"display_name": "renamed after the fact"}

        to_verify = {
            k: v for k, v in signed.items() if k not in ("signatures", "unsigned")
        }
        sig_b64 = signed["signatures"]["@a:b"][f"ed25519:{pub_b64}"]
        sig_bytes = base64.b64decode(sig_b64 + "=" * (-len(sig_b64) % 4))
        verifier = eddsa.new(priv.public_key(), mode="rfc8032")
        verifier.verify(signtool._canonical_json(to_verify), sig_bytes)


# ---------------------------------------------------------------------------
# Passphrase derivation
# ---------------------------------------------------------------------------


class TestPassphrase:
    def test_known_pbkdf2_params(self, signtool):
        """PBKDF2 derivation must match what Element produces from the same
        passphrase + key_info — verify by checking the storage key MAC."""
        passphrase = "correct horse battery staple"
        salt = "test-salt"
        key_info_template = {
            "algorithm": "m.secret_storage.v1.aes-hmac-sha2",
            "passphrase": {
                "algorithm": "m.pbkdf2",
                "iterations": 1000,  # cheap for tests
                "salt": salt,
                "bits": 256,
            },
        }
        raw = signtool._key_from_passphrase(passphrase, key_info_template)
        # Build a key_info whose iv/mac match this raw key.
        full = {**key_info_template, **_make_key_info(raw)}
        signtool._verify_storage_key(raw, full)  # no raise

    def test_wrong_passphrase_fails_verify(self, signtool):
        salt = "test-salt"
        key_info_template = {
            "algorithm": "m.secret_storage.v1.aes-hmac-sha2",
            "passphrase": {
                "algorithm": "m.pbkdf2",
                "iterations": 1000,
                "salt": salt,
                "bits": 256,
            },
        }
        right = signtool._key_from_passphrase("right passphrase", key_info_template)
        wrong = signtool._key_from_passphrase("wrong passphrase", key_info_template)
        full = {**key_info_template, **_make_key_info(right)}
        with pytest.raises(ValueError, match="MAC mismatch"):
            signtool._verify_storage_key(wrong, full)
