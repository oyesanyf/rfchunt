"""
AES-256-GCM Secret & Evidence Encryption at Rest (Pillar 6)
===========================================================
Mirrors BaaRai/ARTEX's operational security guarantee for stored secrets
and captured traffic evidence snapshots:
- Uses 32-byte key from `ARTEX_SECRET_KEY` (base64 or hex) or `keys/secret.key`
  (auto-generated with restrictive permissions on first disk DB startup).
- Wraps encrypted values in `enc:v1:<nonce_b64>:<ciphertext_b64>` envelopes.
- Fail-closed: if encrypted rows exist in SQLite and no valid key is available,
  refuses to start rather than silently serving corrupted/unreadable state.
"""

from __future__ import annotations

import base64
import binascii
import os
from pathlib import Path
import secrets
from typing import Optional, Union

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ENVELOPE_PREFIX = "enc:v1:"
DEFAULT_KEYS_DIR = Path(__file__).resolve().parent.parent / "keys"


def parse_raw_key(raw: Union[str, bytes]) -> bytes:
    """Parses a 32-byte key from raw bytes, 64-char hex, or base64 string."""
    if isinstance(raw, bytes):
        if len(raw) == 32:
            return raw
        try:
            raw_str = raw.decode("utf-8", errors="strict").strip()
        except UnicodeDecodeError as exc:
            raise ValueError("ARTEX secret key bytes must be 32 raw bytes or valid UTF-8 hex/base64.") from exc
    else:
        raw_str = str(raw).strip()

    if not raw_str:
        raise ValueError("Encryption key cannot be empty.")

    # Try 64-char hex first
    if len(raw_str) == 64:
        try:
            decoded = bytes.fromhex(raw_str)
            if len(decoded) == 32:
                return decoded
        except ValueError:
            pass

    # Try standard / urlsafe base64
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            padded = raw_str + "=" * ((4 - len(raw_str) % 4) % 4)
            decoded = decoder(padded)
            if len(decoded) == 32:
                return decoded
        except (binascii.Error, ValueError):
            continue

    raise ValueError("ARTEX secret key must decode to exactly 32 bytes (base64 or 64-char hex).")


def is_encrypted_envelope(value: Optional[str]) -> bool:
    return isinstance(value, str) and value.startswith(ENVELOPE_PREFIX)


class SecretBox:
    """AES-256-GCM authenticated encryption box for secrets and traffic snapshots."""

    def __init__(self, key: bytes, source: str = "memory"):
        if not isinstance(key, bytes) or len(key) != 32:
            raise ValueError("SecretBox requires a 32-byte AES-256 key.")
        self._key = key
        self._aead = AESGCM(key)
        self.source = source

    @staticmethod
    def generate_key() -> bytes:
        return secrets.token_bytes(32)

    @classmethod
    def generate(cls) -> "SecretBox":
        return cls(secrets.token_bytes(32), source="generated")

    @classmethod
    def from_env_or_keyfile(
        cls,
        key_path: Optional[Union[str, Path]] = None,
        *,
        create_if_missing: bool = False,
        env_var: str = "ARTEX_SECRET_KEY",
    ) -> Optional["SecretBox"]:
        """
        Resolves a `SecretBox` from `ARTEX_SECRET_KEY` env var first, then `key_path`
        (default `keys/secret.key`). If neither exists and `create_if_missing=True`,
        generates a fresh 32-byte key, writes it base64-encoded with `0600` mode,
        and returns the initialized box. Returns `None` if unavailable and not created.
        """
        env_val = os.environ.get(env_var, "").strip()
        if env_val:
            return cls(parse_raw_key(env_val), source=f"env:{env_var}")

        resolved_path = Path(key_path) if key_path else (DEFAULT_KEYS_DIR / "secret.key")
        if resolved_path.is_file():
            raw_bytes = resolved_path.read_bytes()
            if len(raw_bytes) == 32:
                return cls(raw_bytes, source=f"file:{resolved_path}")
            return cls(parse_raw_key(raw_bytes.strip()), source=f"file:{resolved_path}")

        if not create_if_missing:
            return None

        resolved_path.parent.mkdir(parents=True, exist_ok=True)
        key_bytes = secrets.token_bytes(32)
        b64_text = base64.b64encode(key_bytes).decode("ascii") + "\n"
        try:
            fd = os.open(str(resolved_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                os.write(fd, b64_text.encode("utf-8"))
            finally:
                os.close(fd)
        except FileExistsError:
            raw_bytes = resolved_path.read_bytes()
            if len(raw_bytes) == 32:
                return cls(raw_bytes, source=f"file:{resolved_path}")
            return cls(parse_raw_key(raw_bytes.strip()), source=f"file:{resolved_path}")
        try:
            os.chmod(resolved_path, 0o600)
        except OSError:
            pass
        return cls(key_bytes, source=f"file:{resolved_path}")

    def encrypt_str(self, plaintext: Optional[str], aad: bytes = b"rfchunt-artex-v1") -> str:
        """Encrypts a UTF-8 string into an authenticated `enc:v1:<nonce>:<ct>` envelope."""
        text = "" if plaintext is None else str(plaintext)
        if not text:
            return ""
        if is_encrypted_envelope(text):
            return text
        nonce = secrets.token_bytes(12)
        ct = self._aead.encrypt(nonce, text.encode("utf-8"), aad)
        return f"{ENVELOPE_PREFIX}{base64.b64encode(nonce).decode('ascii')}:{base64.b64encode(ct).decode('ascii')}"

    def decrypt_str(self, ciphertext: Optional[str], aad: bytes = b"rfchunt-artex-v1") -> str:
        """Decrypts an `enc:v1:` envelope, passing legacy plaintext strings through unchanged."""
        if ciphertext is None or ciphertext == "":
            return ""
        if not is_encrypted_envelope(ciphertext):
            return str(ciphertext)
        body = ciphertext[len(ENVELOPE_PREFIX):]
        if ":" not in body:
            raise ValueError("Malformed encrypted envelope (missing nonce separator).")
        nonce_b64, ct_b64 = body.split(":", 1)
        nonce = base64.b64decode(nonce_b64)
        ct = base64.b64decode(ct_b64)
        if len(nonce) != 12 or len(ct) < 16:
            raise ValueError("Malformed encrypted envelope (invalid AES-GCM nonce or tag length).")
        plain = self._aead.decrypt(nonce, ct, aad)
        return plain.decode("utf-8")

    def encrypt_bytes(self, data: bytes, aad: bytes = b"rfchunt-artex-archive-v1") -> bytes:
        """Encrypts raw binary payload (for encrypted task archives): `RFCA1` magic + 12B nonce + AES-GCM ct."""
        nonce = secrets.token_bytes(12)
        ct = self._aead.encrypt(nonce, data, aad)
        return b"RFCA1" + nonce + ct

    def decrypt_bytes(self, blob: bytes, aad: bytes = b"rfchunt-artex-archive-v1") -> bytes:
        """Decrypts raw binary archive blob produced by `encrypt_bytes`."""
        if not blob or len(blob) < 5 + 12 + 16 or not blob.startswith(b"RFCA1"):
            raise ValueError("Invalid or corrupted encrypted archive header.")
        nonce = blob[5:17]
        ct = blob[17:]
        return self._aead.decrypt(nonce, ct, aad)
