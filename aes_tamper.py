#!/usr/bin/env python3
"""AES encryption tamper script for sqlmap.

Encrypts SQL injection payloads before they are sent to the target,
supporting web applications that encrypt request parameters client-side.

Usage as sqlmap tamper:
    sqlmap -u "http://target/vuln" --tamper=aes_tamper.py --dbs

Usage as standalone CLI:
    python aes_tamper.py encrypt --key "mysecret" "payload"
    python aes_tamper.py decrypt --key "mysecret" "U2FsdGVkX1+..."

Key configuration (tamper mode):
    1. Set SQLMAP_AES_KEY environment variable, or
    2. Create a .aes-key file in the same directory as this script
"""

import argparse
import base64
import os
import sys
from binascii import Error as BinasciiError
from hashlib import md5
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# ---------------------------------------------------------------------------
# sqlmap interface (graceful fallback when run standalone)
# ---------------------------------------------------------------------------

try:
    from lib.core.enums import PRIORITY
    priority = PRIORITY.NORMAL
    _IN_SQLMAP = True
except ImportError:
    priority = "NORMAL"  # sqlmap not on path; standalone CLI mode
    _IN_SQLMAP = False


def _patch_response_handler():
    """Monkey-patch sqlmap's HTTP connect to decrypt AES-encrypted responses."""
    if not _IN_SQLMAP:
        return
    try:
        import lib.request.connect as _conn
        _original_connect = _conn.connect

        def _patched_connect(*args, **kwargs):
            page, code, headers = _original_connect(*args, **kwargs)
            if page and _load_key():
                try:
                    import json as _json
                    parsed = _json.loads(page)
                    if isinstance(parsed, dict):
                        if "data" in parsed:
                            parsed["data"] = decrypt(parsed["data"], _load_key())
                        if "error" in parsed:
                            parsed["error"] = decrypt(parsed["error"], _load_key())
                    page = _json.dumps(parsed)
                except Exception:
                    pass
            return page, code, headers

        _conn.connect = _patched_connect
    except Exception:
        pass


def dependencies():
    """List dependencies for sqlmap. pycryptodome is assumed installed."""
    _patch_response_handler()


# ---------------------------------------------------------------------------
# Crypto primitives (OpenSSL-compatible EVP_BytesToKey / Salted__ format)
# ---------------------------------------------------------------------------

BLOCK_SIZE = 16
MAGIC = b"Salted__"


def _pad(data: bytes) -> bytes:
    """Apply PKCS#7 padding."""
    length = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([length] * length)


def _unpad(data: bytes) -> bytes:
    """Remove PKCS#7 padding with validation."""
    if not data:
        raise DecryptionError("empty ciphertext")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > BLOCK_SIZE:
        raise DecryptionError(f"invalid padding byte: {pad_len}")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise DecryptionError("padding mismatch")
    return data[:-pad_len]


def _bytes_to_key(passphrase: str, salt: bytes, output: int = 48) -> bytes:
    """OpenSSL EVP_BytesToKey with MD5 (Salted__ key derivation).

    Produces *output* bytes of keying material.  For AES-256-CBC we
    need 32 bytes for the key and 16 bytes for the IV (48 total).
    """
    assert len(salt) == 8
    data = passphrase.encode() + salt
    key = md5(data).digest()
    final_key = key
    while len(final_key) < output:
        key = md5(key + data).digest()
        final_key += key
    return final_key[:output]


def encrypt(plaintext: str, passphrase: str) -> str:
    """Encrypt *plaintext* with AES-256-CBC, return base64 string.

    Output format: base64("Salted__" + 8-byte salt + ciphertext)
    Compatible with OpenSSL ``enc -aes-256-cbc`` and CryptoJS.
    """
    salt = get_random_bytes(8)
    key_iv = _bytes_to_key(passphrase, salt, 32 + 16)
    key = key_iv[:32]
    iv = key_iv[32:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = _pad(plaintext.encode())
    ciphertext = cipher.encrypt(padded)
    return base64.b64encode(MAGIC + salt + ciphertext).decode("ascii")


def decrypt(ciphertext_b64: str, passphrase: str) -> str:
    """Decrypt a base64-encoded ``Salted__`` ciphertext.

    Raises ``DecryptionError`` on any failure.
    """
    try:
        raw = base64.b64decode(ciphertext_b64, validate=True)
    except (BinasciiError, ValueError) as exc:
        raise DecryptionError(f"invalid base64: {exc}") from exc

    if raw[:8] != MAGIC:
        raise DecryptionError("missing 'Salted__' header")

    salt = raw[8:16]
    key_iv = _bytes_to_key(passphrase, salt, 32 + 16)
    key = key_iv[:32]
    iv = key_iv[32:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    try:
        padded = cipher.decrypt(raw[16:])
    except Exception as exc:
        raise DecryptionError(f"decryption failed: {exc}") from exc
    return _unpad(padded).decode("utf-8")


# ---------------------------------------------------------------------------
# Key loading
# ---------------------------------------------------------------------------

class DecryptionError(Exception):
    """Raised when decryption fails."""
    pass


_cached_key: str | None = None


def _load_key(cli_key: str | None = None) -> str:
    """Resolve the AES key from CLI arg, env var, or sidecar file.

    Priority: CLI argument > SQLMAP_AES_KEY env var > .aes-key file.
    Result is cached after first load.
    """
    global _cached_key
    if _cached_key is not None:
        return _cached_key

    key: str | None = cli_key

    if key is None:
        key = os.environ.get("SQLMAP_AES_KEY")

    if key is None:
        key_path = Path(__file__).parent / ".aes-key"
        if key_path.is_file():
            key = key_path.read_text().strip()

    if not key:
        raise DecryptionError(
            "No AES key found. Pass --key on the CLI, set SQLMAP_AES_KEY, "
            "or create a .aes-key file next to this script."
        )

    _cached_key = key
    return key


# ---------------------------------------------------------------------------
# sqlmap tamper entry point
# ---------------------------------------------------------------------------

def tamper(payload: str, **kwargs) -> str:
    return encrypt(payload, _load_key())


# ---------------------------------------------------------------------------
# Standalone CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="AES encrypt/decrypt for sqlmap tampered payloads"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    enc = sub.add_parser("encrypt", help="Encrypt plaintext")
    enc.add_argument("--key", "-k", required=True, help="AES passphrase")
    enc.add_argument("plaintext", help="Text to encrypt")

    dec = sub.add_parser("decrypt", help="Decrypt ciphertext")
    dec.add_argument("--key", "-k", required=True, help="AES passphrase")
    dec.add_argument("ciphertext", help="Base64 ciphertext to decrypt")

    args = parser.parse_args()

    try:
        if args.command == "encrypt":
            print(encrypt(args.plaintext, args.key))
        elif args.command == "decrypt":
            print(decrypt(args.ciphertext, args.key))
    except DecryptionError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
