import base64
import binascii
import os
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


_KEY_ENV = "SENTINEL_ENCRYPTION_KEY"
_NONCE_LEN = 12  # AES-GCM recommended nonce size
_KEY_LEN = 32  # AES-256


def _load_key() -> bytes:
    raw = os.getenv(_KEY_ENV)
    if not raw:
        raise RuntimeError(f"{_KEY_ENV} is not set")

    key: bytes | None = None
    for decoder in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            decoded = decoder(raw)
        except (binascii.Error, ValueError):
            continue
        if len(decoded) == _KEY_LEN:
            key = decoded
            break

    if key is None:
        raise RuntimeError(f"{_KEY_ENV} must be base64-encoded {_KEY_LEN} bytes")

    return key


def encrypt(plaintext: str) -> str:
    if not isinstance(plaintext, str):
        raise TypeError("plaintext must be a str")

    key = _load_key()
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(_NONCE_LEN)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    token = nonce + ciphertext
    return base64.urlsafe_b64encode(token).decode("ascii")


def decrypt(ciphertext: str) -> str:
    if not isinstance(ciphertext, str):
        raise TypeError("ciphertext must be a str")

    try:
        token = base64.urlsafe_b64decode(ciphertext)
    except (binascii.Error, ValueError) as e:
        raise ValueError("Invalid ciphertext encoding") from e

    if len(token) <= _NONCE_LEN:
        raise ValueError("Invalid ciphertext")

    nonce = token[:_NONCE_LEN]
    ct = token[_NONCE_LEN:]
    aesgcm = AESGCM(_load_key())
    try:
        plaintext = aesgcm.decrypt(nonce, ct, None)
    except InvalidTag as e:
        raise ValueError("Invalid ciphertext") from e
    return plaintext.decode("utf-8")

