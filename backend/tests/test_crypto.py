import base64

import pytest

from app.core import crypto


def test_encrypt_decrypt_roundtrip(encryption_key):
    plaintext = "super-secret-value"
    ct = crypto.encrypt(plaintext)
    assert isinstance(ct, str)
    assert ct != plaintext
    assert crypto.decrypt(ct) == plaintext


def test_encrypt_missing_key_raises(monkeypatch):
    monkeypatch.delenv("SENTINEL_ENCRYPTION_KEY", raising=False)
    with pytest.raises(RuntimeError):
        crypto.encrypt("x")


def test_decrypt_rejects_invalid_ciphertext(encryption_key):
    with pytest.raises(ValueError):
        crypto.decrypt("not-base64!!!!")

    bad = base64.urlsafe_b64encode(b"short").decode("ascii")
    with pytest.raises(ValueError):
        crypto.decrypt(bad)

