"""Unit tests for cryptographic primitives and password utilities."""

import pytest
from cryptography.exceptions import InvalidTag
from src.crypto import (
    calculate_entropy,
    decrypt_secret,
    derive_key,
    encrypt_secret,
    evaluate_password_strength,
    generate_secure_password,
)


def test_key_derivation_deterministic():
    salt = b"test_salt_1234567890123456789012"
    key1 = derive_key("master_password", salt, iterations=10_000)
    key2 = derive_key("master_password", salt, iterations=10_000)
    assert key1 == key2
    assert len(key1) == 32


def test_encryption_decryption_roundtrip():
    salt = b"test_salt_1234567890123456789012"
    key = derive_key("master_password", salt, iterations=10_000)

    secret = "SuperSecretAPIKey!99283"
    nonce, ciphertext = encrypt_secret(secret, key)

    decrypted = decrypt_secret(nonce, ciphertext, key)
    assert decrypted == secret


def test_tamper_detection_invalid_tag():
    salt = b"test_salt_1234567890123456789012"
    key = derive_key("master_password", salt, iterations=10_000)

    nonce, ciphertext = encrypt_secret("Secret", key)

    # Wrong key decrypt attempt
    wrong_key = derive_key("wrong_password", salt, iterations=10_000)
    with pytest.raises(InvalidTag):
        decrypt_secret(nonce, ciphertext, wrong_key)


def test_secure_password_generator():
    pwd = generate_secure_password(length=24, include_symbols=True, include_numbers=True)
    assert len(pwd) == 24
    assert any(c.isupper() for c in pwd)
    assert any(c.islower() for c in pwd)
    assert any(c.isdigit() for c in pwd)


def test_password_entropy_scoring():
    weak = evaluate_password_strength("123456")
    assert weak["strength"] == "VERY_WEAK"

    strong = evaluate_password_strength("K9#vL!9xZ$2mQ@1wP&")
    assert strong["strength"] in ("STRONG", "VERY_STRONG")
    assert strong["entropy_bits"] > 80
