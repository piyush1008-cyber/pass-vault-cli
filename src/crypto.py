"""Cryptographic operations module implementing AES-256-GCM and PBKDF2-HMAC-SHA256."""

from __future__ import annotations

import base64
import math
import os
import secrets
import string
from typing import Dict, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


PBKDF2_ITERATIONS = 600_000
SALT_SIZE = 32
NONCE_SIZE = 12  # Standard 96-bit nonce for GCM mode


def derive_key(master_password: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes:
    """Derives a 256-bit AES key from the master password using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(master_password.encode("utf-8"))


def encrypt_secret(plaintext: str, key: bytes) -> Tuple[str, str]:
    """Encrypts plaintext using AES-256-GCM. Returns base64-encoded (nonce, ciphertext_and_tag)."""
    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)

    b64_nonce = base64.b64encode(nonce).decode("utf-8")
    b64_ciphertext = base64.b64encode(ciphertext).decode("utf-8")
    return b64_nonce, b64_ciphertext


def decrypt_secret(b64_nonce: str, b64_ciphertext: str, key: bytes) -> str:
    """Decrypts ciphertext using AES-256-GCM. Raises InvalidTag if ciphertext or key is invalid."""
    nonce = base64.b64decode(b64_nonce)
    ciphertext = base64.b64decode(b64_ciphertext)

    aesgcm = AESGCM(key)
    plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext_bytes.decode("utf-8")


def generate_secure_password(length: int = 20, include_symbols: bool = True, include_numbers: bool = True) -> str:
    """Generates a cryptographically strong random password using secrets module."""
    if length < 8:
        length = 8

    alphabet = string.ascii_letters
    guaranteed = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
    ]

    if include_numbers:
        alphabet += string.digits
        guaranteed.append(secrets.choice(string.digits))
    if include_symbols:
        symbols = "!@#$%^&*()-_=+[]{}|;:,.<>?"
        alphabet += symbols
        guaranteed.append(secrets.choice(symbols))

    remaining_length = length - len(guaranteed)
    remaining = [secrets.choice(alphabet) for _ in range(remaining_length)]

    combined = guaranteed + remaining
    # Secure Fisher-Yates shuffle
    for i in range(len(combined) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        combined[i], combined[j] = combined[j], combined[i]

    return "".join(combined)


def calculate_entropy(password: str) -> float:
    """Calculates password entropy in bits based on character pool cardinality."""
    if not password:
        return 0.0

    pool_size = 0
    if any(c in string.ascii_lowercase for c in password):
        pool_size += 26
    if any(c in string.ascii_uppercase for c in password):
        pool_size += 26
    if any(c in string.digits for c in password):
        pool_size += 10
    if any(c in string.punctuation or c in " " for c in password):
        pool_size += 33

    if pool_size == 0:
        return 0.0

    return len(password) * math.log2(pool_size)


def evaluate_password_strength(password: str) -> Dict:
    """Evaluates password strength and entropy rating."""
    entropy = calculate_entropy(password)
    length = len(password)

    if entropy < 30 or length < 8:
        strength = "VERY_WEAK"
    elif entropy < 50:
        strength = "WEAK"
    elif entropy < 70:
        strength = "MODERATE"
    elif entropy < 90:
        strength = "STRONG"
    else:
        strength = "VERY_STRONG"

    return {
        "entropy_bits": round(entropy, 2),
        "strength": strength,
        "length": length,
        "has_lowercase": any(c.islower() for c in password),
        "has_uppercase": any(c.isupper() for c in password),
        "has_digits": any(c.isdigit() for c in password),
        "has_symbols": any(c in string.punctuation for c in password),
    }
