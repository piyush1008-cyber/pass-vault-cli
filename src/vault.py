"""Vault storage layer managing master authentication and encrypted credential records."""

from __future__ import annotations

import base64
import os
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from cryptography.exceptions import InvalidTag
from src.crypto import (
    SALT_SIZE,
    decrypt_secret,
    derive_key,
    encrypt_secret,
    evaluate_password_strength,
)


class VaultError(Exception):
    """Base exception for Vault errors."""
    pass


class AuthenticationError(VaultError):
    """Raised when master password is wrong."""
    pass


SCHEMA_DDL = """
CREATE TABLE IF NOT EXISTS _vault_meta (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    salt TEXT NOT NULL,
    verifier TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS secrets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    service TEXT NOT NULL,
    username TEXT NOT NULL,
    nonce TEXT NOT NULL,
    ciphertext TEXT NOT NULL,
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(service, username)
);
"""


class Vault:
    """Encrypted credential vault backed by SQLite."""

    def __init__(self, db_path: Path | str = "vault.db"):
        self.db_path = str(db_path)
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._get_conn() as conn:
            conn.executescript(SCHEMA_DDL)
            conn.commit()

    def is_initialized(self) -> bool:
        """Checks if a master password has been configured."""
        with self._get_conn() as conn:
            row = conn.execute("SELECT id FROM _vault_meta WHERE id = 1").fetchone()
            return row is not None

    def initialize(self, master_password: str) -> bytes:
        """Configures master password and initializes the cryptographic verifier."""
        if self.is_initialized():
            raise VaultError("Vault is already initialized.")

        salt = os.urandom(SALT_SIZE)
        derived_key = derive_key(master_password, salt)

        # Store a verifier ciphertext to validate master password on login
        v_nonce, v_cipher = encrypt_secret("AUTHENTICATED_OK", derived_key)
        verifier_blob = f"{v_nonce}:{v_cipher}"
        b64_salt = base64.b64encode(salt).decode("utf-8")

        with self._get_conn() as conn:
            conn.execute(
                "INSERT INTO _vault_meta (id, salt, verifier) VALUES (1, ?, ?)",
                (b64_salt, verifier_blob),
            )
            conn.commit()

        return derived_key

    def unlock(self, master_password: str) -> bytes:
        """Authenticates master password and returns derived AES-256 key."""
        if not self.is_initialized():
            raise VaultError("Vault is not initialized. Run 'init' first.")

        with self._get_conn() as conn:
            meta = conn.execute("SELECT salt, verifier FROM _vault_meta WHERE id = 1").fetchone()

        salt = base64.b64decode(meta["salt"])
        derived_key = derive_key(master_password, salt)

        v_nonce, v_cipher = meta["verifier"].split(":", 1)
        try:
            check = decrypt_secret(v_nonce, v_cipher, derived_key)
            if check != "AUTHENTICATED_OK":
                raise AuthenticationError("Incorrect master password.")
        except InvalidTag:
            raise AuthenticationError("Incorrect master password or corrupted vault verifier.")

        return derived_key

    def add_secret(
        self,
        key: bytes,
        service: str,
        username: str,
        password: str,
        notes: str = "",
    ) -> None:
        """Encrypts and stores a new credential entry."""
        nonce, ciphertext = encrypt_secret(password, key)
        now = datetime.now().isoformat()

        with self._get_conn() as conn:
            conn.execute(
                """
                INSERT INTO secrets (service, username, nonce, ciphertext, notes, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(service, username) DO UPDATE SET
                    nonce=excluded.nonce,
                    ciphertext=excluded.ciphertext,
                    notes=excluded.notes,
                    updated_at=excluded.updated_at
                """,
                (service.lower(), username, nonce, ciphertext, notes, now, now),
            )
            conn.commit()

    def get_secret(self, key: bytes, service: str, username: Optional[str] = None) -> Optional[Dict]:
        """Retrieves and decrypts a secret entry by service name."""
        with self._get_conn() as conn:
            if username:
                row = conn.execute(
                    "SELECT service, username, nonce, ciphertext, notes, updated_at FROM secrets WHERE service = ? AND username = ?",
                    (service.lower(), username),
                ).fetchone()
            else:
                row = conn.execute(
                    "SELECT service, username, nonce, ciphertext, notes, updated_at FROM secrets WHERE service = ?",
                    (service.lower(),),
                ).fetchone()

        if not row:
            return None

        decrypted_password = decrypt_secret(row["nonce"], row["ciphertext"], key)
        return {
            "service": row["service"],
            "username": row["username"],
            "password": decrypted_password,
            "notes": row["notes"] or "",
            "updated_at": row["updated_at"],
        }

    def list_secrets(self) -> List[Dict]:
        """Returns metadata of all stored secrets without decrypting passwords."""
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT id, service, username, updated_at FROM secrets ORDER BY service ASC"
            ).fetchall()
            return [
                {"id": r["id"], "service": r["service"], "username": r["username"], "updated_at": r["updated_at"]}
                for r in rows
            ]

    def delete_secret(self, service: str, username: Optional[str] = None) -> bool:
        """Deletes a secret entry from the vault."""
        with self._get_conn() as conn:
            if username:
                cur = conn.execute(
                    "DELETE FROM secrets WHERE service = ? AND username = ?",
                    (service.lower(), username),
                )
            else:
                cur = conn.execute(
                    "DELETE FROM secrets WHERE service = ?",
                    (service.lower(),),
                )
            conn.commit()
            return cur.rowcount > 0

    def audit_passwords(self, key: bytes) -> Dict:
        """Performs a comprehensive security health audit on all stored credentials."""
        with self._get_conn() as conn:
            rows = conn.execute("SELECT service, username, nonce, ciphertext FROM secrets").fetchall()

        total = len(rows)
        weak_count = 0
        passwords_map: Dict[str, List[str]] = {}
        entries_audit = []

        for r in rows:
            pwd = decrypt_secret(r["nonce"], r["ciphertext"], key)
            eval_res = evaluate_password_strength(pwd)
            service_id = f"{r['service']} ({r['username']})"

            if pwd not in passwords_map:
                passwords_map[pwd] = []
            passwords_map[pwd].append(service_id)

            if eval_res["strength"] in ("VERY_WEAK", "WEAK"):
                weak_count += 1

            entries_audit.append({
                "service": r["service"],
                "username": r["username"],
                "strength": eval_res["strength"],
                "entropy_bits": eval_res["entropy_bits"],
                "length": eval_res["length"],
            })

        reused = {pwd: svcs for pwd, svcs in passwords_map.items() if len(svcs) > 1}

        return {
            "total_secrets": total,
            "weak_passwords": weak_count,
            "reused_passwords_count": len(reused),
            "reused_groups": [svcs for svcs in reused.values()],
            "entries": entries_audit,
        }
