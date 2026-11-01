"""Integration tests for Vault database and credential management."""

import pytest
from src.vault import AuthenticationError, Vault, VaultError


@pytest.fixture
def temp_vault(tmp_path):
    db_file = tmp_path / "test_vault.db"
    return Vault(db_file)


def test_vault_lifecycle(temp_vault):
    assert temp_vault.is_initialized() is False

    master = "PiyushMasterKey2026!"
    key = temp_vault.initialize(master)
    assert temp_vault.is_initialized() is True

    # Re-initialization should fail
    with pytest.raises(VaultError):
        temp_vault.initialize(master)

    # Unlock with correct key
    unlocked_key = temp_vault.unlock(master)
    assert key == unlocked_key

    # Unlock with wrong key should fail
    with pytest.raises(AuthenticationError):
        temp_vault.unlock("WrongPassword123")


def test_secret_crud_and_audit(temp_vault):
    master = "SecretMasterPassword"
    key = temp_vault.initialize(master)

    # Add secrets
    temp_vault.add_secret(key, "github", "user1", "ghp_securetoken123", "github notes")
    temp_vault.add_secret(key, "gmail", "user1", "ghp_securetoken123", "reused password")
    temp_vault.add_secret(key, "bank", "user1", "12345", "weak pin")

    # Retrieve secret
    retrieved = temp_vault.get_secret(key, "github")
    assert retrieved is not None
    assert retrieved["password"] == "ghp_securetoken123"
    assert retrieved["notes"] == "github notes"

    # List secrets
    secrets_list = temp_vault.list_secrets()
    assert len(secrets_list) == 3

    # Audit check
    audit_report = temp_vault.audit_passwords(key)
    assert audit_report["total_secrets"] == 3
    assert audit_report["weak_passwords"] >= 1  # "12345" is weak
    assert audit_report["reused_passwords_count"] == 1  # github and gmail reuse same password

    # Delete secret
    deleted = temp_vault.delete_secret("bank")
    assert deleted is True
    assert len(temp_vault.list_secrets()) == 2
