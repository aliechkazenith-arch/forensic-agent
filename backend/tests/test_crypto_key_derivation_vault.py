"""Unit and adversarial regression tests for Cryptographic Key Derivation & Vault Envelope Encryption (Phase 14.3)."""

import base64
import json
from pathlib import Path
import pytest

from backend.app.core.crypto import (
    generate_salt,
    generate_nonce,
    derive_key_pbkdf2,
    derive_key_argon2id,
    derive_key,
    AESGCMVaultCipher,
    encrypt_vault_payload,
    decrypt_vault_payload,
    export_encrypted_vault,
    import_encrypted_vault,
)
from backend.app.core.exceptions import (
    CredentialEncryptionError,
    CryptographicTamperError,
)
from backend.app.db.sqlite_store import LLMStateStore


def test_salt_and_nonce_generation_entropy():
    """Verify salts and nonces are cryptographically random and conform to required lengths."""
    s1 = generate_salt(16)
    s2 = generate_salt(16)
    assert len(s1) == 16
    assert len(s2) == 16
    assert s1 != s2, "Salts must be randomly generated (zero hardcoded salts)"

    n1 = generate_nonce(12)
    n2 = generate_nonce(12)
    assert len(n1) == 12
    assert len(n2) == 12
    assert n1 != n2, "Nonces must be random and unique per encryption"

    with pytest.raises(ValueError, match="Salt length must be at least 16 bytes"):
        generate_salt(8)

    with pytest.raises(ValueError, match="AES-GCM requires a 12-byte"):
        generate_nonce(16)


def test_pbkdf2_key_derivation_deterministic_and_unique():
    """Verify PBKDF2-HMAC-SHA256 generates consistent 256-bit keys and varies with salt/passphrase."""
    salt = generate_salt(16)
    k1 = derive_key_pbkdf2("master_key_alpha", salt, iterations=100000)
    k2 = derive_key_pbkdf2("master_key_alpha", salt, iterations=100000)
    k3 = derive_key_pbkdf2("master_key_beta", salt, iterations=100000)
    k4 = derive_key_pbkdf2("master_key_alpha", generate_salt(16), iterations=100000)

    assert len(k1) == 32
    assert k1 == k2, "Same passphrase and salt must yield identical keys"
    assert k1 != k3, "Different passphrase must yield distinct key"
    assert k1 != k4, "Different salt must yield distinct key"


def test_pbkdf2_security_constraints():
    """Verify fail-closed input validation for PBKDF2."""
    salt = generate_salt(16)
    with pytest.raises(ValueError, match="Passphrase must be a non-empty string"):
        derive_key_pbkdf2("", salt)

    with pytest.raises(ValueError, match="Salt must be at least 16 bytes"):
        derive_key_pbkdf2("valid_passphrase", b"too_short")

    with pytest.raises(ValueError, match="below minimum security threshold"):
        derive_key_pbkdf2("valid_passphrase", salt, iterations=50000)


def test_argon2id_key_derivation():
    """Verify Argon2id key derivation operates correctly and derives 32-byte keys."""
    salt = generate_salt(16)
    key = derive_key_argon2id("argon2_passphrase", salt, iterations=1, memory_cost=65536)
    assert len(key) == 32
    assert isinstance(key, bytes)


def test_generic_derive_key_dispatcher():
    """Verify generic derive_key supports both pbkdf2 and argon2id."""
    salt = generate_salt(16)
    key_p, meta_p = derive_key("passphrase_p", salt, kdf="pbkdf2", iterations=100000)
    assert len(key_p) == 32
    assert meta_p["kdf"] == "pbkdf2"

    key_a, meta_a = derive_key("passphrase_a", salt, kdf="argon2id", iterations=1, memory_cost=65536)
    assert len(key_a) == 32
    assert meta_a["kdf"] == "argon2id"


def test_aes_gcm_envelope_encryption_roundtrip():
    """Verify AES-256-GCM envelope encryption and decryption for dict, string, and raw bytes."""
    passphrase = "UltraSecurePassphrase2026!"

    # 1. Dictionary payload
    dict_payload = {
        "case_id": "case-forensic-001",
        "hashes": ["abc", "def"],
        "metadata": {"analyst": "sec_agent", "verified": True},
    }
    envelope = AESGCMVaultCipher.encrypt(dict_payload, passphrase, kdf="pbkdf2", iterations=100000)
    assert envelope["algorithm"] == "AES-256-GCM"
    assert envelope["kdf"] == "pbkdf2"
    assert "salt" in envelope and "nonce" in envelope and "ciphertext" in envelope

    decrypted_bytes = AESGCMVaultCipher.decrypt(envelope, passphrase)
    decrypted_dict = json.loads(decrypted_bytes.decode("utf-8"))
    assert decrypted_dict == dict_payload

    # 2. String payload
    str_payload = "Forensic artifact raw text log observation."
    str_env = encrypt_vault_payload(str_payload, passphrase, iterations=100000)
    assert decrypt_vault_payload(str_env, passphrase).decode("utf-8") == str_payload

    # 3. JSON envelope format
    json_envelope = AESGCMVaultCipher.encrypt_to_json(dict_payload, passphrase, iterations=100000)
    assert isinstance(json_envelope, str)
    dec_from_json = AESGCMVaultCipher.decrypt_from_json(json_envelope, passphrase)
    assert json.loads(dec_from_json.decode("utf-8")) == dict_payload


def test_aes_gcm_tamper_detection():
    """Verify fail-closed behavior on corrupted ciphertexts, nonces, salts, and wrong keys."""
    passphrase = "CorrectPassphrase!"
    envelope = AESGCMVaultCipher.encrypt({"status": "confidential"}, passphrase, iterations=100000)

    # 1. Wrong passphrase
    with pytest.raises(CryptographicTamperError, match="Authentication tag mismatch"):
        AESGCMVaultCipher.decrypt(envelope, "IncorrectPassphrase!")

    # 2. Tampered ciphertext (1 bit flip)
    ct = bytearray(base64.b64decode(envelope["ciphertext"]))
    ct[4] ^= 0x01
    bad_ct_env = dict(envelope, ciphertext=base64.b64encode(ct).decode("ascii"))
    with pytest.raises(CryptographicTamperError, match="Authentication tag mismatch"):
        AESGCMVaultCipher.decrypt(bad_ct_env, passphrase)

    # 3. Tampered nonce
    nonce = bytearray(base64.b64decode(envelope["nonce"]))
    nonce[0] ^= 0xFF
    bad_nonce_env = dict(envelope, nonce=base64.b64encode(nonce).decode("ascii"))
    with pytest.raises(CryptographicTamperError, match="Authentication tag mismatch"):
        AESGCMVaultCipher.decrypt(bad_nonce_env, passphrase)

    # 4. Tampered salt
    salt = bytearray(base64.b64decode(envelope["salt"]))
    salt[0] ^= 0x42
    bad_salt_env = dict(envelope, salt=base64.b64encode(salt).decode("ascii"))
    with pytest.raises(CryptographicTamperError, match="Authentication tag mismatch"):
        AESGCMVaultCipher.decrypt(bad_salt_env, passphrase)

    # 5. Truncated ciphertext (shorter than 16-byte tag)
    bad_trunc_env = dict(envelope, ciphertext=base64.b64encode(b"short").decode("ascii"))
    with pytest.raises(CryptographicTamperError, match="Tamper detected: Ciphertext is shorter"):
        AESGCMVaultCipher.decrypt(bad_trunc_env, passphrase)


def test_vault_export_and_import_lifecycle(tmp_path):
    """Verify end-to-end SQLite database encrypted export and authenticated import."""
    db_source_path = tmp_path / "source.db"
    export_path = tmp_path / "vault_backup.json"
    db_restored_path = tmp_path / "restored.db"

    passphrase = "MasterVaultExportPassphrase42!"

    # 1. Populate source store
    store1 = LLMStateStore(db_source_path)
    store1.set_active_provider_id("ollama")
    store1.create_or_update_case({
        "case_id": "case-vault-export-01",
        "case_name": "Intrusion Analysis Vault",
        "organization_name": "ForensicOps Corp",
        "lead_analyst": "analyst_alice",
        "active_provider_id": "ollama",
    })

    # 2. Export encrypted vault
    out_path = store1.export_encrypted_vault(export_path, passphrase, iterations=100000)
    assert Path(out_path).exists()

    # 3. Import into a new store
    store2 = LLMStateStore(db_restored_path)
    assert store2.get_active_provider_id() == "lm_studio_local"

    summary = store2.import_encrypted_vault(export_path, passphrase)
    assert summary["status"] == "success"

    # 4. Validate restored database state
    assert store2.get_active_provider_id() == "ollama"
    restored_case = store2.get_case("case-vault-export-01")
    assert restored_case is not None
    assert restored_case["case_name"] == "Intrusion Analysis Vault"
    assert restored_case["lead_analyst"] == "analyst_alice"

    # 5. Attempt import with wrong passphrase
    with pytest.raises(CryptographicTamperError):
        store2.import_encrypted_vault(export_path, "WrongPassphrase123")

    # 6. Attempt import of tampered export file
    tampered_export = tmp_path / "tampered_export.json"
    raw_env = json.loads(export_path.read_text(encoding="utf-8"))
    ct_bytes = bytearray(base64.b64decode(raw_env["ciphertext"]))
    ct_bytes[8] ^= 0x77
    raw_env["ciphertext"] = base64.b64encode(ct_bytes).decode("ascii")
    tampered_export.write_text(json.dumps(raw_env), encoding="utf-8")

    with pytest.raises(CryptographicTamperError):
        store2.import_encrypted_vault(tampered_export, passphrase)

    store1.close()
    store2.close()
