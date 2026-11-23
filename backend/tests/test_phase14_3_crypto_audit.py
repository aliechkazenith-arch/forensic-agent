"""Comprehensive Adversarial Security Test Suite for Phase 14.3: Cryptography & Audit Hash Chains.

Standards & Acceptance Criteria:
1. Key Derivation:
   - PBKDF2-HMAC-SHA256 meets OWASP guidelines (work factor >= 100k, default 600k iterations).
   - Zero hardcoded salts/nonces: salts and nonces strictly derive from OS CSPRNG.
   - Argon2id supported or gracefully falls back to PBKDF2.
2. AES-256-GCM Envelope Encryption:
   - Authenticated encryption round-trip with structured payload.
   - Fail-closed tamper detection on invalid passphrase, corrupted ciphertext, truncated tag.
3. Vault Database Export/Import:
   - Atomically exports SQLite database to encrypted vault file.
   - Decrypts and restores cleanly with valid passphrase.
   - Fails closed with CryptographicTamperError on wrong passphrase or tampered package.
4. Audit Log Hash Chain & Tamper Evidence:
   - Sequential HMAC-SHA256 hash chain rooted at GENESIS_HASH ("0"*64).
   - Verifies consumed_approval_tokens and approval_audit_log chains sequentially.
   - Detects row data mutation (target, actor, timestamp).
   - Detects middle row deletion (broken chain link).
   - Detects genesis block tampering and corrupted hash links.
5. Preserves Phase 14.1 Two-Person Rule and token verification contract.
"""
from __future__ import annotations

import base64
import json
import os
import sqlite3
from pathlib import Path
from typing import Any, Dict
from uuid import uuid4
import pytest

from backend.app.core.crypto import (
    ARGON2_AVAILABLE,
    DEFAULT_NONCE_LENGTH,
    DEFAULT_PBKDF2_ITERATIONS,
    DEFAULT_SALT_LENGTH,
    KEY_LENGTH_BYTES,
    MIN_PBKDF2_ITERATIONS,
    AESGCMVaultCipher,
    derive_key,
    derive_key_argon2id,
    derive_key_pbkdf2,
    export_encrypted_vault,
    generate_nonce,
    generate_salt,
    import_encrypted_vault,
)
from backend.app.core.approval_engine import (
    ApprovalEngine,
    GENESIS_HASH,
    canonicalize_approval_audit_data,
    canonicalize_consumed_token_data,
    compute_record_hmac,
    generate_secure_approval_token,
    verify_approval_audit_chain,
    verify_consumed_tokens_chain,
)
from backend.app.core.exceptions import (
    CredentialEncryptionError,
    CryptographicTamperError,
    ForensicOpsError,
    UnauthorizedCollectorExecutionError,
)
from backend.app.db.sqlite_store import LLMStateStore
from backend.app.models.approval import compute_parameter_digest
from backend.app.models.workflow import HumanApprovalToken


@pytest.fixture
def crypto_audit_env(tmp_path: Path):
    """Isolated hermetic test environment for cryptographic and audit chain tests."""
    secret_key = "test-phase14-3-secret-key-for-hmac-32b!!"
    old_secret = os.environ.get("HUMAN_APPROVAL_HMAC_SECRET")
    os.environ["HUMAN_APPROVAL_HMAC_SECRET"] = secret_key

    db_path = tmp_path / "test_crypto_audit.db"
    store = LLMStateStore(db_path=db_path)
    engine = ApprovalEngine(state_store=store, secret_key=secret_key)

    yield {
        "tmp_path": tmp_path,
        "db_path": db_path,
        "store": store,
        "engine": engine,
        "secret_key": secret_key,
    }

    if old_secret is not None:
        os.environ["HUMAN_APPROVAL_HMAC_SECRET"] = old_secret
    else:
        os.environ.pop("HUMAN_APPROVAL_HMAC_SECRET", None)


# ==============================================================================
# Group 1: Key Derivation & AES-256-GCM Envelope Encryption Adversarial Tests
# ==============================================================================

def test_pbkdf2_key_derivation_adversarial():
    """Verify PBKDF2-HMAC-SHA256 key derivation constraints, determinism, and entropy."""
    salt1 = generate_salt(16)
    salt2 = generate_salt(16)
    assert salt1 != salt2, "Generated salts must be cryptographically distinct"

    passphrase = "Investigator-Strong-Master-Key-2026!#"

    # Deterministic derivation
    key1 = derive_key_pbkdf2(passphrase, salt1, iterations=100000)
    key1_again = derive_key_pbkdf2(passphrase, salt1, iterations=100000)
    assert key1 == key1_again
    assert len(key1) == 32

    # Distinct salt produces distinct key
    key2 = derive_key_pbkdf2(passphrase, salt2, iterations=100000)
    assert key1 != key2

    # Strict rejection of weak work factor (< 100k)
    with pytest.raises(ValueError, match="below minimum security threshold"):
        derive_key_pbkdf2(passphrase, salt1, iterations=99999)

    # Strict rejection of weak/empty inputs
    with pytest.raises(ValueError, match="Passphrase must be a non-empty string"):
        derive_key_pbkdf2("", salt1)

    with pytest.raises(ValueError, match="Salt must be at least 16 bytes"):
        derive_key_pbkdf2(passphrase, b"too-short-salt")


def test_argon2id_key_derivation_and_fallback():
    """Verify Argon2id memory-hard derivation if installed, or fallback via derive_key."""
    salt = generate_salt(16)
    passphrase = "Investigator-Argon2-Test-Key-2026!"

    if ARGON2_AVAILABLE:
        key = derive_key_argon2id(passphrase, salt, iterations=2, memory_cost=65536, lanes=4)
        assert len(key) == 32
        # Deterministic
        key_again = derive_key_argon2id(passphrase, salt, iterations=2, memory_cost=65536, lanes=4)
        assert key == key_again
    else:
        with pytest.raises(NotImplementedError):
            derive_key_argon2id(passphrase, salt)

    # General derive_key dispatcher gracefully falls back to PBKDF2 if Argon2id unavailable
    key, meta = derive_key(passphrase, salt, kdf="pbkdf2", iterations=100000)
    assert len(key) == 32
    assert meta["kdf"] == "pbkdf2"


def test_aes_gcm_envelope_adversarial_tamper_detection():
    """Verify AES-256-GCM envelope encryption fails closed on all forms of tampering."""
    passphrase = "Super-Secure-Vault-Passphrase-2026!"
    secret_payload = {
        "target": "10.0.0.45",
        "command": "Get-WinEvent -ListLog *",
        "analyst": "lead_hunter",
        "evidence_id": str(uuid4()),
    }

    envelope = AESGCMVaultCipher.encrypt(
        secret_payload,
        passphrase,
        kdf="pbkdf2",
        iterations=100000,
    )
    assert envelope["algorithm"] == "AES-256-GCM"
    assert envelope["kdf"] == "pbkdf2"
    assert "salt" in envelope
    assert "nonce" in envelope
    assert "ciphertext" in envelope

    # 1. Valid decryption round-trip
    decrypted_bytes = AESGCMVaultCipher.decrypt(envelope, passphrase)
    decrypted_json = json.loads(decrypted_bytes.decode("utf-8"))
    assert decrypted_json == secret_payload

    # 2. Tamper: Wrong passphrase fails with CryptographicTamperError
    with pytest.raises(CryptographicTamperError, match="Authentication tag mismatch|tamper detected"):
        AESGCMVaultCipher.decrypt(envelope, "Incorrect-Wrong-Passphrase-999!")

    # 3. Tamper: Bit flip in ciphertext
    ct_bytes = bytearray(base64.b64decode(envelope["ciphertext"]))
    ct_bytes[0] ^= 0x01  # Single bit flip
    tampered_envelope = dict(envelope)
    tampered_envelope["ciphertext"] = base64.b64encode(ct_bytes).decode("ascii")

    with pytest.raises(CryptographicTamperError, match="Authentication tag mismatch|tamper detected"):
        AESGCMVaultCipher.decrypt(tampered_envelope, passphrase)

    # 4. Tamper: Truncate authentication tag (< 16 bytes)
    truncated_envelope = dict(envelope)
    truncated_envelope["ciphertext"] = base64.b64encode(b"short").decode("ascii")
    with pytest.raises(CryptographicTamperError, match="Tamper detected: Ciphertext is shorter"):
        AESGCMVaultCipher.decrypt(truncated_envelope, passphrase)

    # 5. Tamper: Malformed base64
    malformed_envelope = dict(envelope)
    malformed_envelope["nonce"] = "!!!not-valid-base64!!!"
    with pytest.raises(CredentialEncryptionError, match="Malformed base64"):
        AESGCMVaultCipher.decrypt(malformed_envelope, passphrase)

    # 6. Tamper: Missing required fields
    missing_envelope = dict(envelope)
    del missing_envelope["salt"]
    with pytest.raises(CredentialEncryptionError, match="Missing mandatory envelope field"):
        AESGCMVaultCipher.decrypt(missing_envelope, passphrase)


def test_vault_export_and_import_lifecycle(crypto_audit_env: Dict[str, Any]):
    """Verify full encrypted vault export and import round-trip and tamper resistance."""
    store: LLMStateStore = crypto_audit_env["store"]
    tmp_path: Path = crypto_audit_env["tmp_path"]
    passphrase = "Vault-Export-Passphrase-2026-Production!"

    # Populate store with test cases and findings
    store.create_or_update_case({
        "case_id": "CASE-EXPORT-TEST",
        "case_name": "Classified Export Test Case",
        "status": "OPEN",
        "lead_analyst": "lead_owner",
        "organization_name": "ForensicOps Lab",
    })

    export_path = tmp_path / "vault_backup.enc"
    res_path = export_encrypted_vault(store, export_path, passphrase, iterations=100000)
    assert res_path.exists()
    assert res_path.stat().st_size > 0

    # Test import into a fresh isolated SQLite database
    new_db_path = tmp_path / "imported_vault.db"
    new_store = LLMStateStore(db_path=new_db_path)
    meta = import_encrypted_vault(new_store, export_path, passphrase)
    assert meta["status"] == "success"

    # Verify case was restored cleanly
    restored_case = new_store.get_case("CASE-EXPORT-TEST")
    assert restored_case is not None
    assert restored_case["case_name"] == "Classified Export Test Case"

    # Test Tamper on export file: Attempt import with wrong passphrase fails
    with pytest.raises(CryptographicTamperError):
        import_encrypted_vault(new_store, export_path, "Wrong-Passphrase-Fails!")

    # Test Tamper on export file: Corrupt payload bytes fails closed
    corrupted_path = tmp_path / "corrupted_vault.enc"
    raw_content = json.loads(export_path.read_text(encoding="utf-8"))
    ct = bytearray(base64.b64decode(raw_content["ciphertext"]))
    ct[5] ^= 0xFF
    raw_content["ciphertext"] = base64.b64encode(ct).decode("ascii")
    corrupted_path.write_text(json.dumps(raw_content), encoding="utf-8")

    with pytest.raises(CryptographicTamperError):
        import_encrypted_vault(new_store, corrupted_path, passphrase)


# ==============================================================================
# Group 2: Sequential HMAC-SHA256 Hash Chain Generation & Verification
# ==============================================================================

def test_approval_audit_log_sequential_hash_chain(crypto_audit_env: Dict[str, Any]):
    """Verify sequential HMAC-SHA256 hash chain generation across approval lifecycle transitions."""
    engine: ApprovalEngine = crypto_audit_env["engine"]
    case_id = "CASE-HASH-CHAIN-01"

    # 1. Initially empty: verification returns True
    ok, err = engine.verify_approval_audit_chain()
    assert ok is True
    assert err is None

    # 2. Trigger lifecycle events generating audit entries
    req = engine.create_request(
        case_id=case_id,
        requesting_investigator="soc_analyst_01",
        action_type="ssh_collector",
        target="10.10.10.50",
        capability_id="ssh_collector",
        parameters={"host": "10.10.10.50", "port": 22},
        reason="Acquire triage volatile memory from compromised Linux host",
        requesting_principal_id="user-analyst-1",
    )
    assert req.approval_id is not None

    # Second event: approve request
    appr_res = engine.approve_request(
        approval_id=req.approval_id,
        approver={
            "username": "lead_investigator_01",
            "role": "lead_investigator",
            "id": "user-lead-1",
            "badge_id": "BADGE-LEAD-01",
        },
    )
    token = appr_res.token

    # Third event: consume token
    engine.verify_and_consume_token(
        token=token,
        expected_case_id=case_id,
        expected_action_type=token.action_type,
        expected_target="10.10.10.50",
        expected_parameters={"host": "10.10.10.50", "port": 22},
        consumed_by="controller:workflow_runner",
    )

    # 3. Direct DB Inspection: verify genesis block and sequential links
    conn = engine.state_store._conn
    cur = conn.execute(
        "SELECT id, event_id, action, previous_hash, current_hash FROM approval_audit_log ORDER BY id ASC"
    )
    rows = cur.fetchall()
    assert len(rows) >= 3, "Expected at least 3 audit log entries for create, approve, and consume"

    # Row 1 must have GENESIS_HASH ("0"*64) as previous_hash
    assert rows[0][3] == GENESIS_HASH
    assert len(rows[0][4]) == 64

    # Every subsequent row must link previous_hash to previous row's current_hash
    for i in range(1, len(rows)):
        prev_curr_hash = rows[i - 1][4]
        curr_prev_hash = rows[i][3]
        assert curr_prev_hash == prev_curr_hash, f"Row {rows[i][0]} broken link: expected {prev_curr_hash}, got {curr_prev_hash}"

    # 4. Engine verification must succeed
    valid, err_msg = engine.verify_approval_audit_chain()
    assert valid is True
    assert err_msg is None

    # Module-level wrapper verification
    mod_valid, mod_err = verify_approval_audit_chain(engine)
    assert mod_valid is True
    assert mod_err is None


def test_consumed_tokens_sequential_hash_chain(crypto_audit_env: Dict[str, Any]):
    """Verify sequential HMAC-SHA256 hash chain generation for consumed_approval_tokens."""
    engine: ApprovalEngine = crypto_audit_env["engine"]
    secret_key: str = crypto_audit_env["secret_key"]
    case_id = "CASE-CONSUMED-CHAIN-01"

    # Generate and consume 3 distinct valid tokens
    for i in range(3):
        node_id = f"act-node-{i}"
        target = f"target-{i}"
        token = generate_secure_approval_token(
            node_id=node_id,
            case_id=case_id,
            secret_key=secret_key,
            action_type="winrm_collector",
            target=target,
            issued_by="lead_investigator_01",
        )
        engine.consume_token(
            token_id=token.token_id,
            case_id=case_id,
            action_type="winrm_collector",
            target=target,
            consumed_by=f"worker-{i}",
        )

    # Direct DB Inspection
    conn = engine.state_store._conn
    cur = conn.execute(
        "SELECT rowid, token_id, previous_hash, current_hash FROM consumed_approval_tokens ORDER BY rowid ASC"
    )
    rows = cur.fetchall()
    assert len(rows) == 3

    # Row 1 must have GENESIS_HASH
    assert rows[0][2] == GENESIS_HASH
    assert rows[1][2] == rows[0][3]
    assert rows[2][2] == rows[1][3]

    # Verification must succeed
    valid, err = engine.verify_consumed_tokens_chain()
    assert valid is True
    assert err is None

    # Module-level wrapper verification
    mod_valid, mod_err = verify_consumed_tokens_chain(engine)
    assert mod_valid is True
    assert mod_err is None


# ==============================================================================
# Group 3: Adversarial Tamper Detection & Broken Link Verification
# ==============================================================================

def test_audit_log_tamper_detection_field_mutation(crypto_audit_env: Dict[str, Any]):
    """Verify tamper detection catches unauthorized mutation of historical audit log fields."""
    engine: ApprovalEngine = crypto_audit_env["engine"]
    case_id = "CASE-TAMPER-MUTATION"

    # Create multiple requests to populate chain
    for i in range(3):
        engine.create_request(
            case_id=case_id,
            requesting_investigator=f"analyst_{i}",
            action_type="ssh_collector",
            target=f"10.0.0.{10 + i}",
            capability_id="ssh_collector",
            parameters={"port": 22},
            reason="Investigation access",
        )

    # Baseline: Chain is valid
    ok, _ = engine.verify_approval_audit_chain()
    assert ok is True

    conn = engine.state_store._conn

    # Adversarial Attack 1: Mutate target in row 2 directly in SQLite
    conn.execute("UPDATE approval_audit_log SET target = '10.0.0.99' WHERE id = 2")
    conn.commit()

    tampered, err = engine.verify_approval_audit_chain()
    assert tampered is False
    assert "Tamper detected at row 2" in err
    assert "current_hash mismatch" in err
    assert "Record data modified" in err

    # Revert target mutation
    conn.execute("UPDATE approval_audit_log SET target = '10.0.0.11' WHERE id = 2")
    conn.commit()

    # Adversarial Attack 2: Mutate timestamp in row 3
    conn.execute("UPDATE approval_audit_log SET timestamp_utc = '2020-01-01T00:00:00Z' WHERE id = 3")
    conn.commit()

    tampered2, err2 = engine.verify_approval_audit_chain()
    assert tampered2 is False
    assert "Tamper detected at row 3" in err2
    assert "current_hash mismatch" in err2


def test_audit_log_tamper_detection_row_deletion(crypto_audit_env: Dict[str, Any]):
    """Verify tamper detection catches unauthorized deletion of middle audit log entries."""
    engine: ApprovalEngine = crypto_audit_env["engine"]
    case_id = "CASE-TAMPER-DELETION"

    # Create 4 requests
    for i in range(4):
        engine.create_request(
            case_id=case_id,
            requesting_investigator=f"analyst_{i}",
            action_type="ssh_collector",
            target=f"10.0.0.{i}",
            capability_id="ssh_collector",
            parameters={"port": 22},
            reason="Deletion detection test",
        )

    # Baseline valid
    assert engine.verify_approval_audit_chain()[0] is True

    conn = engine.state_store._conn

    # Adversarial Attack: Malicious insider deletes row 2 to conceal an action
    conn.execute("DELETE FROM approval_audit_log WHERE id = 2")
    conn.commit()

    tampered, err = engine.verify_approval_audit_chain()
    assert tampered is False
    assert "Tamper detected at row 3" in err
    assert "previous_hash mismatch" in err
    assert "Chain broken or row deleted" in err


def test_audit_log_tamper_detection_corrupted_genesis_block(crypto_audit_env: Dict[str, Any]):
    """Verify tamper detection catches modification of genesis block anchor."""
    engine: ApprovalEngine = crypto_audit_env["engine"]
    case_id = "CASE-TAMPER-GENESIS"

    engine.create_request(
        case_id=case_id,
        requesting_investigator="analyst_genesis",
        action_type="ssh_collector",
        target="10.0.0.1",
        capability_id="ssh_collector",
        parameters={},
        reason="Genesis tamper test",
    )

    conn = engine.state_store._conn

    # Adversarial Attack: Modify genesis previous_hash away from GENESIS_HASH ("0"*64)
    fake_genesis = "f" * 64
    conn.execute("UPDATE approval_audit_log SET previous_hash = ? WHERE id = 1", (fake_genesis,))
    conn.commit()

    tampered, err = engine.verify_approval_audit_chain()
    assert tampered is False
    assert "Tamper detected at row 1" in err
    assert "previous_hash mismatch" in err


def test_consumed_tokens_tamper_detection_mutation_and_deletion(crypto_audit_env: Dict[str, Any]):
    """Verify tamper detection on consumed_approval_tokens catches mutation and row deletion."""
    engine: ApprovalEngine = crypto_audit_env["engine"]
    secret_key: str = crypto_audit_env["secret_key"]
    case_id = "CASE-CONSUMED-TAMPER"

    for i in range(3):
        t = generate_secure_approval_token(
            node_id=f"node-{i}",
            case_id=case_id,
            secret_key=secret_key,
            action_type="ssh_collector",
            target=f"target-{i}",
            issued_by="lead_investigator_01",
        )
        engine.consume_token(
            token_id=t.token_id,
            case_id=case_id,
            action_type="ssh_collector",
            target=f"target-{i}",
            consumed_by=f"worker-{i}",
        )

    # Baseline valid
    assert engine.verify_consumed_tokens_chain()[0] is True

    conn = engine.state_store._conn

    # Attack 1: Mutate consumed_by in row 2
    conn.execute("UPDATE consumed_approval_tokens SET consumed_by = 'rogue_attacker' WHERE rowid = 2")
    conn.commit()

    tampered, err = engine.verify_consumed_tokens_chain()
    assert tampered is False
    assert "Tamper detected at row 2" in err
    assert "current_hash mismatch" in err

    # Revert attack 1
    conn.execute("UPDATE consumed_approval_tokens SET consumed_by = 'worker-1' WHERE rowid = 2")
    conn.commit()
    assert engine.verify_consumed_tokens_chain()[0] is True

    # Attack 2: Delete row 2
    conn.execute("DELETE FROM consumed_approval_tokens WHERE rowid = 2")
    conn.commit()

    tampered2, err2 = engine.verify_consumed_tokens_chain()
    assert tampered2 is False
    assert "previous_hash mismatch" in err2
    assert "Chain broken or row deleted" in err2


# ==============================================================================
# Group 4: Two-Person Rule Preservation & Attribution Verification
# ==============================================================================

def test_two_person_rule_preserved_and_audit_attributed(crypto_audit_env: Dict[str, Any]):
    """Verify Two-Person Rule prevents self-approval and audit log records distinct principals."""
    engine: ApprovalEngine = crypto_audit_env["engine"]
    case_id = "CASE-TWO-PERSON-AUDIT"

    # Requester: analyst_user
    req = engine.create_request(
        case_id=case_id,
        requesting_investigator="soc_analyst_01",
        action_type="ssh_collector",
        target="192.168.1.100",
        capability_id="ssh_collector",
        parameters={"host": "192.168.1.100"},
        reason="Remote forensic triage",
        requesting_principal_id="principal-soc-01",
    )

    # Self-approval attempt: Same principal ID attempting approval MUST fail closed
    with pytest.raises((UnauthorizedCollectorExecutionError, ForensicOpsError), match=r"Self-approval rejected|Two-person rule"):
        engine.approve_request(
            approval_id=req.approval_id,
            approver={
                "username": "soc_analyst_01",
                "role": "soc_analyst",
                "id": "principal-soc-01",
            },
        )

    # Distinct principal: Chief lead investigator approves
    appr_res = engine.approve_request(
        approval_id=req.approval_id,
        approver={
            "username": "lead_investigator_chief",
            "role": "lead_investigator",
            "id": "principal-lead-99",
            "badge_id": "BADGE-LEAD-CHIEF",
        },
    )
    assert appr_res.token is not None

    # Inspect audit log: Request and Approval have distinct attributed principals
    logs = engine.get_approval_audit_logs(case_id=case_id, limit=10)
    actions = {l["action"]: l for l in logs}

    assert "APPROVAL_REQUEST_CREATED" in actions
    assert "APPROVAL_REQUEST_APPROVED" in actions

    assert actions["APPROVAL_REQUEST_CREATED"]["requesting_principal_id"] == "principal-soc-01"
    assert actions["APPROVAL_REQUEST_APPROVED"]["approving_principal_id"] in ("principal-lead-99", "lead_investigator_chief")

    # Chain remains 100% valid
    ok, _ = engine.verify_approval_audit_chain()
    assert ok is True
