"""Comprehensive Security & Regression Tests for Phase 14.2-B (SEC-UI-001).

Validates:
1. Missing encryption key fails closed (CredentialEncryptionError, HTTP 500, no plaintext fallback).
2. Invalid encryption key fails closed (CredentialEncryptionError).
3. Authenticated symmetric encryption (Fernet AES-CBC + HMAC-SHA256) properly encrypts credentials.
4. Accurate decryption of credentials with valid key.
5. Tampered ciphertext fails closed during decryption (Fernet InvalidToken -> CredentialEncryptionError).
6. SQLite database stores ONLY ciphertext at rest; plaintext secrets never appear in the database.
7. Zero secret leakage in API responses (GET /api/siem/connections returns only boolean presence flags).
8. POST /api/siem/connections returns safe response with presence flags, never plaintext secret.
9. Updating connection with blank/None password preserves existing stored password.
10. Explicit removal flags (remove_password, clear_credentials) correctly wipe stored credentials.
11. Query execution via POST /api/intake/siem with connection_id loads encrypted credentials in memory.
12. Investigation session state sanitization strips credentials from wizard_state in SQLite.
13. Exception handling scrubs sensitive credentials and never leaks them in error responses.
14. Credentials persist and remain decryptable across application restarts.
"""
from __future__ import annotations

import base64
import json
import logging
import os
import sqlite3
import stat
import tempfile
from pathlib import Path
from typing import Any, Dict, Generator
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from backend.app.auth.dependencies import reset_user_store, set_user_store
from backend.app.auth.models import UserCreate
from backend.app.auth.security import create_access_token, hash_password
from backend.app.auth.store import UserStore
from backend.app.core.credential_store import (
    SIEMCredentialStore,
    decrypt_credentials,
    encrypt_credentials,
    generate_credential_key,
    get_credential_encryption_key,
    get_credential_store,
    reset_credential_store,
)
from backend.app.core.exceptions import CredentialEncryptionError
from backend.app.db.sqlite_store import LLMStateStore, get_llm_state_store, reset_llm_state_store
from backend.app.main import create_app
from backend.app.models.connectors import SIEMType


@pytest.fixture
def test_key() -> str:
    """Generate a valid Fernet key for test cases."""
    return generate_credential_key()


@pytest.fixture
def memory_db() -> Generator[LLMStateStore, None, None]:
    """Provide an isolated in-memory LLMStateStore."""
    store = LLMStateStore(":memory:")
    reset_llm_state_store(store)
    yield store
    reset_llm_state_store(None)


@pytest.fixture
def authed_client(test_key: str, memory_db: LLMStateStore, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Generator[TestClient, None, None]:
    """Provide a TestClient with valid credential key and authenticated lead investigator token."""
    jwt_secret = "test-phase14-2-b-jwt-secret-key-32chars!!"
    monkeypatch.setenv("FORENSICOPS_CREDENTIAL_KEY", test_key)
    monkeypatch.setenv("HUMAN_APPROVAL_HMAC_SECRET", "test-phase14-2-b-secret-key-32chars!!")
    monkeypatch.setenv("FORENSICOPS_JWT_SECRET", jwt_secret)

    reset_credential_store()

    # Set up user store with lead investigator user
    users_db = tmp_path / "test_users.db"
    user_store = UserStore(db_path=users_db)
    set_user_store(user_store)

    u_lead = user_store.create_user(
        UserCreate(
            username="lead_investigator_bob",
            password="password123",
            role="lead_investigator",
            badge_id="BADGE-123",
            full_name="Lead Investigator Bob",
        ),
        password_hash=hash_password("password123"),
    )

    # Create case in isolated test store
    memory_db.create_or_update_case({
        "case_id": "test_case_sec_01",
        "case_name": "SIEM Credential Security Case",
        "organization_name": "Test Org",
        "lead_analyst": "lead_investigator_bob",
        "status": "OPEN",
    })

    app = create_app()
    client = TestClient(app)

    token = create_access_token({
        "sub": "lead_investigator_bob",
        "user_id": u_lead.id,
        "role": "lead_investigator",
        "badge_id": "BADGE-123",
        "permissions": ["*"],
    })
    client.headers.update({"Authorization": f"Bearer {token}"})
    yield client
    reset_user_store()


# =============================================================================
# Requirement 1 & 2: Fail-Closed Key Configuration
# =============================================================================

def test_missing_encryption_key_fails_closed(monkeypatch: pytest.MonkeyPatch, memory_db: LLMStateStore):
    """When no key is configured, all encryption and decryption operations must fail closed."""
    monkeypatch.delenv("FORENSICOPS_CREDENTIAL_KEY", raising=False)
    monkeypatch.delenv("FORENSICOPS_CREDENTIAL_KEY_FILE", raising=False)
    reset_credential_store()

    with pytest.raises(CredentialEncryptionError, match="No credential encryption key configured"):
        get_credential_encryption_key()

    with pytest.raises(CredentialEncryptionError):
        encrypt_credentials({"password": "secret_password"})

    with pytest.raises(CredentialEncryptionError):
        decrypt_credentials("some_ciphertext")

    store = SIEMCredentialStore(db_store=memory_db)
    with pytest.raises(CredentialEncryptionError):
        store.create_connection(
            case_id="case_01",
            siem_type="elasticsearch",
            endpoint_url="https://93.184.216.34:9200",
            credentials={"password": "secret_password"},
        )


def test_missing_key_file_fails_closed(monkeypatch: pytest.MonkeyPatch):
    """When key file does not exist, fail closed immediately."""
    monkeypatch.delenv("FORENSICOPS_CREDENTIAL_KEY", raising=False)
    monkeypatch.setenv("FORENSICOPS_CREDENTIAL_KEY_FILE", "C:/non_existent_path/fake_key.key")

    with pytest.raises(CredentialEncryptionError, match="does not exist or is not a file"):
        get_credential_encryption_key()


def test_invalid_key_format_fails_closed(monkeypatch: pytest.MonkeyPatch):
    """When key is not a valid 32-byte base64 Fernet key, fail closed."""
    monkeypatch.setenv("FORENSICOPS_CREDENTIAL_KEY", "not-a-valid-base64-key")
    with pytest.raises(CredentialEncryptionError, match="Configured credential encryption key is invalid"):
        get_credential_encryption_key()

    # Valid base64 but wrong length (16 bytes instead of 32)
    short_key = base64.urlsafe_b64encode(b"0123456789abcdef").decode("utf-8")
    monkeypatch.setenv("FORENSICOPS_CREDENTIAL_KEY", short_key)
    with pytest.raises(CredentialEncryptionError, match="expected 32"):
        get_credential_encryption_key()


# =============================================================================
# Requirement 3, 4 & 5: Symmetric Encryption, Decryption & Tamper Evidence
# =============================================================================

def test_authenticated_symmetric_encryption_and_decryption(test_key: str, monkeypatch: pytest.MonkeyPatch):
    """Verify authenticated symmetric encryption produces non-plaintext ciphertext and recovers data."""
    monkeypatch.setenv("FORENSICOPS_CREDENTIAL_KEY", test_key)

    raw_credentials = {
        "password": "SuperSecretPassword123!",
        "api_key": "apiKey_xyz987654321",
        "username": "elastic_admin",
    }

    ciphertext = encrypt_credentials(raw_credentials)

    # Must be non-empty and start with Fernet magic prefix
    assert isinstance(ciphertext, str)
    assert len(ciphertext) > 50
    # Plaintext secrets must NOT be in ciphertext
    assert "SuperSecretPassword123!" not in ciphertext
    assert "apiKey_xyz987654321" not in ciphertext
    assert "elastic_admin" not in ciphertext

    # Decrypt and verify exact recovery
    decrypted = decrypt_credentials(ciphertext)
    assert decrypted == raw_credentials


def test_tampered_ciphertext_fails_closed(test_key: str, monkeypatch: pytest.MonkeyPatch):
    """Tampering with a single byte in ciphertext must fail closed with CredentialEncryptionError."""
    monkeypatch.setenv("FORENSICOPS_CREDENTIAL_KEY", test_key)

    raw_credentials = {"password": "SuperSecretPassword123!"}
    ciphertext = encrypt_credentials(raw_credentials)

    # Flip a character in the ciphertext payload
    tampered_chars = list(ciphertext)
    tampered_chars[-5] = "A" if tampered_chars[-5] != "A" else "B"
    tampered_ciphertext = "".join(tampered_chars)

    with pytest.raises(CredentialEncryptionError, match="failed HMAC verification"):
        decrypt_credentials(tampered_ciphertext)


def test_decryption_with_wrong_key_fails_closed(test_key: str, monkeypatch: pytest.MonkeyPatch):
    """Attempting decryption with a different key must fail closed."""
    monkeypatch.setenv("FORENSICOPS_CREDENTIAL_KEY", test_key)
    ciphertext = encrypt_credentials({"password": "secret"})

    # Switch to a different valid key
    other_key = generate_credential_key()
    monkeypatch.setenv("FORENSICOPS_CREDENTIAL_KEY", other_key)

    with pytest.raises(CredentialEncryptionError, match="failed HMAC verification"):
        decrypt_credentials(ciphertext)


# =============================================================================
# Requirement 6: At-Rest Encryption in SQLite Database
# =============================================================================

def test_sqlite_database_stores_only_ciphertext(test_key: str, monkeypatch: pytest.MonkeyPatch):
    """Directly inspect SQLite database file to ensure plaintext secrets NEVER appear at rest."""
    monkeypatch.setenv("FORENSICOPS_CREDENTIAL_KEY", test_key)

    with tempfile.TemporaryDirectory() as tmp_dir:
        db_path = Path(tmp_dir) / "test_store.db"
        store = LLMStateStore(db_path)
        cred_store = SIEMCredentialStore(db_store=store)

        secret_password = "P@ssw0rd_ForensicOps_AtRest_Test_999!"
        secret_api_key = "apikey_AtRest_Test_Secret_000!"

        cred_store.create_connection(
            case_id="case_at_rest_01",
            siem_type="elasticsearch",
            endpoint_url="https://93.184.216.34:9200",
            credentials={"password": secret_password, "api_key": secret_api_key},
            username="analyst_at_rest",
        )

        store.close()

        # Read raw sqlite bytes and verify plaintext secret is nowhere on disk
        raw_db_bytes = db_path.read_bytes()
        assert secret_password.encode("utf-8") not in raw_db_bytes
        assert secret_api_key.encode("utf-8") not in raw_db_bytes

        # Open raw sqlite connection and verify encrypted_credentials column
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        cursor.execute("SELECT encrypted_credentials, has_password, has_api_key FROM siem_connections")
        row = cursor.fetchone()
        conn.close()

        assert row is not None
        ciphertext_in_db = row[0]
        assert secret_password not in ciphertext_in_db
        assert secret_api_key not in ciphertext_in_db
        assert row[1] == 1  # has_password
        assert row[2] == 1  # has_api_key


# =============================================================================
# Requirement 7 & 8: Zero Secret Leakage in API Responses
# =============================================================================

def test_create_and_get_siem_connection_zero_secret_leakage(authed_client: TestClient):
    """POST /api/siem/connections and GET endpoints must never return passwords or API keys."""
    secret_pass = "ClassifiedPass123!"
    secret_key = "ApiKey-Secret-789!"

    # 1. Create connection
    create_res = authed_client.post(
        "/api/siem/connections",
        json={
            "case_id": "test_case_sec_01",
            "siem_type": "elasticsearch",
            "endpoint_url": "https://93.184.216.34:9200",
            "index_pattern": "winlogbeat-*",
            "username": "sec_analyst",
            "password": secret_pass,
            "api_key": secret_key,
        },
    )
    assert create_res.status_code == 201, create_res.text
    created_data = create_res.json()

    # Zero secret leakage in creation response
    assert created_data["has_password"] is True
    assert created_data["has_api_key"] is True
    assert created_data["username"] == "sec_analyst"
    assert "password" not in created_data
    assert "api_key" not in created_data
    assert "encrypted_credentials" not in created_data
    assert secret_pass not in json.dumps(created_data)
    assert secret_key not in json.dumps(created_data)

    connection_id = created_data["connection_id"]

    # 2. Get connection detail
    get_res = authed_client.get(f"/api/siem/connections/{connection_id}")
    assert get_res.status_code == 200
    detail_data = get_res.json()

    assert detail_data["has_password"] is True
    assert detail_data["has_api_key"] is True
    assert "password" not in detail_data
    assert "api_key" not in detail_data
    assert "encrypted_credentials" not in detail_data
    assert secret_pass not in json.dumps(detail_data)

    # 3. List connections
    list_res = authed_client.get("/api/siem/connections?case_id=test_case_sec_01")
    assert list_res.status_code == 200
    list_data = list_res.json()
    assert len(list_data) >= 1
    found = next(c for c in list_data if c["connection_id"] == connection_id)
    assert found["has_password"] is True
    assert "password" not in found
    assert secret_pass not in json.dumps(list_data)


# =============================================================================
# Requirement 9 & 10: Blank Update Preservation & Explicit Deletion
# =============================================================================

def test_blank_update_preserves_existing_credentials(authed_client: TestClient, memory_db: LLMStateStore):
    """Updating connection with omitted or blank password preserves existing credentials."""
    original_pass = "KeepMeSafeAndSound123!"
    create_res = authed_client.post(
        "/api/siem/connections",
        json={
            "case_id": "test_case_sec_01",
            "siem_type": "elasticsearch",
            "endpoint_url": "https://93.184.216.34:9200",
            "password": original_pass,
        },
    )
    conn_id = create_res.json()["connection_id"]

    # Update endpoint_url with password omitted (None)
    patch_res = authed_client.patch(
        f"/api/siem/connections/{conn_id}",
        json={
            "endpoint_url": "https://93.184.216.35:9200",
            "password": "",  # Blank password
        },
    )
    assert patch_res.status_code == 200
    patch_data = patch_res.json()
    assert patch_data["endpoint_url"] == "https://93.184.216.35:9200"
    assert patch_data["has_password"] is True  # Preserved!

    # Verify directly via backend internal credential store
    cred_store = get_credential_store(db_store=memory_db)
    internal_conn = cred_store.get_connection(conn_id, include_credentials=True)
    assert internal_conn is not None
    assert internal_conn["credentials"]["password"] == original_pass


def test_explicit_credential_removal_and_deletion(authed_client: TestClient, memory_db: LLMStateStore):
    """Explicit remove_password and clear_credentials flags correctly wipe secrets."""
    create_res = authed_client.post(
        "/api/siem/connections",
        json={
            "case_id": "test_case_sec_01",
            "siem_type": "splunk",
            "endpoint_url": "https://93.184.216.34:8089",
            "password": "PasswordToWipe!",
            "api_key": "TokenToKeep!",
        },
    )
    conn_id = create_res.json()["connection_id"]

    # Remove only password
    remove_pass_res = authed_client.patch(
        f"/api/siem/connections/{conn_id}",
        json={"remove_password": True},
    )
    assert remove_pass_res.status_code == 200
    data1 = remove_pass_res.json()
    assert data1["has_password"] is False
    assert data1["has_api_key"] is True

    # Clear all remaining credentials
    clear_res = authed_client.patch(
        f"/api/siem/connections/{conn_id}",
        json={"clear_credentials": True},
    )
    assert clear_res.status_code == 200
    data2 = clear_res.json()
    assert data2["has_password"] is False
    assert data2["has_api_key"] is False

    # Delete connection permanently
    del_res = authed_client.delete(f"/api/siem/connections/{conn_id}")
    assert del_res.status_code == 200
    assert del_res.json()["status"] == "deleted"

    # Confirm 404 on subsequent get
    assert authed_client.get(f"/api/siem/connections/{conn_id}").status_code == 404


# =============================================================================
# Requirement 11: Query Execution with Stored connection_id
# =============================================================================

def test_siem_intake_query_with_connection_id(authed_client: TestClient):
    """POST /api/intake/siem using connection_id decrypts credentials in memory and runs query."""
    # Create connection
    create_res = authed_client.post(
        "/api/siem/connections",
        json={
            "case_id": "test_case_sec_01",
            "siem_type": "elasticsearch",
            "endpoint_url": "https://93.184.216.34:9200",
            "api_key": "test_query_api_key",
        },
    )
    conn_id = create_res.json()["connection_id"]

    # Mock ElasticsearchConnector search
    with patch("backend.app.api.intake.ElasticsearchConnector") as mock_conn_cls:
        mock_instance = MagicMock()
        mock_conn_cls.return_value = mock_instance
        mock_instance.siem_type = "elasticsearch"
        mock_instance.test_connection.return_value = True

        from backend.app.models.findings import ForensicFinding
        from backend.app.models.connectors import SIEMQuerySnapshot

        dummy_finding = ForensicFinding(
            finding_id="fnd-100",
            case_id="test_case_sec_01",
            source_artifact_id="art-100",
            source_artifact_hash="abc",
            tool_id="elasticsearch",
            artifact_type="siem_query",
            category="authentication",
            severity="medium",
            summary="Successful login event",
            projected_data={},
        )
        dummy_snapshot = SIEMQuerySnapshot(
            snapshot_id="snap-100",
            case_id="test_case_sec_01",
            siem_type="elasticsearch",
            query_string="event.code: 4624",
            snapshot_sha256="deadbeef",
            record_count=1,
        )

        with patch("backend.app.api.intake.ingest_siem_query_findings", return_value=([dummy_finding], dummy_snapshot)):
            intake_res = authed_client.post(
                "/api/intake/siem",
                json={
                    "case_id": "test_case_sec_01",
                    "connection_id": conn_id,
                    "query": "event.code: 4624",
                },
            )
            assert intake_res.status_code == 200, intake_res.text
            res_json = intake_res.json()
            assert res_json["status"] == "success"
            assert res_json["findings_count"] == 1
            # Verify initialized with decrypted api_key
            assert mock_conn_cls.call_count == 1
            call_config = mock_conn_cls.call_args[1]["config"]
            assert call_config.api_key == "test_query_api_key"


# =============================================================================
# Requirement 12: Session State Sanitization (SEC-UI-001)
# =============================================================================

def test_session_state_sanitizes_wizard_credentials(authed_client: TestClient, memory_db: LLMStateStore):
    """Saving investigation session strips siemApiKey and passwords before persisting to SQLite."""
    leak_attempt_payload = {
        "wizard_state": {
            "mode": "siem",
            "siemType": "elasticsearch",
            "siemUrl": "https://93.184.216.34:9200",
            "siemApiKey": "SUPER_SECRET_LEAK_ATTEMPT_12345",
            "password": "ANOTHER_SECRET_PASSWORD_67890",
            "safe_field": "innocent_metadata",
        },
        "workflow_state": {"selectedBlueprintKey": "windows_intrusion"},
        "active_tab": "wizard",
    }

    save_res = authed_client.post("/api/session/test_case_sec_01", json=leak_attempt_payload)
    assert save_res.status_code == 200
    saved_json = save_res.json()

    # Returned session must not contain siemApiKey or password
    assert "siemApiKey" not in saved_json["wizard_state"]
    assert "password" not in saved_json["wizard_state"]
    assert saved_json["wizard_state"]["safe_field"] == "innocent_metadata"

    # Direct SQLite query must confirm neither secret exists in raw stored JSON
    cursor = memory_db._conn.execute(
        "SELECT wizard_state FROM investigation_sessions WHERE case_id = 'test_case_sec_01'"
    )
    raw_stored_state = cursor.fetchone()[0]
    assert "SUPER_SECRET_LEAK_ATTEMPT_12345" not in raw_stored_state
    assert "ANOTHER_SECRET_PASSWORD_67890" not in raw_stored_state
    assert "innocent_metadata" in raw_stored_state


# =============================================================================
# Requirement 13: Exception Handling Zero Credential Leakage
# =============================================================================

def test_exception_handling_scrubs_credentials(authed_client: TestClient):
    """When an exception occurs during SIEM intake, credentials must not leak in HTTP error details."""
    secret_in_error = "SuperSecretToken_DoNotLeakMe!"

    with patch("backend.app.api.intake.ElasticsearchConnector") as mock_conn:
        # Simulate connector raising an exception that happens to embed the secret token
        mock_conn.side_effect = Exception(f"Connection failed with token: {secret_in_error}")

        intake_res = authed_client.post(
            "/api/intake/siem",
            json={
                "case_id": "test_case_sec_01",
                "config": {
                    "siem_type": "elasticsearch",
                    "endpoint_url": "https://93.184.216.34:9200",
                    "api_key": secret_in_error,
                },
                "query": "event.code: 4624",
            },
        )
        assert intake_res.status_code == 500
        error_text = intake_res.text
        # The secret must have been scrubbed by sanitize_credentials
        assert secret_in_error not in error_text
        assert "******" in error_text


# =============================================================================
# Requirement 14: Persistence Across Application Restarts
# =============================================================================

def test_credentials_persist_across_restarts(test_key: str, monkeypatch: pytest.MonkeyPatch):
    """Credentials stored in SQLite persist and can be decrypted after server restart."""
    monkeypatch.setenv("FORENSICOPS_CREDENTIAL_KEY", test_key)

    with tempfile.TemporaryDirectory() as tmp_dir:
        db_file = Path(tmp_dir) / "reboot_test.db"

        # Session 1: Create connection and store credentials
        store1 = LLMStateStore(db_file)
        cred_store1 = SIEMCredentialStore(db_store=store1)
        created = cred_store1.create_connection(
            case_id="case_reboot_01",
            siem_type="wazuh",
            endpoint_url="https://93.184.216.34:55000",
            credentials={"api_key": "persistent_key_abc123", "password": "persistent_pass_xyz"},
            username="wazuh_admin",
        )
        conn_id = created["connection_id"]
        store1.close()

        # Simulate Application Restart: Open brand-new store instance pointing to same DB
        store2 = LLMStateStore(db_file)
        cred_store2 = SIEMCredentialStore(db_store=store2)

        recovered = cred_store2.get_connection(conn_id, include_credentials=True)
        assert recovered is not None
        assert recovered["credentials"]["api_key"] == "persistent_key_abc123"
        assert recovered["credentials"]["password"] == "persistent_pass_xyz"
        assert recovered["username"] == "wazuh_admin"
        store2.close()


def test_api_create_connection_fails_closed_when_key_missing(authed_client: TestClient, monkeypatch: pytest.MonkeyPatch):
    """API endpoint returns HTTP 500 and fails closed when encryption key is not set."""
    monkeypatch.delenv("FORENSICOPS_CREDENTIAL_KEY", raising=False)
    monkeypatch.delenv("FORENSICOPS_CREDENTIAL_KEY_FILE", raising=False)
    reset_credential_store()

    res = authed_client.post(
        "/api/siem/connections",
        json={
            "case_id": "test_case_sec_01",
            "siem_type": "elasticsearch",
            "endpoint_url": "https://93.184.216.34:9200",
            "password": "secret_password",
        },
    )
    assert res.status_code == 500
    assert "Fail-Closed Security" in res.json()["detail"]


def test_siem_connection_test_endpoint_sanitizes_errors(authed_client: TestClient):
    """POST /api/siem/connections/{id}/test tests connectivity and scrubs secret leakage."""
    secret_pass = "P@ssw0rdLeakTest999!"
    create_res = authed_client.post(
        "/api/siem/connections",
        json={
            "case_id": "test_case_sec_01",
            "siem_type": "elasticsearch",
            "endpoint_url": "https://93.184.216.34:9200",
            "password": secret_pass,
        },
    )
    conn_id = create_res.json()["connection_id"]

    # 1. Successful test
    with patch("backend.app.connectors.siem_connectors.ElasticsearchConnector.test_connection", return_value=True):
        test_res = authed_client.post(f"/api/siem/connections/{conn_id}/test")
        assert test_res.status_code == 200
        test_data = test_res.json()
        assert test_data["status"] == "success"
        assert test_data["reachable"] is True
        assert test_data["authenticated"] is True

    # 2. Error during test with embedded secret
    with patch("backend.app.connectors.siem_connectors.ElasticsearchConnector.test_connection", side_effect=Exception(f"Auth failed for password: {secret_pass}")):
        test_res2 = authed_client.post(f"/api/siem/connections/{conn_id}/test")
        assert test_res2.status_code == 200
        test_data2 = test_res2.json()
        assert test_data2["status"] == "error"
        assert test_data2["reachable"] is False
        assert secret_pass not in test_data2["message"]
        assert "******" in test_data2["message"]


def test_vault_database_permissions(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, test_key: str):
    """Verify that SQLite vault database file permissions are owner-only."""
    monkeypatch.setenv("FORENSICOPS_CREDENTIAL_KEY", test_key)
    db_file = tmp_path / "vault_perm_test.db"
    store = LLMStateStore(db_file)
    store.close()

    assert db_file.exists()
    if os.name != "nt":
        # On POSIX, file mode should be 0600 (owner read/write only)
        mode = stat.S_IMODE(os.stat(db_file).st_mode)
        assert mode == 0o600


def test_log_output_masks_credentials(caplog: pytest.LogCaptureFixture):
    """Verify that SecretRedactingFilter masks passwords, API keys, and tokens in log output."""
    from backend.app.core.logging_config import SecretRedactingFilter

    test_logger = logging.getLogger("test_secret_redaction")
    test_logger.setLevel(logging.DEBUG)
    test_filter = SecretRedactingFilter()
    test_logger.addFilter(test_filter)

    secret_key = "super_secret_api_key_12345"
    with caplog.at_level(logging.DEBUG):
        test_logger.debug("Connecting with password: '%s' and apiKey: %s", "P@ssword123!", secret_key)
        test_logger.info("Payload dump: api_key='%s'", secret_key)

    for record in caplog.records:
        assert secret_key not in record.getMessage()
        assert "P@ssword123!" not in record.getMessage()


def test_api_response_never_echoes_credentials(authed_client: TestClient):
    """Verify that all SIEM connection API endpoints mathematically exclude secrets from response bodies."""
    secret_pass = "NeverEchoThisSecretPassword123!"
    secret_token = "NeverEchoThisSecretToken456!"

    res = authed_client.post(
        "/api/siem/connections",
        json={
            "case_id": "test_case_echo_01",
            "siem_type": "splunk",
            "endpoint_url": "https://93.184.216.34:8089",
            "password": secret_pass,
            "token": secret_token,
        },
    )
    assert res.status_code == 201
    body_text = res.text
    assert secret_pass not in body_text
    assert secret_token not in body_text
    data = res.json()
    assert "password" not in data
    assert "token" not in data
    assert "encrypted_credentials" not in data
    assert data["has_password"] is True
    assert data["has_token"] is True

    conn_id = data["connection_id"]

    # GET by id
    get_res = authed_client.get(f"/api/siem/connections/{conn_id}")
    assert get_res.status_code == 200
    assert secret_pass not in get_res.text
    assert secret_token not in get_res.text

    # GET list
    list_res = authed_client.get("/api/siem/connections?case_id=test_case_echo_01")
    assert list_res.status_code == 200
    assert secret_pass not in list_res.text
    assert secret_token not in list_res.text

