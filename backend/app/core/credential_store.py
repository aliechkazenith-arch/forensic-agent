"""Encrypted Credential Storage & Management for ForensicOps AI (SEC-UI-001).

Standards:
- Authenticated symmetric encryption at rest using Fernet (AES-128-CBC + HMAC-SHA256).
- Encryption keys loaded strictly from FORENSICOPS_CREDENTIAL_KEY or FORENSICOPS_CREDENTIAL_KEY_FILE.
- Zero Secret Leakage: Keys and plaintext secrets are never written alongside ciphertext or returned via API.
- Fail-Closed: If encryption keys are missing or invalid, operations immediately fail without plaintext fallback.
- Tamper-Evident: Modified or invalid ciphertext triggers CredentialEncryptionError.
"""
from __future__ import annotations

import base64
import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
from uuid import uuid4

from cryptography.fernet import Fernet, InvalidToken

from backend.app.core.exceptions import CredentialEncryptionError
from backend.app.core.network_validator import sanitize_credentials
from backend.app.db.sqlite_store import LLMStateStore, get_llm_state_store
from backend.app.models.connectors import SIEMConnectionConfig, SIEMType

logger = logging.getLogger(__name__)


def generate_credential_key() -> str:
    """Generate a new url-safe base64-encoded 32-byte Fernet key."""
    return Fernet.generate_key().decode("utf-8")


def get_credential_encryption_key() -> bytes:
    """Retrieve and validate the master credential encryption key.
    
    Checks FORENSICOPS_CREDENTIAL_KEY, then FORENSICOPS_CREDENTIAL_KEY_FILE.
    Fails closed if key is not configured or fails format validation.
    """
    key_str = os.getenv("FORENSICOPS_CREDENTIAL_KEY")

    if not key_str:
        key_file = os.getenv("FORENSICOPS_CREDENTIAL_KEY_FILE")
        if key_file:
            p = Path(key_file)
            if p.exists() and p.is_file():
                try:
                    key_str = p.read_text(encoding="utf-8").strip()
                except Exception as e:
                    raise CredentialEncryptionError(
                        f"Failed to read credential key file '{key_file}': {e}"
                    )
            else:
                raise CredentialEncryptionError(
                    f"Credential key file '{key_file}' does not exist or is not a file."
                )

    if not key_str or not key_str.strip():
        raise CredentialEncryptionError(
            "Fail-Closed Security: No credential encryption key configured. "
            "Set FORENSICOPS_CREDENTIAL_KEY or FORENSICOPS_CREDENTIAL_KEY_FILE."
        )

    clean_key = key_str.strip().encode("utf-8")

    # Validate that the key is a valid 32-byte url-safe base64 key
    try:
        decoded = base64.urlsafe_b64decode(clean_key)
        if len(decoded) != 32:
            raise ValueError(f"Key decoded to {len(decoded)} bytes; expected 32.")
    except Exception as e:
        raise CredentialEncryptionError(
            f"Fail-Closed Security: Configured credential encryption key is invalid: {e}"
        )

    return clean_key


def get_fernet(key: Optional[Union[bytes, str]] = None) -> Fernet:
    """Instantiate a Fernet symmetric encryption cipher with the validated key."""
    if key is None:
        raw_key = get_credential_encryption_key()
    elif isinstance(key, str):
        raw_key = key.strip().encode("utf-8")
    else:
        raw_key = key

    try:
        return Fernet(raw_key)
    except Exception as e:
        raise CredentialEncryptionError(f"Failed to initialize encryption cipher: {e}")


def encrypt_credentials(credentials: Dict[str, Any], key: Optional[Union[bytes, str]] = None) -> str:
    """Encrypt a credentials dictionary to a Fernet token string.
    
    Fails closed if cipher cannot be initialized or payload cannot be serialized.
    """
    f = get_fernet(key=key)
    try:
        payload_bytes = json.dumps(credentials, sort_keys=True).encode("utf-8")
        ciphertext_bytes = f.encrypt(payload_bytes)
        return ciphertext_bytes.decode("utf-8")
    except Exception as e:
        raise CredentialEncryptionError(f"Failed to encrypt credentials: {e}")


def decrypt_credentials(ciphertext: str, key: Optional[Union[bytes, str]] = None) -> Dict[str, Any]:
    """Decrypt a Fernet token string to a credentials dictionary.
    
    Fails closed on tamper detection (InvalidToken), corruption, or missing keys.
    """
    if not ciphertext or not ciphertext.strip():
        return {}

    f = get_fernet(key=key)
    try:
        decrypted_bytes = f.decrypt(ciphertext.strip().encode("utf-8"))
        data = json.loads(decrypted_bytes.decode("utf-8"))
        if not isinstance(data, dict):
            raise CredentialEncryptionError("Decrypted credential payload is not a valid dictionary.")
        return data
    except InvalidToken:
        raise CredentialEncryptionError(
            "Fail-Closed Integrity: Credential ciphertext failed HMAC verification (tampered, corrupted, or wrong key)."
        )
    except CredentialEncryptionError:
        raise
    except Exception as e:
        raise CredentialEncryptionError(f"Failed to decrypt credentials: {e}")


class SIEMCredentialStore:
    """Server-side encrypted store for SIEM connections and authentication credentials."""

    def __init__(self, db_store: Optional[LLMStateStore] = None):
        self._db_store = db_store or get_llm_state_store()

    def create_connection(
        self,
        case_id: str,
        siem_type: SIEMType,
        endpoint_url: str,
        credentials: Optional[Dict[str, Any]] = None,
        index_pattern: Optional[str] = None,
        allowed_hosts: Optional[List[str]] = None,
        headers: Optional[Dict[str, str]] = None,
        verify_ssl: bool = True,
        timeout_seconds: float = 30.0,
        username: Optional[str] = None,
        created_by: str = "analyst",
        connection_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create a new managed SIEM connection with server-side encrypted credentials.
        
        Returns safe connection dictionary without secrets.
        """
        conn_id = connection_id or f"siem-{uuid4().hex[:12]}"
        now_utc = datetime.now(timezone.utc).isoformat()

        creds = credentials.copy() if credentials else {}
        if username and not creds.get("username"):
            creds["username"] = username

        # Determine presence indicators
        has_password = bool(creds.get("password"))
        has_api_key = bool(creds.get("api_key"))
        has_token = bool(creds.get("token"))

        # Encrypt secrets fail-closed
        encrypted_ciphertext = encrypt_credentials(creds)

        allowed_json = json.dumps(allowed_hosts) if allowed_hosts else None
        headers_json = json.dumps(headers) if headers else None

        self._db_store.create_siem_connection_record(
            connection_id=conn_id,
            case_id=case_id,
            siem_type=siem_type,
            endpoint_url=endpoint_url,
            index_pattern=index_pattern,
            allowed_hosts_json=allowed_json,
            headers_json=headers_json,
            verify_ssl=1 if verify_ssl else 0,
            timeout_seconds=float(timeout_seconds),
            encrypted_credentials=encrypted_ciphertext,
            has_password=1 if has_password else 0,
            has_api_key=1 if has_api_key else 0,
            has_token=1 if has_token else 0,
            username=username or creds.get("username"),
            created_by=created_by,
            created_at_utc=now_utc,
            updated_at_utc=now_utc,
        )

        return self.get_connection(conn_id, case_id=case_id, include_credentials=False)  # type: ignore

    def get_connection(
        self,
        connection_id: str,
        case_id: Optional[str] = None,
        include_credentials: bool = False,
    ) -> Optional[Dict[str, Any]]:
        """Retrieve connection by ID.
        
        If include_credentials is False, ZERO secrets or ciphertexts are returned.
        If include_credentials is True, decrypted secrets are returned (backend memory only).
        """
        record = self._db_store.get_siem_connection_record(connection_id)
        if not record:
            return None

        if case_id and record["case_id"] != case_id:
            return None

        # Build safe public view
        safe_view = {
            "connection_id": record["connection_id"],
            "case_id": record["case_id"],
            "siem_type": record["siem_type"],
            "endpoint_url": record["endpoint_url"],
            "index_pattern": record["index_pattern"],
            "allowed_hosts": json.loads(record["allowed_hosts_json"]) if record.get("allowed_hosts_json") else None,
            "headers": json.loads(record["headers_json"]) if record.get("headers_json") else {},
            "verify_ssl": bool(record["verify_ssl"]),
            "timeout_seconds": float(record["timeout_seconds"]),
            "username": record["username"],
            "has_password": bool(record["has_password"]),
            "has_api_key": bool(record["has_api_key"]),
            "has_token": bool(record["has_token"]),
            "created_by": record["created_by"],
            "created_at_utc": record["created_at_utc"],
            "updated_at_utc": record["updated_at_utc"],
        }

        if include_credentials:
            decrypted = decrypt_credentials(record["encrypted_credentials"])
            safe_view["credentials"] = decrypted

        return safe_view

    def list_connections(self, case_id: str) -> List[Dict[str, Any]]:
        """List all SIEM connections for a case in safe format (zero secrets)."""
        records = self._db_store.list_siem_connection_records(case_id=case_id)
        results = []
        for r in records:
            results.append({
                "connection_id": r["connection_id"],
                "case_id": r["case_id"],
                "siem_type": r["siem_type"],
                "endpoint_url": r["endpoint_url"],
                "index_pattern": r["index_pattern"],
                "allowed_hosts": json.loads(r["allowed_hosts_json"]) if r.get("allowed_hosts_json") else None,
                "headers": json.loads(r["headers_json"]) if r.get("headers_json") else {},
                "verify_ssl": bool(r["verify_ssl"]),
                "timeout_seconds": float(r["timeout_seconds"]),
                "username": r["username"],
                "has_password": bool(r["has_password"]),
                "has_api_key": bool(r["has_api_key"]),
                "has_token": bool(r["has_token"]),
                "created_by": r["created_by"],
                "created_at_utc": r["created_at_utc"],
                "updated_at_utc": r["updated_at_utc"],
            })
        return results

    def update_connection(
        self,
        connection_id: str,
        case_id: Optional[str] = None,
        siem_type: Optional[SIEMType] = None,
        endpoint_url: Optional[str] = None,
        index_pattern: Optional[str] = None,
        allowed_hosts: Optional[List[str]] = None,
        headers: Optional[Dict[str, str]] = None,
        verify_ssl: Optional[bool] = None,
        timeout_seconds: Optional[float] = None,
        username: Optional[str] = None,
        updated_credentials: Optional[Dict[str, Any]] = None,
        remove_password: bool = False,
        remove_api_key: bool = False,
        remove_token: bool = False,
        clear_credentials: bool = False,
    ) -> Optional[Dict[str, Any]]:
        """Update connection parameters and/or credentials.
        
        CRITICAL SECURITY BEHAVIOR:
        - Leaving password/api_key/token fields empty/None PRESERVES existing credentials.
        - Deletion of credentials must be explicitly triggered via remove_* or clear_credentials flags.
        """
        existing = self._db_store.get_siem_connection_record(connection_id)
        if not existing:
            return None

        if case_id and existing["case_id"] != case_id:
            return None

        # Decrypt existing credentials
        current_creds = decrypt_credentials(existing["encrypted_credentials"])

        if clear_credentials:
            current_creds.clear()
        else:
            if remove_password:
                current_creds.pop("password", None)
            if remove_api_key:
                current_creds.pop("api_key", None)
            if remove_token:
                current_creds.pop("token", None)

            if updated_credentials:
                for k, v in updated_credentials.items():
                    # If value is non-empty string, update it; if empty string or None, preserve!
                    if v is not None and (not isinstance(v, str) or v.strip() != ""):
                        current_creds[k] = v

        if username is not None:
            current_creds["username"] = username

        # Encrypt updated credentials
        new_encrypted = encrypt_credentials(current_creds)
        has_password = bool(current_creds.get("password"))
        has_api_key = bool(current_creds.get("api_key"))
        has_token = bool(current_creds.get("token"))

        now_utc = datetime.now(timezone.utc).isoformat()

        # Update fields if provided
        final_type = siem_type if siem_type is not None else existing["siem_type"]
        final_url = endpoint_url if endpoint_url is not None else existing["endpoint_url"]
        final_index = index_pattern if index_pattern is not None else existing["index_pattern"]
        final_allowed = json.dumps(allowed_hosts) if allowed_hosts is not None else existing["allowed_hosts_json"]
        final_headers = json.dumps(headers) if headers is not None else existing["headers_json"]
        final_verify = (1 if verify_ssl else 0) if verify_ssl is not None else existing["verify_ssl"]
        final_timeout = float(timeout_seconds) if timeout_seconds is not None else float(existing["timeout_seconds"])
        final_username = username if username is not None else existing["username"]

        self._db_store.update_siem_connection_record(
            connection_id=connection_id,
            siem_type=final_type,
            endpoint_url=final_url,
            index_pattern=final_index,
            allowed_hosts_json=final_allowed,
            headers_json=final_headers,
            verify_ssl=final_verify,
            timeout_seconds=final_timeout,
            encrypted_credentials=new_encrypted,
            has_password=1 if has_password else 0,
            has_api_key=1 if has_api_key else 0,
            has_token=1 if has_token else 0,
            username=final_username,
            updated_at_utc=now_utc,
        )

        return self.get_connection(connection_id, case_id=case_id, include_credentials=False)

    def delete_connection(self, connection_id: str, case_id: Optional[str] = None) -> bool:
        """Permanently delete a SIEM connection and its encrypted credentials."""
        existing = self._db_store.get_siem_connection_record(connection_id)
        if not existing:
            return False
        if case_id and existing["case_id"] != case_id:
            return False
        return self._db_store.delete_siem_connection_record(connection_id)

    def test_connection(self, connection_id: str, case_id: Optional[str] = None) -> Dict[str, Any]:
        """Test connection reachability and authentication to target SIEM endpoint.
        
        Zero Secret Leakage: Does not return credentials or leak tokens in exceptions.
        """
        conn_data = self.get_connection(connection_id, case_id=case_id, include_credentials=True)
        if not conn_data:
            return {
                "status": "error",
                "connection_id": connection_id,
                "siem_type": "elasticsearch",
                "reachable": False,
                "authenticated": False,
                "latency_ms": 0,
                "message": f"Connection '{connection_id}' not found.",
            }

        creds = conn_data.get("credentials", {})
        siem_type = conn_data["siem_type"]

        config = SIEMConnectionConfig(
            siem_type=siem_type,
            endpoint_url=conn_data["endpoint_url"],
            api_key=creds.get("api_key"),
            username=creds.get("username") or conn_data.get("username"),
            password=creds.get("password"),
            token=creds.get("token"),
            verify_ssl=conn_data["verify_ssl"],
            timeout_seconds=conn_data["timeout_seconds"],
            index_pattern=conn_data.get("index_pattern"),
            headers=conn_data.get("headers") or {},
            allowed_hosts=conn_data.get("allowed_hosts"),
        )

        from backend.app.connectors.siem_connectors import (
            ElasticsearchConnector,
            WazuhConnector,
            SplunkConnector,
        )

        start_time = time.time()
        try:
            if siem_type == "elasticsearch":
                connector = ElasticsearchConnector(config=config)
            elif siem_type == "wazuh":
                connector = WazuhConnector(config=config)
            elif siem_type == "splunk":
                connector = SplunkConnector(config=config)
            else:
                return {
                    "status": "error",
                    "connection_id": connection_id,
                    "siem_type": siem_type,
                    "reachable": False,
                    "authenticated": False,
                    "latency_ms": 0,
                    "message": f"Unsupported SIEM type: {siem_type}",
                }

            with connector:
                success = connector.test_connection()

            latency_ms = int((time.time() - start_time) * 1000)
            return {
                "status": "success" if success else "error",
                "connection_id": connection_id,
                "siem_type": siem_type,
                "reachable": success,
                "authenticated": success,
                "latency_ms": latency_ms,
                "message": "Connection and authentication successful." if success else "Authentication failed.",
            }
        except Exception as e:
            latency_ms = int((time.time() - start_time) * 1000)
            clean_err = sanitize_credentials(str(e))
            return {
                "status": "error",
                "connection_id": connection_id,
                "siem_type": siem_type,
                "reachable": False,
                "authenticated": False,
                "latency_ms": latency_ms,
                "message": f"Connection test failed: {clean_err}",
            }


_credential_store_instance: Optional[SIEMCredentialStore] = None


def get_credential_store(db_store: Optional[LLMStateStore] = None) -> SIEMCredentialStore:
    """Retrieve or initialize singleton SIEMCredentialStore instance."""
    global _credential_store_instance
    if _credential_store_instance is None or db_store is not None:
        _credential_store_instance = SIEMCredentialStore(db_store=db_store)
    return _credential_store_instance


def reset_credential_store() -> None:
    """Reset singleton for test isolation."""
    global _credential_store_instance
    _credential_store_instance = None
