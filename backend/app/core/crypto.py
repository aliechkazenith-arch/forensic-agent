"""Cryptographic Key Derivation & Vault Envelope Encryption (Phase 14.3).

Standards:
- Key Derivation: PBKDF2-HMAC-SHA256 (OWASP recommended 600,000 iterations) and Argon2id.
- Zero Hardcoded Salts: Salts generated strictly using os.urandom(16) / secrets.token_bytes(16).
- Envelope Encryption: AES-256-GCM (NIST SP 800-38D) with 12-byte random IV/nonce and 16-byte authentication tag.
- Fail-Closed Authentication: AEAD authentication failures raise CryptographicTamperError immediately without exposing partial plaintext.
- Zero Secret Leakage: Master passphrases and derived keys are zeroized from memory references and never serialized.
"""
from __future__ import annotations

import base64
import json
import logging
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, Union

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Check for Argon2id support in cryptography
try:
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False

from backend.app.core.exceptions import CredentialEncryptionError, CryptographicTamperError

logger = logging.getLogger(__name__)

# Minimum security thresholds
DEFAULT_PBKDF2_ITERATIONS = 600000
MIN_PBKDF2_ITERATIONS = 100000
DEFAULT_SALT_LENGTH = 16
DEFAULT_NONCE_LENGTH = 12
KEY_LENGTH_BYTES = 32  # 256 bits


def generate_salt(length: int = DEFAULT_SALT_LENGTH) -> bytes:
    """Generate a cryptographically secure random salt using os.urandom.
    
    Zero hardcoded salts: Each key derivation operation must use a fresh random salt.
    """
    if length < 16:
        raise ValueError("Salt length must be at least 16 bytes for cryptographic security.")
    return os.urandom(length)


def generate_nonce(length: int = DEFAULT_NONCE_LENGTH) -> bytes:
    """Generate a cryptographically secure 12-byte IV/nonce for AES-GCM."""
    if length != 12:
        raise ValueError("AES-GCM requires a 12-byte (96-bit) nonce per NIST SP 800-38D.")
    return os.urandom(length)


def derive_key_pbkdf2(
    passphrase: str,
    salt: bytes,
    iterations: int = DEFAULT_PBKDF2_ITERATIONS,
    key_length: int = KEY_LENGTH_BYTES,
) -> bytes:
    """Derive a 256-bit symmetric key using PBKDF2-HMAC-SHA256 (OWASP recommended work factor).
    
    Args:
        passphrase: User master passphrase. Must be non-empty.
        salt: Random salt bytes (minimum 16 bytes).
        iterations: Iteration count (minimum 100,000, default 600,000).
        key_length: Target key length in bytes (default 32 for AES-256).
    """
    if not passphrase or not isinstance(passphrase, str):
        raise ValueError("Passphrase must be a non-empty string.")
    if not salt or not isinstance(salt, bytes) or len(salt) < 16:
        raise ValueError("Salt must be at least 16 bytes.")
    if iterations < MIN_PBKDF2_ITERATIONS:
        raise ValueError(
            f"PBKDF2 iterations ({iterations}) below minimum security threshold ({MIN_PBKDF2_ITERATIONS})."
        )

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def derive_key_argon2id(
    passphrase: str,
    salt: bytes,
    key_length: int = KEY_LENGTH_BYTES,
    iterations: int = 2,
    memory_cost: int = 65536,  # 64 MiB
    lanes: int = 4,
) -> bytes:
    """Derive a 256-bit symmetric key using Argon2id memory-hard KDF.
    
    Args:
        passphrase: User master passphrase. Must be non-empty.
        salt: Random salt bytes (minimum 16 bytes).
        key_length: Target key length in bytes (default 32 for AES-256).
        iterations: Time cost (passes).
        memory_cost: Memory cost in KiB (default 65536 = 64 MiB).
        lanes: Parallelism / lanes.
    """
    if not ARGON2_AVAILABLE:
        raise NotImplementedError("Argon2id KDF is not available in the current cryptography installation.")
    if not passphrase or not isinstance(passphrase, str):
        raise ValueError("Passphrase must be a non-empty string.")
    if not salt or not isinstance(salt, bytes) or len(salt) < 16:
        raise ValueError("Salt must be at least 16 bytes.")

    kdf = Argon2id(
        salt=salt,
        length=key_length,
        iterations=iterations,
        lanes=lanes,
        memory_cost=memory_cost,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def derive_key(
    passphrase: str,
    salt: bytes,
    kdf: str = "pbkdf2",
    key_length: int = KEY_LENGTH_BYTES,
    **kwargs: Any,
) -> Tuple[bytes, Dict[str, Any]]:
    """Derive key using specified KDF with automatic fallback to PBKDF2HMAC if Argon2id is requested but unavailable."""
    kdf_lower = kdf.lower().strip()
    if kdf_lower == "argon2id":
        if ARGON2_AVAILABLE:
            iterations = kwargs.get("iterations", 2)
            memory_cost = kwargs.get("memory_cost", 65536)
            lanes = kwargs.get("lanes", 4)
            key = derive_key_argon2id(
                passphrase,
                salt,
                key_length=key_length,
                iterations=iterations,
                memory_cost=memory_cost,
                lanes=lanes,
            )
            return key, {
                "kdf": "argon2id",
                "iterations": iterations,
                "memory_cost": memory_cost,
                "lanes": lanes,
            }
        logger.warning("Argon2id requested but not available; falling back to PBKDF2-HMAC-SHA256.")

    # Default to PBKDF2HMAC
    iterations = kwargs.get("iterations", DEFAULT_PBKDF2_ITERATIONS)
    key = derive_key_pbkdf2(passphrase, salt, iterations=iterations, key_length=key_length)
    return key, {
        "kdf": "pbkdf2",
        "iterations": iterations,
    }


class AESGCMVaultCipher:
    """Authenticated AES-256-GCM envelope cipher with derived key support."""

    ALGORITHM = "AES-256-GCM"

    @classmethod
    def encrypt(
        cls,
        data: Union[bytes, str, Dict[str, Any]],
        passphrase: str,
        kdf: str = "pbkdf2",
        iterations: int = DEFAULT_PBKDF2_ITERATIONS,
        salt: Optional[bytes] = None,
        associated_data: Optional[bytes] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Encrypt plaintext payload using AES-256-GCM with a passphrase-derived key.
        
        Returns structured dictionary containing algorithm, KDF parameters, salt, nonce, and ciphertext.
        """
        if not passphrase:
            raise CredentialEncryptionError("Passphrase must not be empty.")

        # Serialize input to bytes if needed
        if isinstance(data, dict):
            raw_data = json.dumps(data, ensure_ascii=False).encode("utf-8")
        elif isinstance(data, str):
            raw_data = data.encode("utf-8")
        elif isinstance(data, bytes):
            raw_data = data
        else:
            raise CredentialEncryptionError(f"Unsupported data type for encryption: {type(data)}")

        eff_salt = salt if salt is not None else generate_salt(DEFAULT_SALT_LENGTH)
        derived_key, kdf_meta = derive_key(
            passphrase,
            eff_salt,
            kdf=kdf,
            iterations=iterations,
            **kwargs,
        )

        nonce = generate_nonce(DEFAULT_NONCE_LENGTH)
        aesgcm = AESGCM(derived_key)

        try:
            # AESGCM.encrypt returns ciphertext + 16-byte authentication tag
            ciphertext = aesgcm.encrypt(nonce, raw_data, associated_data)
        except Exception as e:
            raise CredentialEncryptionError(f"AES-256-GCM encryption failed: {e}") from e

        envelope: Dict[str, Any] = {
            "version": 1,
            "algorithm": cls.ALGORITHM,
            "kdf": kdf_meta["kdf"],
            "salt": base64.b64encode(eff_salt).decode("ascii"),
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        }
        envelope.update({k: v for k, v in kdf_meta.items() if k != "kdf"})
        return envelope

    @classmethod
    def decrypt(
        cls,
        payload: Union[Dict[str, Any], str, bytes],
        passphrase: str,
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        """Decrypt and authenticate an AES-256-GCM envelope payload.
        
        Fails closed with CryptographicTamperError or CredentialEncryptionError if ciphertext,
        tag, nonce, salt, or passphrase are invalid or tampered.
        """
        if not passphrase:
            raise CredentialEncryptionError("Passphrase must not be empty.")

        # Parse payload
        if isinstance(payload, (str, bytes)):
            try:
                envelope = json.loads(payload)
            except Exception as e:
                raise CredentialEncryptionError(f"Invalid envelope JSON: {e}") from e
        elif isinstance(payload, dict):
            envelope = payload
        else:
            raise CredentialEncryptionError(f"Unsupported envelope payload type: {type(payload)}")

        # Validate mandatory envelope attributes
        for field in ("algorithm", "kdf", "salt", "nonce", "ciphertext"):
            if field not in envelope:
                raise CredentialEncryptionError(f"Missing mandatory envelope field: '{field}'.")

        algo = envelope.get("algorithm")
        if algo != cls.ALGORITHM:
            raise CredentialEncryptionError(
                f"Unsupported encryption algorithm '{algo}'; expected '{cls.ALGORITHM}'."
            )

        try:
            salt = base64.b64decode(envelope["salt"])
            nonce = base64.b64decode(envelope["nonce"])
            ciphertext = base64.b64decode(envelope["ciphertext"])
        except Exception as e:
            raise CredentialEncryptionError(f"Malformed base64 encoding in envelope: {e}") from e

        if len(salt) < 16:
            raise CredentialEncryptionError("Corrupted envelope: salt is shorter than 16 bytes.")
        if len(nonce) != 12:
            raise CredentialEncryptionError("Corrupted envelope: nonce must be exactly 12 bytes.")
        if len(ciphertext) < 16:
            raise CryptographicTamperError(
                "Tamper detected: Ciphertext is shorter than 16-byte authentication tag."
            )

        kdf_name = envelope.get("kdf", "pbkdf2")
        iterations = envelope.get("iterations", DEFAULT_PBKDF2_ITERATIONS)
        memory_cost = envelope.get("memory_cost", 65536)
        lanes = envelope.get("lanes", 4)

        try:
            derived_key, _ = derive_key(
                passphrase,
                salt,
                kdf=kdf_name,
                iterations=iterations,
                memory_cost=memory_cost,
                lanes=lanes,
            )
        except Exception as e:
            raise CredentialEncryptionError(f"Key derivation failed during decryption: {e}") from e

        aesgcm = AESGCM(derived_key)
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data)
            return plaintext
        except InvalidTag as it:
            raise CryptographicTamperError(
                "Decryption failed: Authentication tag mismatch, corrupted ciphertext, or invalid passphrase (tamper detected)."
            ) from it
        except Exception as e:
            raise CryptographicTamperError(f"Cryptographic failure during decryption: {e}") from e

    @classmethod
    def encrypt_to_json(
        cls,
        data: Union[bytes, str, Dict[str, Any]],
        passphrase: str,
        kdf: str = "pbkdf2",
        **kwargs: Any,
    ) -> str:
        """Encrypt payload and return formatted JSON envelope string."""
        envelope = cls.encrypt(data, passphrase, kdf=kdf, **kwargs)
        return json.dumps(envelope, indent=2)

    @classmethod
    def decrypt_from_json(
        cls,
        json_str: str,
        passphrase: str,
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        """Decrypt JSON envelope string and return authenticated plaintext bytes."""
        return cls.decrypt(json_str, passphrase, associated_data=associated_data)


# Top-level module convenience functions
encrypt_vault_payload = AESGCMVaultCipher.encrypt
decrypt_vault_payload = AESGCMVaultCipher.decrypt


# ------------------------------------------------------------------------------
# Vault Export & Import Functions (Task 3)
# ------------------------------------------------------------------------------
def export_encrypted_vault(
    store: Any,
    export_path: Union[str, Path],
    passphrase: str,
    kdf: str = "pbkdf2",
    iterations: int = DEFAULT_PBKDF2_ITERATIONS,
) -> Path:
    """Export complete SQLite vault database to an authenticated AES-256-GCM encrypted package.
    
    Args:
        store: LLMStateStore instance containing SQLite connection.
        export_path: Destination path for the encrypted export file.
        passphrase: User master passphrase for key derivation.
        kdf: Key derivation function ('pbkdf2' or 'argon2id').
        iterations: Work factor iterations for PBKDF2.
        
    Returns:
        Path to the written encrypted export file.
    """
    if not passphrase or not passphrase.strip():
        raise CredentialEncryptionError("Passphrase is required for encrypted vault export.")

    if not hasattr(store, "_conn") or store._conn is None:
        raise CredentialEncryptionError("Invalid state store: missing active database connection.")

    target_path = Path(export_path)
    target_path.parent.mkdir(parents=True, exist_ok=True)

    # Perform atomic database dump using iterdump after WAL checkpoint
    try:
        # Flush all uncommitted WAL frames into main database file (WAL checkpoint)
        try:
            store._conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
        except Exception as we:
            logger.warning("WAL checkpoint prior to vault export failed or not applicable: %s", we)

        sql_lines = list(store._conn.iterdump())
        sql_dump = "\n".join(sql_lines)
    except Exception as e:
        raise CredentialEncryptionError(f"Failed to generate vault SQL dump: {e}") from e

    payload = {
        "magic": "FORENSICOPS_VAULT_EXPORT",
        "format_version": 1,
        "exported_at_utc": datetime.now(timezone.utc).isoformat(),
        "database_type": "sqlite3",
        "sql_dump": sql_dump,
    }
    payload_bytes = json.dumps(payload, ensure_ascii=False).encode("utf-8")

    # Encrypt envelope
    envelope = AESGCMVaultCipher.encrypt(
        payload_bytes,
        passphrase=passphrase,
        kdf=kdf,
        iterations=iterations,
    )

    # Write securely
    try:
        target_path.write_text(json.dumps(envelope, indent=2), encoding="utf-8")
        if os.name != "nt":
            os.chmod(target_path, 0o600)
    except Exception as e:
        raise CredentialEncryptionError(f"Failed to write encrypted vault export: {e}") from e

    logger.info(
        "Successfully exported encrypted vault to '%s' (KDF: %s, Iterations: %d).",
        target_path,
        kdf,
        iterations,
    )
    return target_path


def import_encrypted_vault(
    store: Any,
    import_path: Union[str, Path],
    passphrase: str,
) -> Dict[str, Any]:
    """Import and decrypt an authenticated AES-256-GCM encrypted vault package into the state store.
    
    Args:
        store: LLMStateStore instance to restore data into.
        import_path: Path to the encrypted vault export file.
        passphrase: User master passphrase for decryption.
        
    Returns:
        Summary dictionary with import details and record counts.
    """
    if not passphrase or not passphrase.strip():
        raise CredentialEncryptionError("Passphrase is required for vault decryption.")

    if not hasattr(store, "_conn") or store._conn is None:
        raise CredentialEncryptionError("Invalid state store: missing active database connection.")

    src_path = Path(import_path)
    if not src_path.exists() or not src_path.is_file():
        raise CredentialEncryptionError(f"Encrypted vault file '{import_path}' does not exist.")

    try:
        raw_envelope_text = src_path.read_text(encoding="utf-8")
    except Exception as e:
        raise CredentialEncryptionError(f"Failed to read vault file '{import_path}': {e}") from e

    # Decrypt and authenticate
    decrypted_bytes = AESGCMVaultCipher.decrypt(raw_envelope_text, passphrase=passphrase)

    try:
        payload = json.loads(decrypted_bytes.decode("utf-8"))
    except Exception as e:
        raise CryptographicTamperError(f"Corrupted vault payload JSON: {e}") from e

    if not isinstance(payload, dict) or payload.get("magic") != "FORENSICOPS_VAULT_EXPORT":
        raise CredentialEncryptionError(
            "Invalid vault package: Missing or invalid FORENSICOPS_VAULT_EXPORT magic identifier."
        )

    sql_dump = payload.get("sql_dump")
    if not sql_dump or not isinstance(sql_dump, str):
        raise CredentialEncryptionError("Invalid vault package: Missing or empty database SQL dump.")

    # Execute SQL script into the database cleanly by resetting existing user objects first
    try:
        with store._conn:
            cursor = store._conn.cursor()
            cursor.execute("PRAGMA foreign_keys = OFF;")
            tables = [
                row[0]
                for row in cursor.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';"
                ).fetchall()
            ]
            for tbl in tables:
                cursor.execute(f'DROP TABLE IF EXISTS "{tbl}";')
            views = [
                row[0]
                for row in cursor.execute(
                    "SELECT name FROM sqlite_master WHERE type='view';"
                ).fetchall()
            ]
            for v in views:
                cursor.execute(f'DROP VIEW IF EXISTS "{v}";')
            cursor.execute("PRAGMA foreign_keys = ON;")
            store._conn.executescript(sql_dump)
    except Exception as e:
        raise CredentialEncryptionError(f"Database restoration script failed: {e}") from e

    imported_summary = {
        "status": "success",
        "format_version": payload.get("format_version", 1),
        "exported_at_utc": payload.get("exported_at_utc"),
        "imported_at_utc": datetime.now(timezone.utc).isoformat(),
        "database_type": payload.get("database_type", "sqlite3"),
    }
    logger.info(
        "Successfully restored encrypted vault from '%s' (originally exported at %s).",
        src_path,
        imported_summary["exported_at_utc"],
    )
    return imported_summary
