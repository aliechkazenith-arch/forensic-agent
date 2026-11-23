"""Cryptographic Security Utilities: bcrypt Password Hashing & python-jose JWT Management.

Standards:
- NIST SP 800-63B Authentication Standards
- 72-Byte Safe Bcrypt Password Truncation
- HS256 HMAC-SHA256 Token Signatures with Configurable Expiry
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional
import bcrypt
from jose import JWTError, jwt
from pydantic import ValidationError

import secrets
from pathlib import Path

from backend.app.auth.models import TokenPayload

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("FORENSICOPS_TOKEN_EXPIRE_MINUTES", "480"))  # 8 hours default


def get_jwt_secret() -> str:
    """Retrieve JWT secret key from environment, persistent vault secret file, or generate one."""
    secret = os.getenv("FORENSICOPS_JWT_SECRET")
    if secret:
        return secret

    is_test = bool(os.getenv("PYTEST_CURRENT_TEST")) or os.getenv("FORENSICOPS_ENVIRONMENT") == "test"
    if is_test:
        return "forensicops-ai-secure-air-gapped-secret-key-2026"

    # In production with explicit production flag, enforce strict environment variable
    if os.getenv("FORENSICOPS_ENVIRONMENT") == "production":
        raise RuntimeError(
            "CRITICAL SECURITY CONFIGURATION ERROR: FORENSICOPS_JWT_SECRET environment variable is missing in production. "
            "A cryptographically strong secret must be explicitly set."
        )

    # For local-first air-gapped workstations: load or create persistent vault secret
    vault_dir = Path(os.getenv("FORENSICOPS_VAULT_DIR", "vault"))
    vault_dir.mkdir(parents=True, exist_ok=True)
    secret_file = vault_dir / ".jwt_secret"
    if secret_file.exists():
        try:
            persisted = secret_file.read_text(encoding="utf-8").strip()
            if persisted:
                return persisted
        except Exception:
            pass

    # Generate cryptographically secure 64-character secret and persist
    new_secret = secrets.token_urlsafe(48)
    try:
        secret_file.write_text(new_secret, encoding="utf-8")
    except Exception:
        pass
    return new_secret


def hash_password(password: str) -> str:
    """Generate secure bcrypt password hash with standard 72-byte truncation."""
    pwd_bytes = password.encode("utf-8")[:72]
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(pwd_bytes, salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against a stored bcrypt hash."""
    try:
        pwd_bytes = plain_password.encode("utf-8")[:72]
        hash_bytes = hashed_password.encode("utf-8")
        return bcrypt.checkpw(pwd_bytes, hash_bytes)
    except Exception:
        return False


def create_access_token(
    data: Dict[str, Any],
    expires_delta: Optional[timedelta] = None,
) -> str:
    """Create a signed JWT access token containing investigator claims."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": int(expire.timestamp())})
    return jwt.encode(to_encode, get_jwt_secret(), algorithm=ALGORITHM)


def decode_access_token(token: str) -> Optional[TokenPayload]:
    """Decode and validate a signed JWT access token."""
    try:
        payload = jwt.decode(token, get_jwt_secret(), algorithms=[ALGORITHM])
        return TokenPayload(**payload)
    except (JWTError, ValidationError, Exception):
        return None
