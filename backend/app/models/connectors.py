"""Pydantic v2 data models for Hybrid SIEM Connectors.

Standards:
- Read-Only SIEM Query Connectors with SHA-256 Query-Snapshot Hashes
- Deterministic Finding Normalization
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional
from uuid import uuid4
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


SIEMType = Literal["elasticsearch", "wazuh", "splunk"]


def get_current_utc() -> str:
    """Return formatted ISO-8601 UTC timestamp."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class SIEMConnectionConfig(BaseModel):
    """Connection parameters and authentication credentials for SIEM query adapters."""
    model_config = ConfigDict(extra="ignore")

    siem_type: SIEMType
    endpoint_url: str
    api_key: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    token: Optional[str] = None
    verify_ssl: bool = True
    timeout_seconds: float = 30.0
    index_pattern: Optional[str] = None
    headers: Dict[str, str] = Field(default_factory=dict)
    allowed_hosts: Optional[List[str]] = None

    @model_validator(mode="after")
    def validate_endpoint_url_ssrf(self) -> SIEMConnectionConfig:
        """Prevent SSRF to loopback, link-local, cloud metadata, or unapproved private IP ranges."""
        from backend.app.core.network_validator import validate_url_ssrf
        validate_url_ssrf(self.endpoint_url, allowed_targets=self.allowed_hosts)
        return self


class SIEMQuerySnapshot(BaseModel):
    """Cryptographic record of a SIEM query execution and response payload snapshot."""
    model_config = ConfigDict(frozen=True)

    snapshot_id: str = Field(default_factory=lambda: str(uuid4()))
    case_id: str
    siem_type: SIEMType
    query_string: str
    snapshot_sha256: str
    record_count: int
    timestamp_utc: str = Field(default_factory=get_current_utc)
    raw_reference: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class SIEMConnectionCreateRequest(BaseModel):
    """Request model for creating a managed SIEM connection with encrypted credentials."""
    model_config = ConfigDict(extra="ignore")

    case_id: str
    siem_type: SIEMType
    endpoint_url: str
    index_pattern: Optional[str] = None
    allowed_hosts: Optional[List[str]] = None
    headers: Dict[str, str] = Field(default_factory=dict)
    verify_ssl: bool = True
    timeout_seconds: float = 30.0
    username: Optional[str] = None
    password: Optional[str] = None
    api_key: Optional[str] = None
    token: Optional[str] = None

    @model_validator(mode="after")
    def validate_endpoint(self) -> SIEMConnectionCreateRequest:
        from backend.app.core.network_validator import validate_url_ssrf
        validate_url_ssrf(self.endpoint_url, allowed_targets=self.allowed_hosts)
        return self


class SIEMConnectionUpdateRequest(BaseModel):
    """Request model for updating an existing SIEM connection.
    
    Blank or omitted password/api_key/token fields preserve existing stored secrets.
    Explicit removal flags must be used to delete credentials.
    """
    model_config = ConfigDict(extra="ignore")

    siem_type: Optional[SIEMType] = None
    endpoint_url: Optional[str] = None
    index_pattern: Optional[str] = None
    allowed_hosts: Optional[List[str]] = None
    headers: Optional[Dict[str, str]] = None
    verify_ssl: Optional[bool] = None
    timeout_seconds: Optional[float] = None
    username: Optional[str] = None
    password: Optional[str] = None
    api_key: Optional[str] = None
    token: Optional[str] = None
    remove_password: bool = False
    remove_api_key: bool = False
    remove_token: bool = False
    clear_credentials: bool = False

    @model_validator(mode="after")
    def validate_endpoint(self) -> SIEMConnectionUpdateRequest:
        if self.endpoint_url:
            from backend.app.core.network_validator import validate_url_ssrf
            validate_url_ssrf(self.endpoint_url, allowed_targets=self.allowed_hosts)
        return self


class SIEMConnectionResponse(BaseModel):
    """Safe response model for SIEM connection details.
    
    Zero Secret Leakage: Never returns plaintext credentials, tokens, or raw ciphertexts.
    Only exposes boolean presence indicators (has_password, has_api_key, has_token).
    """
    model_config = ConfigDict(extra="ignore")

    connection_id: str
    case_id: str
    siem_type: SIEMType
    endpoint_url: str
    index_pattern: Optional[str] = None
    allowed_hosts: Optional[List[str]] = None
    headers: Dict[str, str] = Field(default_factory=dict)
    verify_ssl: bool = True
    timeout_seconds: float = 30.0
    username: Optional[str] = None
    has_password: bool = False
    has_api_key: bool = False
    has_token: bool = False
    created_by: str
    created_at_utc: str
    updated_at_utc: str


class SIEMConnectionTestResponse(BaseModel):
    """Response model for SIEM connection test results."""
    status: str  # "success" or "error"
    connection_id: str
    siem_type: SIEMType
    reachable: bool
    authenticated: bool
    latency_ms: int = 0
    message: str = ""

