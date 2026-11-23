"""Unit & Integration Tests for Case Manager & Forensic Case Vault Sharing.

Standards:
- SQLite persistence of Case records (status lifecycle, metadata, serialized state).
- Peer Review Case Vault filtering (is_shared_to_vault).
- REST endpoint validation: list, get, create, patch, share, delete.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from backend.app.main import create_app
from backend.app.db.sqlite_store import get_llm_state_store, reset_llm_state_store


@pytest.fixture
def clean_env():
    """Ensure clean isolated SQLite store."""
    reset_llm_state_store()
    yield
    reset_llm_state_store()


@pytest.fixture
def client(clean_env) -> TestClient:
    app = create_app()
    return TestClient(app)


def test_case_crud_lifecycle(client: TestClient):
    """Test full case creation, reading, patching, and deletion."""
    # 1. Create Case
    create_resp = client.post(
        "/api/cases",
        json={
            "case_id": "CASE-2026-ALPHA",
            "case_name": "Ransomware Lateral Movement Hunt",
            "organization_name": "CyberCorp Financial",
            "investigation_goal": "Identify initial access vector and PsExec execution across domain",
            "status": "OPEN",
        },
    )
    assert create_resp.status_code == 201
    created_data = create_resp.json()
    assert created_data["case_id"] == "CASE-2026-ALPHA"
    assert created_data["case_name"] == "Ransomware Lateral Movement Hunt"
    assert created_data["organization_name"] == "CyberCorp Financial"
    assert created_data["status"] == "OPEN"
    assert created_data["is_shared_to_vault"] is False

    # 2. Get Case
    get_resp = client.get("/api/cases/CASE-2026-ALPHA")
    assert get_resp.status_code == 200
    assert get_resp.json()["case_id"] == "CASE-2026-ALPHA"

    # 3. Patch Status to IN_REVIEW
    patch_resp = client.patch(
        "/api/cases/CASE-2026-ALPHA",
        json={"status": "IN_REVIEW", "investigation_goal": "Updated investigation goal"},
    )
    assert patch_resp.status_code == 200
    patched_data = patch_resp.json()
    assert patched_data["status"] == "IN_REVIEW"
    assert patched_data["investigation_goal"] == "Updated investigation goal"

    # 4. Search and Filter
    list_resp = client.get("/api/cases?search=CyberCorp&status=IN_REVIEW")
    assert list_resp.status_code == 200
    cases = list_resp.json()
    assert len(cases) == 1
    assert cases[0]["case_id"] == "CASE-2026-ALPHA"

    # 5. Delete Case
    del_resp = client.delete("/api/cases/CASE-2026-ALPHA")
    assert del_resp.status_code == 200
    assert client.get("/api/cases/CASE-2026-ALPHA").status_code == 404


def test_forensic_case_vault_sharing(client: TestClient):
    """Test sharing cases to the Forensic Case Vault for peer review."""
    # Create two cases
    client.post(
        "/api/cases",
        json={
            "case_id": "CASE-VAULT-01",
            "case_name": "Shared Case for Peer Review",
            "organization_name": "SecOps Global",
            "status": "COMPLETED",
        },
    )
    client.post(
        "/api/cases",
        json={
            "case_id": "CASE-PRIVATE-02",
            "case_name": "Private Internal Case",
            "organization_name": "SecOps Global",
            "status": "OPEN",
        },
    )

    # Initially, vault should be empty
    vault_resp = client.get("/api/cases/vault/shared")
    assert vault_resp.status_code == 200
    assert len(vault_resp.json()) == 0

    # Toggle share on CASE-VAULT-01
    share_resp = client.post(
        "/api/cases/CASE-VAULT-01/share",
        json={"is_shared_to_vault": True},
    )
    assert share_resp.status_code == 200
    assert share_resp.json()["is_shared_to_vault"] is True

    # Vault should now list CASE-VAULT-01
    vault_resp_after = client.get("/api/cases/vault/shared")
    assert vault_resp_after.status_code == 200
    shared_cases = vault_resp_after.json()
    assert len(shared_cases) == 1
    assert shared_cases[0]["case_id"] == "CASE-VAULT-01"

    # Unshare
    unshare_resp = client.post(
        "/api/cases/CASE-VAULT-01/share",
        json={"is_shared_to_vault": False},
    )
    assert unshare_resp.status_code == 200
    assert unshare_resp.json()["is_shared_to_vault"] is False
    assert len(client.get("/api/cases/vault/shared").json()) == 0
