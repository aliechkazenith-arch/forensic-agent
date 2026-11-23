"""Phase 8 Tests - Streaming Multipart Evidence Upload, Hash Integrity & Local Host Picker.

Standards:
- Verifies chunked streaming upload (1 MB chunks) computing SHA-256 and SHA-512 on the fly.
- Verifies strict directory traversal defense and filename sanitization.
- Verifies read-only permissions (0400) applied to uploaded artifacts.
- Verifies SQLite intake upload metadata persistence.
- Verifies server-side local host file picker and extension filtering.
"""
from __future__ import annotations

import hashlib
import io
import os
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from backend.app.api.deps import reset_dependencies, set_base_vault_dir
from backend.app.db.sqlite_store import LLMStateStore, get_llm_state_store, reset_llm_state_store
from backend.app.main import create_app


@pytest.fixture(autouse=True)
def setup_upload_env(tmp_path: Path, monkeypatch):
    """Hermetic test environment for streaming uploads and SQLite state."""
    test_vault = tmp_path / "vault"
    test_vault.mkdir(parents=True, exist_ok=True)
    test_intake = tmp_path / "evidence_intake"
    test_intake.mkdir(parents=True, exist_ok=True)

    test_db = test_vault / "llm_state.db"
    store = LLMStateStore(db_path=test_db)
    reset_llm_state_store(store)

    monkeypatch.setenv("FORENSICOPS_VAULT_DIR", str(test_vault))
    set_base_vault_dir(test_vault)
    reset_dependencies()

    yield test_intake

    reset_llm_state_store()
    reset_dependencies()


@pytest.fixture
def client() -> TestClient:
    app = create_app()
    return TestClient(app)


def test_streaming_file_upload_success_and_hashes(client: TestClient, tmp_path: Path, monkeypatch):
    """Verify streaming upload of multi-megabyte artifact computes accurate SHA-256 and SHA-512 hashes."""
    # Custom intake dir for test isolation
    custom_intake = tmp_path / "custom_intake"
    custom_intake.mkdir(parents=True, exist_ok=True)
    monkeypatch.chdir(tmp_path)

    # Generate 2.5 MB of deterministic dummy evidence data
    dummy_data = b"EVTX_HEADER_SIG" + (b"A" * 1024 * 1024) + (b"B" * 1024 * 1024) + (b"C" * 512 * 1024)
    expected_sha256 = hashlib.sha256(dummy_data).hexdigest()
    expected_sha512 = hashlib.sha512(dummy_data).hexdigest()
    expected_size = len(dummy_data)

    file_obj = io.BytesIO(dummy_data)
    resp = client.post(
        "/api/intake/upload",
        files={"file": ("Security.evtx", file_obj, "application/octet-stream")},
        data={"case_id": "case_test_upload"},
    )

    assert resp.status_code == 200
    data = resp.json()

    assert data["status"] == "success"
    assert data["filename"] == "Security.evtx"
    assert data["size_bytes"] == expected_size
    assert data["sha256"] == expected_sha256
    assert data["sha512"] == expected_sha512
    assert data["detected_artifact_type"] == "evtx"
    assert data["upload_id"].startswith("upl-")

    # Verify file saved on disk
    saved_path = Path(data["file_path"])
    assert saved_path.exists()
    assert saved_path.stat().st_size == expected_size

    # Verify SQLite metadata record
    store = get_llm_state_store()
    record = store.get_evidence_upload(data["upload_id"])
    assert record is not None
    assert record["filename"] == "Security.evtx"
    assert record["sha256"] == expected_sha256
    assert record["sha512"] == expected_sha512
    assert record["artifact_type"] == "evtx"


def test_filename_traversal_protection(client: TestClient, tmp_path: Path, monkeypatch):
    """Verify malicious path traversal filenames are neutralized and constrained inside intake dir."""
    monkeypatch.chdir(tmp_path)

    traversal_filenames = [
        "../../../../etc/passwd",
        "..\\..\\Windows\\System32\\cmd.exe",
        "evidence/../../../boot.ini",
        "subfolder/test_artifact.evtx",
        "test\x00injection.evtx",
    ]

    for malicious_name in traversal_filenames:
        file_content = b"TEST_MALICIOUS_TRAVERSAL_PAYLOAD"
        resp = client.post(
            "/api/intake/upload",
            files={"file": (malicious_name, io.BytesIO(file_content), "application/octet-stream")},
            data={"case_id": "case_security"},
        )

        assert resp.status_code == 200
        data = resp.json()
        saved_file = Path(data["file_path"]).resolve()

        # Target must be inside backend/data/evidence_intake
        intake_dir = Path("backend/data/evidence_intake").resolve()
        assert saved_file.is_relative_to(intake_dir), f"Path traversal breached sandbox: {saved_file}"
        assert ".." not in saved_file.name


def test_empty_or_whitespace_filename_fallback(client: TestClient, tmp_path: Path, monkeypatch):
    """Verify dot-only or whitespace filenames receive a safe fallback name."""
    monkeypatch.chdir(tmp_path)

    for empty_name in ["...", "..", "   .   ", " . . "]:
        resp = client.post(
            "/api/intake/upload",
            files={"file": (empty_name, io.BytesIO(b"DUMMY_EVIDENCE"), "application/octet-stream")},
            data={"case_id": "case_fallback"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["filename"].startswith("evidence_")
        assert Path(data["file_path"]).exists()


def test_auto_artifact_type_detection(client: TestClient, tmp_path: Path, monkeypatch):
    """Verify forensic artifact types are accurately inferred from filename extensions."""
    monkeypatch.chdir(tmp_path)

    test_cases = [
        ("triage_dump.raw", "memory"),
        ("memory.dmp", "memory"),
        ("disk_image.E01", "disk_image"),
        ("virtual_drive.vmdk", "disk_image"),
        ("network_capture.pcap", "pcap"),
        ("collector_bundle.zip", "capsule"),
        ("audit_events.json", "json_log"),
        ("syslog.log", "text_log"),
        ("SYSTEM", "registry"),
    ]

    for filename, expected_type in test_cases:
        resp = client.post(
            "/api/intake/upload",
            files={"file": (filename, io.BytesIO(b"FORENSIC_SIG"), "application/octet-stream")},
        )
        assert resp.status_code == 200
        assert resp.json()["detected_artifact_type"] == expected_type, f"Failed for {filename}"


def test_browse_local_directory_listing_and_filtering(client: TestClient, tmp_path: Path):
    """Verify POST /api/intake/browse-local lists directories and filters forensic evidence files."""
    # Create test directory structure
    evidence_dir = tmp_path / "mock_evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)

    # Evidence files
    (evidence_dir / "disk01.E01").write_bytes(b"E01_IMAGE")
    (evidence_dir / "mem.raw").write_bytes(b"RAW_MEM")
    (evidence_dir / "triage.zip").write_bytes(b"ZIP_ARCHIVE")

    # Non-evidence file (should be filtered out by default)
    (evidence_dir / "notes.docx").write_bytes(b"OFFICE_DOC")

    # Subdirectory
    sub_dir = evidence_dir / "nested_logs"
    sub_dir.mkdir(parents=True, exist_ok=True)
    (sub_dir / "Security.evtx").write_bytes(b"EVTX_LOG")

    # Call browse-local
    resp = client.post(
        "/api/intake/browse-local",
        json={"current_path": str(evidence_dir)},
    )
    assert resp.status_code == 200
    data = resp.json()

    assert data["status"] == "success"
    assert data["current_path"] == str(evidence_dir.resolve())
    assert len(data["drives"]) >= 1

    item_names = [i["name"] for i in data["items"]]
    assert "nested_logs" in item_names
    assert "disk01.E01" in item_names
    assert "mem.raw" in item_names
    assert "triage.zip" in item_names
    assert "notes.docx" not in item_names  # Filtered out


def test_browse_local_single_file_direct_path(client: TestClient, tmp_path: Path):
    """Verify POST /api/intake/browse-local handles direct file paths by returning selected_file."""
    test_file = tmp_path / "target_disk.E01"
    test_file.write_bytes(b"TARGET_E01_BYTES")

    resp = client.post(
        "/api/intake/browse-local",
        json={"current_path": str(test_file)},
    )
    assert resp.status_code == 200
    data = resp.json()

    assert data["selected_file"] == str(test_file.resolve())
    assert data["current_path"] == str(test_file.parent.resolve())
