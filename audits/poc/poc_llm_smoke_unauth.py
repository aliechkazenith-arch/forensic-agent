"""PoC 5: Unauthenticated Public LLM Provider Smoke-Testing.
Verifies that POST /api/llm/smoke-test/{provider_id} allows unauthenticated callers
to trigger remote LLM completions, exposing endpoints and draining token budgets.
"""
import sys
import unittest.mock as mock
from fastapi.testclient import TestClient
from backend.app.main import create_app

def run_poc():
    app = create_app()
    client = TestClient(app)

    # Mock the actual network call to avoid waiting 15s if LM studio is offline
    with mock.patch("backend.app.api.llm.run_provider_smoke_test") as mock_smoke:
        mock_smoke.return_value = {
            "provider_id": "lm_studio_local",
            "success": True,
            "latency_ms": 12,
            "response_preview": "Healthy",
            "error_detail": None,
        }
        # Calling smoke test on lm_studio_local without any Authorization header
        resp = client.post("/api/llm/smoke-test/lm_studio_local")
        print(f"POST /api/llm/smoke-test/lm_studio_local Status: {resp.status_code}")
        
        if resp.status_code == 200:
            data = resp.json()
            print(f"CONFIRMED: Smoke test triggered unauthenticated! Result: success={data.get('success')}, latency={data.get('latency_ms')}ms")
            return True
        else:
            print(f"FAILED: Expected 200, got {resp.status_code}: {resp.text}")
            return False

if __name__ == "__main__":
    success = run_poc()
    sys.exit(0 if success else 1)
