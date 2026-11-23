"""PoC 6: Dead Code in Report Builder Custody Verification.
Verifies that ReportBuilder.build_report checks hasattr(custody_engine, 'verify_custody_chain'),
which does not exist on CustodyEngine (the method is named verify_chain or verify_chain_integrity),
causing Section 2 to ALWAYS report 'VERIFIED (100% Chain Integrity)' even when the custody
ledger is deliberately corrupted or broken!
"""
import sys
from pathlib import Path
from backend.app.agent.report_builder import ReportBuilder
from backend.app.core.custody_engine import CustodyEngine
from backend.app.core.storage import ForensicStore

def run_poc():
    temp_dir = Path("vault/poc_broken_chain")
    temp_dir.mkdir(parents=True, exist_ok=True)
    
    # 1. Initialize engine and storage
    custody = CustodyEngine(vault_root=temp_dir)
    storage = ForensicStore(db_path=str(temp_dir / "store.duckdb"))
    
    # 2. Append entries
    custody.append_custody_entry(case_id="case_poc", actor="alice", action="INTAKE", artifact_sha256="abc1")
    custody.append_custody_entry(case_id="case_poc", actor="bob", action="PARSE", artifact_sha256="abc2")

    # 3. Deliberately tamper with the SQLite custody table to corrupt entry_hash and break the chain!
    with custody._get_connection() as conn:
        conn.execute("UPDATE custody_chain SET entry_hash = 'TAMPERED_FORGED_HASH_999' WHERE seq_id = 1;")
        conn.commit()

    # 4. Verify that real integrity check detects tampering:
    is_valid, errors = custody.verify_chain_integrity()
    print(f"CustodyEngine.verify_chain_integrity(): is_valid={is_valid}, errors={errors}")
    assert not is_valid, "Tamper should have been detected by CustodyEngine!"

    # 5. Build report and check Section 2 text:
    report = ReportBuilder.build_report(
        case_id="case_poc",
        node_results=[],
        storage=storage,
        custody_engine=custody,
    )

    md = report.to_markdown()
    print("\n--- Excerpt from Report Section 2 ---")
    for line in md.split("\n"):
        if "Custody Ledger Verification:" in line:
            print(line)
            if "100% Chain Integrity" in line:
                print("CONFIRMED: Report claims 'VERIFIED (100% Chain Integrity)' despite corrupted custody chain!")
                return True

    print("FAILED: Did not find expected text")
    return False

if __name__ == "__main__":
    success = run_poc()
    sys.exit(0 if success else 1)
