"""Global Pytest Configuration and Test Harness for ForensicOps AI.

Ensures all unit, integration, and security tests execute with deterministic,
zero-latency mock LLM fixtures without sending live API traffic over the network.
"""
from __future__ import annotations

import os

# Enforce mock mode and air-gapped isolation for automated test suites
os.environ["LLM_MOCK_MODE"] = "true"
os.environ["FORENSICOPS_LIVE_LLM"] = "false"
os.environ.setdefault("HUMAN_APPROVAL_HMAC_SECRET", "test-secure-approval-hmac-secret-key-32b")
os.environ.setdefault("FORENSICOPS_ALLOW_PRIVATE_SIEM", "true")
