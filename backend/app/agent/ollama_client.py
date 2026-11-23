"""Backwards-compatibility shim for Ollama client, now aliased to LMStudioClient.

Standards:
- Local-first & Air-Gapped: Defaults to local LM Studio (http://localhost:1234/v1).
- Non-negotiable forensic integrity & anti-hallucination guardrails.
"""
from __future__ import annotations

from backend.app.agent.lmstudio_client import (
    LMStudioClient,
    build_forensic_system_prompt,
    clean_json_markdown,
    wrap_untrusted_evidence,
)

# OllamaClient is aliased to LMStudioClient for seamless backwards compatibility
OllamaClient = LMStudioClient

__all__ = [
    "LMStudioClient",
    "OllamaClient",
    "wrap_untrusted_evidence",
    "build_forensic_system_prompt",
    "clean_json_markdown",
]
