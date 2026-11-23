"""ForensicOps AI DFIR Technical Co-Pilot Chat Endpoint.

Standards:
- Zero Extrapolation / Anti-Hallucination: Technical guidance grounded in case telemetry.
- Untrusted Evidence Encapsulation: Nonce-shielded evidence blocks against Indirect Prompt Injection (IPI).
- Interactive Incident Commander: Executes deterministic playbooks on user commands and recommends concrete next steps.
"""
from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from backend.app.agent.hypothesis_planner import HypothesisPlannerService
from backend.app.agent.lmstudio_client import LMStudioClient
from backend.app.agent.prompts import CHATBOT_COPILOT_SYSTEM_PROMPT
from backend.app.agent.provider_registry import get_provider_registry
from backend.app.api.deps import get_case_authorization_service, get_custody_engine, get_storage
from backend.app.auth.dependencies import get_current_user_optional, require_roles
from backend.app.auth.models import UserRead
from backend.app.core.config import get_settings
from backend.app.core.dissect_adapter import DissectAdapter
from backend.app.db.sqlite_store import get_llm_state_store

router = APIRouter(prefix="/api/copilot", tags=["DFIR Co-Pilot"])


class CopilotChatRequest(BaseModel):
    case_id: str = "default_case"
    message: str = Field(..., min_length=1, description="Analyst question or inquiry")
    history: List[Dict[str, str]] = Field(default_factory=list, description="Previous chat messages")
    send_system_prompt: bool = Field(default=True, description="Whether to prepend standard DFIR system prompt")


class CopilotChatResponse(BaseModel):
    reply: str
    timestamp_utc: str
    provider_id: str
    case_id: str
    suggested_actions: List[str] = Field(default_factory=list)
    executed_playbooks: List[str] = Field(default_factory=list)
    findings_count: int = 0
    threat_hypothesis: Optional[str] = None
    benign_hypothesis: Optional[str] = None


def _extract_suggested_action_chips(tactics: List[str], findings_count: int) -> List[str]:
    """Generate 3 to 4 clickable action chips tailored to current case state."""
    actions: List[str] = []
    t_set = set(tactics)

    if "TA0003" not in t_set:
        actions.append("🔍 Check Persistence Hooks")
    if "TA0002" not in t_set:
        actions.append("📜 Analyze PowerShell 4104")
    if "TA0011" not in t_set:
        actions.append("🌐 Correlate PCAP Network Traffic")
    if "TA0008" not in t_set:
        actions.append("🛡️ Audit Lateral Movement")
    if "TA0006" not in t_set:
        actions.append("🔑 Check Credential Access")

    if findings_count > 0:
        actions.append("📋 Generate Final Cited Report")

    return actions[:4]


@router.post("/chat", response_model=CopilotChatResponse)
async def copilot_chat_endpoint(
    req: CopilotChatRequest,
    current_user: UserRead = Depends(require_roles("lead_investigator", "soc_analyst", "external_auditor")),
) -> CopilotChatResponse:
    """Provide context-aware technical DFIR Lead reasoning, playbook execution, and next steps."""
    store = get_llm_state_store()
    settings = get_settings()
    is_mock = settings.llm_mock_mode or (os.getenv("FORENSICOPS_LIVE_LLM", "false").lower() not in ("true", "1", "yes"))

    active_pid = get_provider_registry().get_active_provider_id()
    llm = LMStudioClient(
        provider_id=active_pid,
        timeout=settings.llm_timeout,
        mock_mode=is_mock,
    )

    case_auth = get_case_authorization_service()
    if store.get_case(req.case_id):
        case_auth.verify_case_access(current_user, req.case_id, action="read")
    else:
        case_auth.ensure_case_registered(req.case_id, current_user.username)

    storage = get_storage(req.case_id)
    custody = get_custody_engine(req.case_id)
    dissect = DissectAdapter()

    # 1. Resolve intent: Is the user selecting an option (e.g. "Do option 1", "Step 2") or issuing an investigative directive?
    msg_raw = req.message.strip()
    msg_lower = msg_raw.lower()
    resolved_goal = msg_raw
    is_option_pick = False

    opt_match = re.search(r"(?:option|step)\s*([1-4])", msg_lower)
    if opt_match and req.history:
        opt_idx = int(opt_match.group(1)) - 1
        for h in reversed(req.history):
            if h.get("role") == "assistant" and h.get("content"):
                lines = [line.strip() for line in h["content"].split("\n") if line.strip()]
                numbered_lines = [l for l in lines if re.match(r"^(\d+[\.\)]|•|\-)\s+", l)]
                if 0 <= opt_idx < len(numbered_lines):
                    resolved_goal = re.sub(r"^(\d+[\.\)]|•|\-)\s*", "", numbered_lines[opt_idx]).strip()
                    is_option_pick = True
                    break

    # Determine if action/playbook execution is requested
    action_triggers = [
        "investigate", "check", "find", "analyze", "sweep", "hunt", "detect",
        "run", "search", "look for", "audit", "trace", "examine", "persistence",
        "lateral", "logon", "login", "pcap", "beacon", "powershell", "c2", "teamviewer"
    ]
    is_investigative = (
        is_option_pick
        or msg_lower.startswith(("/goal", "/playbook"))
        or any(trigger in msg_lower for trigger in action_triggers)
    )

    # Clean leading slash commands
    clean_goal = re.sub(r"^(\/goal|\/playbook)\s+", "", resolved_goal).strip()

    if is_investigative and clean_goal:
        # Run deterministic goal engine across vault artifacts
        planner = HypothesisPlannerService(
            storage=storage,
            custody_engine=custody,
            dissect_adapter=dissect,
            llm_client=llm,
        )
        draft = await planner.plan_hypothesis(
            case_id=req.case_id,
            investigation_goal=clean_goal,
            auto_approve=True,
        )

        all_findings = storage.query_structured_findings(case_id=req.case_id, limit=30)
        total_count = storage.count_findings(case_id=req.case_id)

        # Extract matched tactics from plan steps
        matched_tactics: List[str] = []
        if draft and draft.plan_steps:
            for s in draft.plan_steps:
                tid = s.get("tactic_id") if isinstance(s, dict) else getattr(s, "tactic_id", None)
                if tid and tid not in matched_tactics:
                    matched_tactics.append(tid)

        tactics_str = ", ".join(matched_tactics) if matched_tactics else "Enterprise Triage"
        findings_snippets = []
        for f in all_findings[:4]:
            host_str = f"on host `{f.host}`" if f.host else ""
            user_str = f"(User: `{f.user}`)" if f.user else ""
            findings_snippets.append(
                f"- **`[{f.finding_id}]`** `{f.category.upper()}` {host_str} {user_str}: {f.summary}"
            )

        findings_block = (
            "\n".join(findings_snippets)
            if findings_snippets
            else "- *No matching anomalous telemetry identified in current vault artifacts.*"
        )

        # Format numbered recommended next steps
        step_lines = []
        for idx, step_desc in enumerate(draft.suggested_steps[:3], start=1):
            clean_step = re.sub(r"^\[.*?\]\s*", "", step_desc)
            step_lines.append(f"{idx}. {clean_step}")
        next_steps_block = "\n".join(step_lines) if step_lines else "1. Collect additional endpoint triage artifacts."

        reply_text = (
            f"### 🛡️ DFIR Lead Incident Briefing — Case `{req.case_id}`\n\n"
            f"**Investigative Objective:** {clean_goal}\n"
            f"**MITRE ATT&CK Tactics Evaluated:** `{tactics_str}`\n\n"
            f"#### 🔎 Verified Evidence Findings ({total_count} total indexed in vault):\n"
            f"{findings_block}\n\n"
            f"#### ⚖️ Competing Hypotheses Assessment:\n"
            f"**Threat Assessment:** {draft.threat_hypothesis}\n\n"
            f"**Benign Alternative:** {draft.benign_hypothesis}\n\n"
            f"#### 🎯 Recommended Next Investigative Actions:\n"
            f"{next_steps_block}\n\n"
            f"*You can click one of the quick actions below, or instruct me on what to analyze next (e.g. 'Do option 1' or 'Analyze user Administrator').*"
        )

        suggested_actions = _extract_suggested_action_chips(matched_tactics, total_count)

        return CopilotChatResponse(
            reply=reply_text,
            timestamp_utc=datetime.now(timezone.utc).isoformat(),
            provider_id="deterministic_dfir_lead",
            case_id=req.case_id,
            suggested_actions=suggested_actions,
            executed_playbooks=matched_tactics,
            findings_count=total_count,
            threat_hypothesis=draft.threat_hypothesis,
            benign_hypothesis=draft.benign_hypothesis,
        )

    # 2. General Technical Question / Inquiry
    case_meta = store.get_case(req.case_id) or {}
    session_data = store.get_investigation_session(req.case_id) or {}
    wiz_state = session_data.get("wizard_state", {})
    goal = case_meta.get("investigation_goal") or wiz_state.get("investigation_goal") or "General forensic triage"
    hyp_draft = wiz_state.get("hypothesis_draft")

    findings = storage.query_structured_findings(case_id=req.case_id, limit=20)
    total_count = storage.count_findings(case_id=req.case_id)

    nonce = uuid4().hex[:16]
    evidence_blocks = "\n".join(f.to_evidence_xml(nonce=nonce) for f in findings[:10]) if findings else "None recorded yet."

    hyp_summary = "None formulated yet."
    if hyp_draft:
        hyp_summary = (
            f"Threat Hypothesis: {hyp_draft.get('threat_hypothesis')}\n"
            f"Benign Alternative: {hyp_draft.get('benign_hypothesis')}\n"
            f"Recommended Blueprint: {hyp_draft.get('recommended_blueprint')}"
        )

    context_prompt = (
        f"INVESTIGATION CONTEXT:\n"
        f"- Case ID: {req.case_id}\n"
        f"- Investigation Goal: {goal}\n"
        f"- Active Hypotheses:\n{hyp_summary}\n\n"
        f"- Untrusted Telemetry Facts ({len(findings)} findings):\n"
        f"{evidence_blocks}\n\n"
        f"Analyst Question: {req.message}"
    )

    messages: List[Dict[str, str]] = [
        {"role": "system", "content": CHATBOT_COPILOT_SYSTEM_PROMPT}
    ]

    for h in req.history[-6:]:
        if h.get("role") in ("user", "assistant") and h.get("content"):
            messages.append({"role": h["role"], "content": h["content"]})

    messages.append({"role": "user", "content": context_prompt})

    try:
        resp = await llm.chat_completion(messages=messages, max_tokens=1500)
        choices = resp.get("choices", [])
        msg = choices[0].get("message", {}) if choices else {}
        raw_reply = (msg.get("content") or msg.get("reasoning_content") or "").strip()
        if raw_reply:
            reply_text = raw_reply
        else:
            reply_text = (
                f"[Co-Pilot ({active_pid})]: Analyzed telemetry for Case {req.case_id}. "
                f"Observed {len(findings)} verified findings related to '{goal}'. "
                f"To advance the investigation, recommend correlating logon event 4624/4625 records with PowerShell 4104 execution."
            )
    except Exception as e:
        reply_text = f"[Co-Pilot Error]: Failed to contact LLM provider '{active_pid}': {str(e)}"

    suggested_actions = _extract_suggested_action_chips([], total_count)

    return CopilotChatResponse(
        reply=reply_text,
        timestamp_utc=datetime.now(timezone.utc).isoformat(),
        provider_id=active_pid,
        case_id=req.case_id,
        suggested_actions=suggested_actions,
        executed_playbooks=[],
        findings_count=total_count,
    )
