"""ForensicOps AI Agent & Workflow layer."""
from backend.app.agent.memory_protocol import (
    DEFAULT_DFIR_KNOWLEDGE,
    KnowledgeAndMemoryProvider,
    SQLiteFeedbackMemoryProvider,
)
from backend.app.agent.lmstudio_client import (
    LMStudioClient,
    build_chat_completions_url,
    build_forensic_system_prompt,
    clean_json_markdown,
    run_provider_smoke_test,
    wrap_untrusted_evidence,
)
from backend.app.agent.provider_registry import (
    LLMProviderConfig,
    LLMProviderPublicDTO,
    LLMProviderRegistry,
    get_provider_registry,
    reset_provider_registry,
)
from backend.app.agent.ollama_client import OllamaClient
from backend.app.agent.tools import (
    create_view_tool,
    extract_pivots_from_findings,
    extract_pivots_from_goal_result,
    hybrid_search_tool,
    query_findings_tool,
    timeline_window_tool,
)
from backend.app.agent.report_builder import (
    AIFTRubricItem,
    CitedReport,
    CustodyAuditSection,
    DeterministicCorrelationRecord,
    EvidenceConflict,
    ExecutiveSummarySection,
    PatientZeroRemediationSection,
    ReportBuilder,
    ReportProvenance,
    ReportStore,
    TimelineEntry,
    get_report_store,
)
from backend.app.agent.hypothesis_planner import HypothesisPlannerService
from backend.app.agent.graph import (
    ForensicOpsWorkflowEngine,
    get_starter_blueprints,
)

__all__ = [
    "KnowledgeAndMemoryProvider",
    "SQLiteFeedbackMemoryProvider",
    "DEFAULT_DFIR_KNOWLEDGE",
    "LMStudioClient",
    "OllamaClient",
    "wrap_untrusted_evidence",
    "build_forensic_system_prompt",
    "clean_json_markdown",
    "query_findings_tool",
    "timeline_window_tool",
    "hybrid_search_tool",
    "create_view_tool",
    "extract_pivots_from_findings",
    "extract_pivots_from_goal_result",
    "AIFTRubricItem",
    "TimelineEntry",
    "ExecutiveSummarySection",
    "CustodyAuditSection",
    "PatientZeroRemediationSection",
    "CitedReport",
    "ReportBuilder",
    "ForensicOpsWorkflowEngine",
    "get_starter_blueprints",
    "HypothesisPlannerService",
]
