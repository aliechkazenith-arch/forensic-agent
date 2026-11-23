/**
 * ForensicOps AI API Client.
 * Connects React UI to FastAPI REST and Server-Sent Events (SSE) endpoints.
 */
import {
  ArtifactRecord,
  CitedReport,
  CustodyChainEntry,
  DryRunAutoMapperResult,
  ForensicFinding,
  HumanApprovalToken,
  HumanFeedbackRecord,
  SIEMConnectionConfig,
  SIEMConnectionCreatePayload,
  SIEMConnectionResponse,
  SIEMConnectionTestResponse,
  SIEMConnectionUpdatePayload,
  SIEMQuerySnapshot,
  ToolPluginCard,
  WorkflowDefinition,
  WorkflowEdgePayload,
  WorkflowExecutionState,
  AuthStatus,
  TokenResponse,
  User,
  UserCreatePayload,
  UserSetupPayload,
  LLMProvider,
  LLMSmokeTestResult,
  EvidenceUploadResult,
  BrowseLocalResult,
  InvestigationSession,
  HypothesisDraft,
  CaseRecord,
  CopilotChatResponse,
  DeterministicGoalPlan,
  MitrePlaybook,
  ScopedFilterParams,
  ApprovalRequest,
  ApprovalStatus,
  CompetingHypothesis,
  InvestigationRecord,
  InvestigationTimelineEntry,
} from "../types";


const API_BASE = (import.meta as any).env?.VITE_API_BASE_URL || "http://localhost:8000/api";

function getStoredToken(): string | null {
  return sessionStorage.getItem("forensicops_token");
}

async function request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  const url = `${API_BASE}${endpoint}`;
  const token = getStoredToken();
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...((options.headers as Record<string, string>) || {}),
  };

  const response = await fetch(url, {
    ...options,
    headers,
  });

  if (!response.ok) {
    let errorDetail = `HTTP ${response.status}: ${response.statusText}`;
    try {
      const errJson = await response.json();
      errorDetail = errJson.detail || errJson.error || errorDetail;
    } catch {
      // Keep default error
    }
    throw new Error(errorDetail);
  }

  return response.json();
}

async function requestBlob(endpoint: string, options: RequestInit = {}): Promise<{ blob: Blob; filename: string }> {
  const url = `${API_BASE}${endpoint}`;
  const token = getStoredToken();
  const headers: Record<string, string> = {
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...((options.headers as Record<string, string>) || {}),
  };

  const response = await fetch(url, {
    ...options,
    headers,
  });

  if (!response.ok) {
    let errorDetail = `HTTP ${response.status}: ${response.statusText}`;
    try {
      const errJson = await response.json();
      errorDetail = errJson.detail || errJson.error || errorDetail;
    } catch {
      // Keep default error
    }
    throw new Error(errorDetail);
  }

  const disposition = response.headers.get("Content-Disposition") || "";
  let filename = "export";
  const match = disposition.match(/filename="?([^";]+)"?/);
  if (match && match[1]) {
    filename = match[1].trim();
  }

  const blob = await response.blob();
  return { blob, filename };
}

export function triggerBrowserDownload(blob: Blob, filename: string): void {
  const downloadUrl = window.URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = downloadUrl;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  window.URL.revokeObjectURL(downloadUrl);
}

export const api = {
  // Authentication & RBAC
  getAuthStatus: () => request<AuthStatus>("/auth/status"),
  setupFirstBoot: (payload: UserSetupPayload) =>
    request<TokenResponse>("/auth/setup", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  login: (payload: { username: string; password: string }) =>
    request<TokenResponse>("/auth/login", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  getMe: () => request<User>("/auth/me"),
  listUsers: () => request<User[]>("/auth/users"),
  createUser: (payload: UserCreatePayload) =>
    request<User>("/auth/users", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  updateUserStatus: (userId: string, isActive: boolean) =>
    request<User>(`/auth/users/${userId}/status`, {
      method: "PATCH",
      body: JSON.stringify({ is_active: isActive }),
    }),

  // Health
  getHealth: () => request<{ status: string; version: string; phase: number }>("/health"),

  // Intake & Custody
  intakeOffline: (payload: {
    case_id: string;
    evidence_path?: string;
    raw_content_b64?: string;
    artifact_type?: string;
    acquisition_method?: string;
    actor?: string;
    auto_index?: boolean;
  }) =>
    request<{
      status: string;
      case_id: string;
      artifacts: ArtifactRecord[];
      findings_indexed_count: number;
      custody_entries: CustodyChainEntry[];
    }>("/intake/offline", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  intakeSIEM: (payload: {
    case_id: string;
    connection_id?: string;
    config?: SIEMConnectionConfig;
    query: string;
    limit?: number;
    actor?: string;
  }) =>
    request<{
      status: string;
      case_id: string;
      query_snapshot: SIEMQuerySnapshot;
      findings_count: number;
      findings: ForensicFinding[];
    }>("/intake/siem", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  // SIEM Connection & Credential Store Management (SEC-UI-001)
  createSIEMConnection: (payload: SIEMConnectionCreatePayload) =>
    request<SIEMConnectionResponse>("/siem/connections", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  listSIEMConnections: (caseId: string) =>
    request<SIEMConnectionResponse[]>(`/siem/connections?case_id=${encodeURIComponent(caseId)}`),

  getSIEMConnection: (connectionId: string) =>
    request<SIEMConnectionResponse>(`/siem/connections/${encodeURIComponent(connectionId)}`),

  updateSIEMConnection: (connectionId: string, payload: SIEMConnectionUpdatePayload) =>
    request<SIEMConnectionResponse>(`/siem/connections/${encodeURIComponent(connectionId)}`, {
      method: "PATCH",
      body: JSON.stringify(payload),
    }),

  deleteSIEMConnection: (connectionId: string) =>
    request<{ status: string; connection_id: string }>(`/siem/connections/${encodeURIComponent(connectionId)}`, {
      method: "DELETE",
    }),

  testSIEMConnection: (connectionId: string) =>
    request<SIEMConnectionTestResponse>(`/siem/connections/${encodeURIComponent(connectionId)}/test`, {
      method: "POST",
    }),

  getCustodyLedger: (caseId: string) =>
    request<{
      case_id: string;
      is_tamper_free: boolean;
      entry_count: number;
      entries: CustodyChainEntry[];
    }>(`/intake/custody/${caseId}`),

  // Plugins
  getPlugins: () => request<ToolPluginCard[]>("/plugins"),

  dryRunAutoMapper: (sampleRows: Record<string, any>[]) =>
    request<DryRunAutoMapperResult>("/plugins/dry-run", {
      method: "POST",
      body: JSON.stringify({ sample_rows: sampleRows }),
    }),

  registerPlugin: (card: ToolPluginCard) =>
    request<{
      status: string;
      tool_id: string;
      message: string;
      yaml_path: string;
      card: ToolPluginCard;
    }>("/plugins/register", {
      method: "POST",
      body: JSON.stringify(card),
    }),

  // AI Agent Hypothesis Planner & Deterministic Goal Engine
  planHypothesis: (payload: {
    case_id: string;
    investigation_goal: string;
    findings?: ForensicFinding[];
    recommended_blueprint?: string;
    auto_approve?: boolean;
    scoped_filters?: ScopedFilterParams;
  }) =>
    request<HypothesisDraft>("/agent/plan-hypothesis", {
      method: "POST",
      body: JSON.stringify({
        auto_approve: true,
        ...payload,
      }),
    }),

  compilePlan: (payload: {
    case_id: string;
    investigation_goal: string;
    findings?: ForensicFinding[];
    auto_approve?: boolean;
    scoped_filters?: ScopedFilterParams;
  }) =>
    request<DeterministicGoalPlan>("/agent/compile-plan", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  executePlan: (payload: {
    case_id: string;
    plan: DeterministicGoalPlan;
    findings?: ForensicFinding[];
  }) =>
    request<{
      status: string;
      plan_id: string;
      executed_steps_count: number;
      skipped_steps_count: number;
      findings_count: number;
      report?: CitedReport;
      report_markdown?: string;
    }>("/agent/execute-plan", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  getPlaybooks: () => request<MitrePlaybook[]>("/agent/playbooks"),

  // Workflows
  getBlueprints: () => request<Record<string, WorkflowDefinition>>("/workflows/blueprints"),

  runWorkflow: (payload: {
    case_id: string;
    workflow: WorkflowDefinition;
    initial_pivots?: WorkflowEdgePayload;
    approval_tokens?: Record<string, HumanApprovalToken>;
  }) =>
    request<WorkflowExecutionState>("/workflow/run", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  executeWorkflow: (payload: {
    case_id: string;
    workflow: WorkflowDefinition;
    initial_pivots?: WorkflowEdgePayload;
    approval_tokens?: Record<string, HumanApprovalToken>;
  }) =>
    request<WorkflowExecutionState>("/workflows/execute", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  resumeWorkflow: (payload: {
    case_id: string;
    workflow: WorkflowDefinition;
    state: WorkflowExecutionState;
    approval_token: HumanApprovalToken;
  }) =>
    request<WorkflowExecutionState>("/workflows/resume", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  createApprovalToken: (payload: {
    case_id: string;
    node_id: string;
    target?: string;
    action_type?: string;
    parameters?: Record<string, any>;
    parameter_digest?: string;
    validity_minutes?: number;
    requesting_investigator?: string;
    reason?: string;
  }) =>
    request<HumanApprovalToken>("/workflows/approval-token", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  // Action Authorization Engine (Phase 08)
  createApprovalRequest: (payload: {
    case_id: string;
    action_type: string;
    target: string;
    capability_id: string;
    parameters?: Record<string, any>;
    risk_level?: string;
    evidence_scope?: string[];
    justification?: string;
    validity_minutes?: number;
  }) =>
    request<ApprovalRequest>("/approvals/requests", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  listApprovalRequests: (params?: { case_id?: string; status?: ApprovalStatus }) => {
    const q = new URLSearchParams();
    if (params?.case_id) q.set("case_id", params.case_id);
    if (params?.status) q.set("status", params.status);
    const qs = q.toString();
    return request<ApprovalRequest[]>(`/approvals${qs ? `?${qs}` : ""}`);
  },

  getApprovalRequest: (approvalId: string) =>
    request<ApprovalRequest>(`/approvals/${approvalId}`),

  approveRequest: (approvalId: string, reason?: string) =>
    request<ApprovalRequest>(`/approvals/${approvalId}/approve`, {
      method: "POST",
      body: JSON.stringify({ reason: reason || "Approved by authorized investigator" }),
    }),

  rejectRequest: (approvalId: string, reason: string) =>
    request<ApprovalRequest>(`/approvals/${approvalId}/reject`, {
      method: "POST",
      body: JSON.stringify({ reason }),
    }),

  revokeRequest: (approvalId: string, reason: string) =>
    request<ApprovalRequest>(`/approvals/${approvalId}/revoke`, {
      method: "POST",
      body: JSON.stringify({ reason }),
    }),

  // SSE Workflow Streaming
  streamWorkflow: (
    payload: {
      case_id: string;
      workflow: WorkflowDefinition;
      initial_pivots?: WorkflowEdgePayload;
      approval_tokens?: Record<string, HumanApprovalToken>;
    },
    onEvent: (event: string, data: any) => void,
    onError: (err: any) => void,
    onComplete: () => void
  ) => {
    const url = `${API_BASE}/workflows/stream`;
    const token = getStoredToken();
    fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      body: JSON.stringify(payload),
    })
      .then(async (response) => {
        if (!response.ok || !response.body) {
          throw new Error(`SSE stream failed: ${response.statusText}`);
        }
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = "";

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;

          buffer += decoder.decode(value, { stream: true });
          const parts = buffer.split("\n\n");
          buffer = parts.pop() || "";

          for (const chunk of parts) {
            const lines = chunk.split("\n");
            let eventType = "message";
            let dataStr = "";

            for (const line of lines) {
              if (line.startsWith("event: ")) {
                eventType = line.slice(7).trim();
              } else if (line.startsWith("data: ")) {
                dataStr = line.slice(6).trim();
              }
            }

            if (dataStr) {
              try {
                const parsed = JSON.parse(dataStr);
                onEvent(eventType, parsed);
              } catch {
                onEvent(eventType, dataStr);
              }
            }
          }
        }
        onComplete();
      })
      .catch((err) => {
        onError(err);
      });
  },

  // Reports & Findings
  getReport: (caseId: string, refresh: boolean = false) =>
    request<{
      case_id: string;
      report: CitedReport;
      markdown: string;
    }>(`/reports/${caseId}${refresh ? "?refresh=true" : ""}`),

  compileReport: (caseId: string, nodeResults: any[] = []) =>
    request<{
      case_id: string;
      report: CitedReport;
      markdown: string;
    }>("/reports/compile", {
      method: "POST",
      body: JSON.stringify({ case_id: caseId, node_results: nodeResults }),
    }),

  finalizeReport: (reportId: string, approvalToken: any) =>
    request<{
      case_id: string;
      report: CitedReport;
      markdown: string;
    }>(`/reports/${reportId}/finalize`, {
      method: "POST",
      body: JSON.stringify({ approval_token: approvalToken }),
    }),

  getReportHistory: (caseId: string) =>
    request<
      Array<{
        report_id: string;
        version: number;
        status: string;
        digest?: string | null;
        created_utc: string;
        created_by: string;
        finalized_utc?: string | null;
        finalized_by?: string | null;
        approval_token_id?: string | null;
      }>
    >(`/reports/${caseId}/history`),

  getFinding: (findingId: string, caseId: string = "default_case") =>
    request<ForensicFinding>(`/findings/${findingId}?case_id=${encodeURIComponent(caseId)}`),

  queryFindings: (caseId: string, filters: Record<string, string> = {}) => {
    const q = new URLSearchParams({ case_id: caseId, ...filters });
    return request<ForensicFinding[]>(`/findings?${q.toString()}`);
  },

  // Feedback & Learning Loop
  submitFeedback: (payload: {
    case_id?: string;
    finding_id?: string;
    feedback_type: string;
    analyst_note?: string;
    entity_pattern?: string;
    scope?: string;
    org_id?: string;
    artifact_type?: string;
    corrected_query?: string;
  }) =>
    request<{
      status: string;
      feedback_id: string;
      record: HumanFeedbackRecord;
    }>("/feedback", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  getBaselines: (orgId: string = "default_org") =>
    request<Record<string, any>[]>(`/feedback/baselines?org_id=${encodeURIComponent(orgId)}`),

  // LLM Multi-Provider Registry & Smoke Testing
  getLLMProviders: () => request<LLMProvider[]>("/llm/providers"),
  selectLLMProvider: (provider_id: string) =>
    request<{ status: string; active_provider_id: string; message: string }>("/llm/select", {
      method: "POST",
      body: JSON.stringify({ provider_id }),
    }),
  smokeTestLLMProvider: (provider_id: string) =>
    request<LLMSmokeTestResult>(`/llm/smoke-test/${provider_id}`, {
      method: "POST",
    }),

  // Streaming Evidence Upload & Local Host Browser
  uploadEvidence: async (file: File, caseId: string = "default_case") => {
    const formData = new FormData();
    formData.append("file", file);
    formData.append("case_id", caseId);

    const token = getStoredToken();
    const headers: Record<string, string> = {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    };

    const response = await fetch(`${API_BASE}/intake/upload`, {
      method: "POST",
      headers,
      body: formData,
    });

    if (!response.ok) {
      let errorDetail = `Upload failed (HTTP ${response.status})`;
      try {
        const errJson = await response.json();
        errorDetail = errJson.detail || errJson.error || errorDetail;
      } catch {}
      throw new Error(errorDetail);
    }
    return response.json() as Promise<EvidenceUploadResult>;
  },

  browseLocal: (payload: { current_path?: string; filter_extensions?: string[] } = {}) =>
    request<BrowseLocalResult>("/intake/browse-local", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  // Investigation Session Store (SQLite Backend Persistence)
  getSession: (caseId: string) =>
    request<InvestigationSession>(`/session/${encodeURIComponent(caseId)}`),

  saveSession: (
    caseId: string,
    payload: {
      wizard_state: any;
      workflow_state: any;
      active_tab?: string;
    }
  ) =>
    request<InvestigationSession>(`/session/${encodeURIComponent(caseId)}`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  listSessions: () => request<InvestigationSession[]>("/session"),

  // Case Management & Forensic Vault Registry
  listCases: (search?: string, status?: string) => {
    const params = new URLSearchParams();
    if (search) params.append("search", search);
    if (status && status !== "ALL") params.append("status", status);
    const qs = params.toString() ? `?${params.toString()}` : "";
    return request<CaseRecord[]>(`/cases${qs}`);
  },

  getCase: (caseId: string) =>
    request<CaseRecord>(`/cases/${encodeURIComponent(caseId)}`),

  createOrUpdateCase: (payload: Partial<CaseRecord> & { case_id: string; case_name: string }) =>
    request<CaseRecord>("/cases", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  updateCase: (caseId: string, payload: Partial<CaseRecord>) =>
    request<CaseRecord>(`/cases/${encodeURIComponent(caseId)}`, {
      method: "PATCH",
      body: JSON.stringify(payload),
    }),

  shareCaseToVault: (caseId: string, isShared: boolean) =>
    request<{ status: string; case_id: string; is_shared_to_vault: boolean }>(
      `/cases/${encodeURIComponent(caseId)}/share`,
      {
        method: "POST",
        body: JSON.stringify({ is_shared_to_vault: isShared }),
      }
    ),

  getVaultCases: () => request<CaseRecord[]>("/cases/vault/shared"),

  deleteCase: (caseId: string) =>
    request<{ status: string; message: string }>(`/cases/${encodeURIComponent(caseId)}`, {
      method: "DELETE",
    }),

  // DFIR Co-Pilot Chat Endpoint
  copilotChat: (payload: {
    case_id: string;
    message: string;
    history?: Array<{ role: string; content: string }>;
    send_system_prompt?: boolean;
  }) =>
    request<CopilotChatResponse>("/copilot/chat", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  // Autonomous Investigation Controller Endpoints
  startInvestigation: (payload: { case_id: string; objective?: string; budget?: any; autorun?: boolean }) =>
    request<InvestigationRecord>("/investigations/start", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  getInvestigation: (caseId: string) =>
    request<InvestigationRecord>(`/investigations/${encodeURIComponent(caseId)}`),

  getInvestigationFindings: (caseId: string, limit: number = 50, offset: number = 0) =>
    request<ForensicFinding[]>(`/investigations/${encodeURIComponent(caseId)}/findings?limit=${limit}&offset=${offset}`),

  getInvestigationHypotheses: (caseId: string) =>
    request<CompetingHypothesis[]>(`/investigations/${encodeURIComponent(caseId)}/hypotheses`),

  getInvestigationTimeline: (caseId: string, limit: number = 100, offset: number = 0) =>
    request<InvestigationTimelineEntry[]>(`/investigations/${encodeURIComponent(caseId)}/timeline?limit=${limit}&offset=${offset}`),

  exportReport: (caseId: string, format: "markdown" | "json" | "md" = "markdown") =>
    requestBlob(`/reports/${encodeURIComponent(caseId)}/export?format=${format}`),

  exportCustodyLedger: (caseId: string, format: "jsonl" | "json" = "jsonl") =>
    requestBlob(`/intake/custody/${encodeURIComponent(caseId)}/export?format=${format}`),

  iterateInvestigation: (caseId: string) =>
    request<InvestigationRecord>(`/investigations/${encodeURIComponent(caseId)}/iterate`, {
      method: "POST",
    }),

  resumeInvestigation: (caseId: string, payload: { approval_token?: any; autorun?: boolean } = {}) =>
    request<InvestigationRecord>(`/investigations/${encodeURIComponent(caseId)}/resume`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  cancelInvestigation: (caseId: string, reason?: string) =>
    request<InvestigationRecord>(`/investigations/${encodeURIComponent(caseId)}/cancel`, {
      method: "POST",
      body: JSON.stringify({ reason: reason || "User cancelled investigation" }),
    }),

  getSpecialists: (caseId: string) =>
    request<any[]>(`/investigations/${encodeURIComponent(caseId)}/specialists`),

  getToolExecutionHistory: (caseId: string) =>
    request<any[]>(`/investigations/${encodeURIComponent(caseId)}/tool-history`),
};


