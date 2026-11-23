/**
 * TypeScript Data Contracts for ForensicOps AI.
 * Perfectly aligned with backend Pydantic v2 models.
 */
export * from "./auth";

export type FindingSeverity = "critical" | "high" | "medium" | "low" | "info";

export type ClaimType = "observed_fact" | "derived_correlation" | "hypothesis" | "recommendation";

export type FeedbackType = "true_positive" | "false_positive_benign_baseline" | "query_correction";

export type FeedbackScope = "this_case_only" | "organization_baseline" | "global_playbook";

export type NodeType =
  | "evidence_input"
  | "dissect_parser"
  | "tool_runner"
  | "ai_goal_step"
  | "human_approval_gate"
  | "report_compiler";

export interface ArtifactRecord {
  artifact_id: string;
  case_id: string;
  type: string;
  original_path: string;
  blob_path: string;
  size_bytes: number;
  sha256: string;
  sha512: string;
  acquired_utc: string;
  acquisition_method: string;
}

export interface CustodyChainEntry {
  seq_id: number;
  case_id: string;
  timestamp_utc: string;
  actor: string;
  action: string;
  artifact_sha256?: string | null;
  tool_id?: string | null;
  prev_hash: string;
  entry_hash: string;
}

export interface ForensicFinding {
  finding_id: string;
  case_id: string;
  source_artifact_id: string;
  source_artifact_hash: string;
  tool_id: string;
  timestamp_utc?: string | null;
  artifact_type: string;
  category: string;
  event_id?: string | null;
  severity: FindingSeverity;
  host?: string | null;
  user?: string | null;
  process_name?: string | null;
  command_line?: string | null;
  raw_reference?: string | null;
  summary: string;
  projected_data: Record<string, any>;
  raw_data_path?: string | null;
}

export interface CitedClaim {
  claim_id: string;
  claim_type: ClaimType;
  statement: string;
  citing_finding_ids: string[];
  source_artifact_hashes: string[];
  confidence: number;
  why_it_matters?: string | null;
  benign_alternative?: string | null;
  verification_steps: string[];
  data_gaps: string[];
  verification_status?: string;
  requires_analyst_review?: boolean;
  review_notes?: string | null;
}

export interface NodeGoalResult {
  node_id: string;
  status: "success" | "needs_more_data" | "failed";
  summary: string;
  claims: CitedClaim[];
  extracted_pivots: Record<string, string[]>;
  recommended_next_actions: string[];
  confidence_score: number;
}

export interface WorkflowEdgePayload {
  dataset_pointer?: string | null;
  pivots: Record<string, string[]>;
}

export interface WorkflowNode {
  id: string;
  name: string;
  type: NodeType;
  config: Record<string, any>;
  position?: { x: number; y: number } | null;
}

export interface WorkflowEdge {
  id: string;
  source: string;
  target: string;
  payload?: WorkflowEdgePayload | null;
}

export interface HumanApprovalToken {
  token_id: string;
  node_id: string;
  case_id: string;
  issued_by: string;
  timestamp_utc: string;
  signature?: string | null;
  is_valid: boolean;
  approval_id?: string | null;
  action_type?: string | null;
  target?: string | null;
  parameter_digest?: string | null;
  expires_at_utc?: string | null;
  consumed?: boolean;
}

export type ApprovalStatus = "pending" | "approved" | "rejected" | "expired" | "revoked" | "consumed";
export type ActionRiskLevel = "low" | "medium" | "high" | "critical";

export interface ApprovalRequest {
  approval_id: string;
  case_id: string;
  requesting_investigator: string;
  action_type: string;
  target: string;
  capability_id: string;
  parameters: Record<string, any>;
  parameter_digest: string;
  risk_level: ActionRiskLevel;
  evidence_scope?: string[] | null;
  justification?: string | null;
  policy_version: string;
  created_at_utc: string;
  expires_at_utc: string;
  status: ApprovalStatus;
  approving_investigator?: string | null;
  decision_reason?: string | null;
  decided_at_utc?: string | null;
  token?: HumanApprovalToken | null;
}

export interface WorkflowDefinition {
  workflow_id: string;
  name: string;
  description: string;
  nodes: WorkflowNode[];
  edges: WorkflowEdge[];
  version: string;
}

export interface WorkflowExecutionState {
  case_id: string;
  workflow_id: string;
  current_node_id?: string | null;
  completed_nodes: string[];
  node_results: Record<string, NodeGoalResult>;
  node_outputs: Record<string, any>;
  edge_payloads: Record<string, WorkflowEdgePayload>;
  active_payload: WorkflowEdgePayload;
  approval_tokens: Record<string, HumanApprovalToken>;
  is_paused: boolean;
  pause_node_id?: string | null;
  pause_reason?: string | null;
  errors: string[];
  report?: Record<string, any> | null;
}

export interface ToolPluginCard {
  tool_id: string;
  name: string;
  version: string;
  description: string;
  author?: string;
  category: string;
  supported_artifact_types: string[];
  execution_tier: "tier_a_builtin" | "tier_b_adapter";
  command_template: string[];
  container_image?: string | null;
  input_type: "file" | "directory";
  output_format: "json" | "jsonl" | "csv";
  field_map: Record<string, string>;
  ai_keep_fields: string[];
  default_severity: FindingSeverity;
  timeout_seconds: number;
}

export interface DryRunAutoMapperResult {
  suggested_field_map: Record<string, string>;
  suggested_ai_keep_fields: string[];
  confidence_scores: Record<string, number>;
  sample_raw_rows: Record<string, any>[];
  sample_projected_rows: Record<string, any>[];
  total_columns_inspected: number;
  detected_artifact_type?: string | null;
}

export interface HumanFeedbackRecord {
  feedback_id: string;
  case_id?: string | null;
  finding_id?: string | null;
  feedback_type: FeedbackType;
  analyst_note?: string | null;
  entity_pattern?: string | null;
  scope: FeedbackScope;
  org_id?: string | null;
  artifact_type?: string | null;
  created_utc: string;
  corrected_query?: string | null;
}

export interface TimelineEntry {
  timestamp_utc: string;
  original_timestamp?: string | null;
  original_timezone?: string | null;
  timezone_status?: string;
  normalized_timestamp_utc?: string | null;
  timestamp_source?: string | null;
  timestamp_precision?: string | null;
  clock_uncertainty?: string | null;
  host?: string | null;
  user?: string | null;
  process_or_event: string;
  summary: string;
  severity: FindingSeverity;
  citing_finding_id: string;
  source_artifact_hash: string;
}

export interface ExecutiveSummarySection {
  title: string;
  case_id: string;
  generated_utc: string;
  incident_overview: string;
  severity: FindingSeverity;
  impacted_hosts: string[];
  impacted_users: string[];
  earliest_timestamp_utc?: string | null;
  latest_timestamp_utc?: string | null;
  timeline: TimelineEntry[];
}

export interface CustodyAuditSection {
  title: string;
  evidence_items: Record<string, any>[];
  column_projection_summary: Record<string, any>;
  tamper_check_passed: boolean;
  verification_status?: string;
  verification_errors?: string[];
}

export interface AIFTRubricItem {
  claim_id: string;
  statement: string;
  citing_finding_ids: string[];
  source_artifact_hashes: string[];
  confidence: number;
  why_it_matters: string;
  benign_alternative: string;
  verification_steps: string[];
  data_gaps: string[];
}

export interface PatientZeroRemediationSection {
  title: string;
  patient_zero_host?: string | null;
  patient_zero_status?: string;
  initial_access_vector?: string | null;
  initial_timestamp_utc?: string | null;
  confidence?: number;
  evidence_basis?: string[];
  lateral_movement_paths: string[];
  containment_actions: string[];
  remediation_steps: string[];
  data_gaps?: string[];
}

export interface EvidenceConflict {
  conflict_id: string;
  conflict_type: string;
  affected_finding_ids: string[];
  affected_artifact_hashes: string[];
  severity: FindingSeverity;
  description: string;
  contradictory_details: Record<string, any>;
}

export interface DeterministicCorrelationRecord {
  correlation_id: string;
  case_id: string;
  relationship_type: string;
  source_finding_ids: string[];
  source_artifact_hashes: string[];
  entity_identifiers: Record<string, any>;
  correlation_method: string;
  supporting_observations: string[];
  conflicting_observations: string[];
  time_window?: {
    start_utc?: string;
    end_utc?: string;
    duration_seconds?: number;
  } | null;
  limitations: string[];
  confidence: number;
  statement?: string | null;
}

export interface ReportProvenance {
  version: number;
  status: "draft" | "finalized" | "signed" | "blocked" | "incomplete";
  created_utc: string;
  created_by: string;
  finalized_utc?: string | null;
  finalized_by?: string | null;
  finalized_role?: string | null;
  approval_token_id?: string | null;
  approval_token_signature?: string | null;
  canonical_report_digest?: string | null;
  parent_report_id?: string | null;
}

export interface CitedReport {
  report_id: string;
  case_id: string;
  title?: string;
  generated_utc: string;
  status?: "draft" | "finalized" | "signed" | "blocked" | "incomplete";
  version?: number;
  provenance?: ReportProvenance;
  digest?: string | null;
  executive_summary: ExecutiveSummarySection;
  custody_and_filter_audit: CustodyAuditSection;
  observed_facts: CitedClaim[];
  derived_correlations: CitedClaim[];
  correlation_records?: DeterministicCorrelationRecord[];
  evidence_conflicts?: EvidenceConflict[];
  rejected_claims?: CitedClaim[];
  unverified_hypotheses?: CitedClaim[];
  aift_rubric: AIFTRubricItem[];
  patient_zero_and_remediation: PatientZeroRemediationSection;
  verified_finding_ids: string[];
  verified_artifact_hashes: string[];
  all_cited_finding_ids?: string[];
  all_source_artifact_hashes?: string[];
}


export interface SIEMConnectionConfig {
  siem_type: "elasticsearch" | "wazuh" | "splunk";
  endpoint_url: string;
  api_key?: string | null;
  username?: string | null;
  password?: string | null;
  token?: string | null;
  index_pattern?: string | null;
}

export interface SIEMQuerySnapshot {
  snapshot_id: string;
  case_id: string;
  siem_type: string;
  query_string: string;
  snapshot_sha256: string;
  record_count: number;
  timestamp_utc: string;
}

export interface SIEMConnectionResponse {
  connection_id: string;
  case_id: string;
  siem_type: "elasticsearch" | "wazuh" | "splunk";
  endpoint_url: string;
  index_pattern?: string | null;
  allowed_hosts?: string[] | null;
  headers?: Record<string, string>;
  verify_ssl: boolean;
  timeout_seconds: number;
  username?: string | null;
  has_password: boolean;
  has_api_key: boolean;
  has_token: boolean;
  created_by: string;
  created_at_utc: string;
  updated_at_utc: string;
}

export interface SIEMConnectionCreatePayload {
  case_id: string;
  siem_type: "elasticsearch" | "wazuh" | "splunk";
  endpoint_url: string;
  index_pattern?: string;
  allowed_hosts?: string[];
  headers?: Record<string, string>;
  verify_ssl?: boolean;
  timeout_seconds?: number;
  username?: string;
  password?: string;
  api_key?: string;
  token?: string;
}

export interface SIEMConnectionUpdatePayload {
  siem_type?: "elasticsearch" | "wazuh" | "splunk";
  endpoint_url?: string;
  index_pattern?: string;
  allowed_hosts?: string[];
  headers?: Record<string, string>;
  verify_ssl?: boolean;
  timeout_seconds?: number;
  username?: string;
  password?: string;
  api_key?: string;
  token?: string;
  remove_password?: boolean;
  remove_api_key?: boolean;
  remove_token?: boolean;
  clear_credentials?: boolean;
}

export interface SIEMConnectionTestResponse {
  status: string;
  connection_id: string;
  siem_type: "elasticsearch" | "wazuh" | "splunk";
  reachable: boolean;
  authenticated: boolean;
  latency_ms: number;
  message: string;
}

export interface LLMProvider {
  provider_id: string;
  label: string;
  model_name: string;
  base_url: string;
  is_local: boolean;
  is_configured: boolean;
  is_active: boolean;
  last_test_success?: boolean | null;
  last_latency_ms?: number | null;
  last_tested_at_utc?: string | null;
  response_preview?: string | null;
  error_detail?: string | null;
}

export interface LLMSmokeTestResult {
  provider_id: string;
  success: boolean;
  latency_ms: number;
  response_preview?: string | null;
  error_detail?: string | null;
}

export interface EvidenceUploadResult {
  status: string;
  upload_id: string;
  filename: string;
  file_path: string;
  size_bytes: number;
  sha256: string;
  sha512: string;
  detected_artifact_type: string;
  uploaded_at_utc: string;
}

export interface BrowseLocalItem {
  name: string;
  path: string;
  is_dir: boolean;
  size_bytes: number;
  extension: string;
}

export interface BrowseLocalResult {
  status: string;
  current_path: string;
  parent_path?: string | null;
  selected_file?: string | null;
  drives?: string[];
  items: BrowseLocalItem[];
}

export interface ScopedFilterParams {
  keywords_or_iocs?: string[];
  regex_pattern?: string | null;
  time_start_utc?: string | null;
  time_end_utc?: string | null;
  event_ids?: number[];
}

export type PlanStepStatus = "READY" | "SKIPPED_NO_ARTIFACT" | "EXECUTED" | "FAILED";

export interface CompiledPlanStep {
  step_id: string;
  name: string;
  tactic_id: string;
  tactic_name: string;
  description: string;
  target_os: string;
  parser_plugin: string;
  required_artifact_types: string[];
  artifact_globs?: string[];
  status: PlanStepStatus;
  skip_reason?: string | null;
  matched_artifact_ids?: string[];
  scoped_filters?: ScopedFilterParams | null;
}

export interface DeterministicGoalPlan {
  plan_id: string;
  case_id: string;
  investigation_goal: string;
  auto_approve: boolean;
  status: string;
  scoped_filters: ScopedFilterParams;
  matched_tactics: string[];
  steps: CompiledPlanStep[];
  executed_steps_count: number;
  skipped_steps_count: number;
  created_at_utc: string;
}

export interface PlaybookStep {
  step_id: string;
  name: string;
  tactic_id: string;
  tactic_name: string;
  description: string;
  target_os: string;
  artifact_globs: string[];
  required_artifact_types: string[];
  parser_plugin: string;
  default_event_ids?: number[];
  suggested_commands?: string[];
}

export interface MitrePlaybook {
  tactic_id: string;
  tactic_name: string;
  description: string;
  keywords: string[];
  steps: PlaybookStep[];
}

export interface HypothesisDraft {
  hypothesis_id: string;
  case_id: string;
  investigation_goal: string;
  threat_hypothesis: string;
  benign_hypothesis: string;
  key_questions: string[];
  recommended_blueprint: string;
  cited_findings: CitedClaim[];
  suggested_steps: string[];
  confidence_score: number;
  created_at_utc: string;
  auto_approve?: boolean;
  status?: string;
  scoped_filters?: ScopedFilterParams | null;
  plan_steps?: CompiledPlanStep[];
  report?: CitedReport | null;
  report_markdown?: string | null;
}

export interface WizardPersistedState {
  mode: "offline" | "siem";
  offlinePath: string;
  isZeroCopy: boolean;
  artifactType: string;
  autoIndex: boolean;
  uploadedMetadata?: EvidenceUploadResult | null;
  approvalTokenId: string;
  gateApproved: boolean;
  siemType: "elasticsearch" | "wazuh" | "splunk";
  siemUrl: string;
  siemIndex: string;
  siemQuery: string;
  siemConnectionId?: string | null;
  siemApiKey?: string;
  ingestedArtifacts?: ArtifactRecord[];
  indexedFindingsCount?: number;
  recentCustody?: CustodyChainEntry[];
  investigationGoal?: string;
  hypothesisDraft?: HypothesisDraft | null;
  caseName?: string;
  organizationName?: string;
  caseStatus?: CaseStatus;
  caseId?: string;
  isSharedToVault?: boolean;
}

export interface WorkflowCanvasPersistedState {
  selectedBlueprintKey: string;
  activeWorkflow?: WorkflowDefinition | null;
  executionState?: WorkflowExecutionState | null;
  streamLogs?: Array<{ timestamp: string; event: string; detail: string }>;
  isStreaming?: boolean;
}

export type ActiveTab = "cases" | "wizard" | "canvas" | "investigation" | "plugins" | "report" | "custody" | "vault";

export type CaseStatus = "OPEN" | "IN_REVIEW" | "COMPLETED";

export interface CaseRecord {
  case_id: string;
  case_name: string;
  organization_name: string;
  investigation_goal?: string;
  lead_analyst: string;
  active_provider_id: string;
  status: CaseStatus;
  is_shared_to_vault: boolean;
  created_at_utc: string;
  updated_at_utc: string;
  serialized_state?: {
    wizard_state?: WizardPersistedState;
    workflow_state?: WorkflowCanvasPersistedState;
    active_tab?: ActiveTab;
  };
}

export interface CopilotMessage {
  id: string;
  role: "user" | "assistant" | "system";
  content: string;
  timestamp_utc: string;
  provider_id?: string;
  suggested_actions?: string[];
  executed_playbooks?: string[];
  findings_count?: number;
}

export interface CopilotChatResponse {
  reply: string;
  timestamp_utc: string;
  provider_id: string;
  case_id: string;
  suggested_actions?: string[];
  executed_playbooks?: string[];
  findings_count?: number;
  threat_hypothesis?: string;
  benign_hypothesis?: string;
}

export interface InvestigationSession {
  case_id: string;
  wizard_state: WizardPersistedState | Record<string, any>;
  workflow_state: WorkflowCanvasPersistedState | Record<string, any>;
  active_tab: ActiveTab;
  updated_at_utc: string;
}

export type InvestigationLifecycleState =
  | "created"
  | "evidence_validation"
  | "planning"
  | "executing"
  | "evaluating"
  | "awaiting_approval"
  | "needs_more_data"
  | "completed"
  | "partially_completed"
  | "failed"
  | "cancelled";

export interface InvestigationBudget {
  max_iterations: number;
  max_tool_executions: number;
  per_tool_timeout_seconds: number;
  max_total_execution_seconds: number;
  max_findings_per_step: number;
  max_context_tokens: number;
  max_retries_per_step: number;
}

export interface ToolRequest {
  capability_id: string;
  artifact_id?: string | null;
  arguments?: Record<string, any>;
  justification?: string;
  requires_approval?: boolean;
}

export interface InvestigationAction {
  action_id: string;
  step_index: number;
  action_type: "tier_a_parser" | "tier_b_tool" | "store_query" | "pivot_search" | "containment";
  capability_id: string;
  artifact_id?: string | null;
  arguments?: Record<string, any>;
  justification?: string;
  requires_approval?: boolean;
  approval_id?: string | null;
  approval_token?: HumanApprovalToken | null;
  status: "pending" | "approved" | "executing" | "completed" | "failed" | "skipped";
  execution_id?: string | null;
  findings_count: number;
  raw_output_ref?: string | null;
  error?: string | null;
  retries: number;
}

export interface EvidenceGap {
  gap_id: string;
  missing_artifact_type: string;
  tactical_reason: string;
  recommended_collection: string;
  is_evidence_of_absence?: boolean;
}

export interface CompetingHypothesis {
  hypothesis_id: string;
  title: string;
  description: string;
  is_benign_null?: boolean;
  supporting_finding_ids: string[];
  contradicting_finding_ids: string[];
  confidence: number;
  status: "untested" | "supported" | "refuted" | "inconclusive";
  version: number;
}

export interface InvestigationStepTrace {
  trace_id: string;
  investigation_id: string;
  case_id: string;
  iteration: number;
  step_name: string;
  inputs?: Record<string, any>;
  outputs?: Record<string, any>;
  executed_queries?: string[];
  cited_finding_ids?: string[];
  tool_executions?: Array<Record<string, any>>;
  status: string;
  duration_seconds: number;
  created_at_utc: string;
}

export interface InvestigationPlan {
  plan_id: string;
  case_id: string;
  objective: string;
  hypotheses: CompetingHypothesis[];
  planned_actions: InvestigationAction[];
  evidence_gaps: EvidenceGap[];
  correlations: Array<Record<string, any>>;
  created_at_utc: string;
}

export interface InvestigationRecord {
  investigation_id: string;
  case_id: string;
  investigator: string;
  lifecycle_state: InvestigationLifecycleState;
  objective: string;
  plan: InvestigationPlan;
  current_iteration: number;
  budget: InvestigationBudget;
  pivots?: WorkflowEdgePayload;
  authorized_evidence_scope?: string[];
  available_capabilities?: string[];
  hypotheses: CompetingHypothesis[];
  evidence_gaps: EvidenceGap[];
  correlations: Array<Record<string, any>>;
  completed_actions: InvestigationAction[];
  pending_actions: InvestigationAction[];
  execution_ids: string[];
  findings_count: number;
  errors: string[];
}

export interface InvestigationTimelineEntry {
  timestamp_utc: string;
  entry_type: "finding" | "action_trace";
  description: string;
  source: string;
  host?: string | null;
  details?: Record<string, any>;
}





