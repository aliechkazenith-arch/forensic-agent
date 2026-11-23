import React, { useState, useEffect, useCallback } from "react";
import {
  Bot,
  Play,
  RotateCcw,
  ShieldAlert,
  Terminal,
  Layers,
  Sparkles,
  CheckCircle2,
  AlertCircle,
  HelpCircle,
  Wrench,
  Clock,
  Shield,
  Activity,
  Search,
  ExternalLink,
  Ban,
  FileCheck,
} from "lucide-react";
import { api } from "../services/api";
import { useForensicStore } from "../store/useForensicStore";
import { useAuth } from "../context/AuthContext";
import { ApprovalReviewModal } from "./ApprovalReviewModal";
import { ApprovalRequest, ForensicFinding, InvestigationRecord } from "../types";

export const InvestigationView: React.FC = () => {
  const { currentCaseId, openCitationDrawer, setActiveTab } = useForensicStore();
  const { user } = useAuth();
  const isAuditor = user?.role === "auditor";

  const [objective, setObjective] = useState<string>(
    "Perform comprehensive forensic compromise assessment and investigate credential dumping, lateral movement, and persistence."
  );
  const [investigationData, setInvestigationData] = useState<InvestigationRecord | null>(null);
  const [specialists, setSpecialists] = useState<any[]>([]);
  const [toolHistory, setToolHistory] = useState<any[]>([]);
  const [recentFindings, setRecentFindings] = useState<ForensicFinding[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [isIterating, setIsIterating] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  // Approval modal state
  const [isApprovalModalOpen, setIsApprovalModalOpen] = useState<boolean>(false);
  const [currentApprovalRequest, setCurrentApprovalRequest] = useState<ApprovalRequest | null>(null);

  const fetchInvestigation = useCallback(async () => {
    if (!currentCaseId) return;
    try {
      const data = await api.getInvestigation(currentCaseId);
      setInvestigationData(data);
      if (data.lifecycle_state === "awaiting_approval") {
        // Construct approval request for the paused action
        const pendingAction = data.pending_actions?.[0];
        if (pendingAction) {
          setCurrentApprovalRequest({
            approval_id: pendingAction.approval_id || `gate-${pendingAction.action_id}`,
            case_id: currentCaseId,
            requesting_investigator: data.investigator || "investigation_controller",
            action_type: pendingAction.action_type || "sensitive_operation",
            capability_id: pendingAction.capability_id,
            target: currentCaseId,
            parameters: pendingAction.arguments || {},
            parameter_digest: "sha256:pending-action-digest",
            risk_level: "high",
            justification: pendingAction.justification || "Operation requires explicit human authorization.",
            policy_version: "1.0.0",
            created_at_utc: new Date().toISOString(),
            expires_at_utc: new Date(Date.now() + 3600 * 1000).toISOString(),
            status: "pending",
          });
        }
      }
    } catch {
      // No active investigation yet
    }
  }, [currentCaseId]);

  const fetchSupplementaryData = useCallback(async () => {
    if (!currentCaseId) return;
    try {
      const [specs, hist, fnds] = await Promise.all([
        api.getSpecialists(currentCaseId).catch(() => []),
        api.getToolExecutionHistory(currentCaseId).catch(() => []),
        api.getInvestigationFindings(currentCaseId, 20, 0).catch(() => []),
      ]);
      setSpecialists(specs);
      setToolHistory(hist);
      setRecentFindings(Array.isArray(fnds) ? fnds : []);
    } catch {
      // Ignored
    }
  }, [currentCaseId]);

  useEffect(() => {
    fetchInvestigation();
    fetchSupplementaryData();
  }, [fetchInvestigation, fetchSupplementaryData]);

  const handleStart = async (autorun: boolean = false) => {
    setIsLoading(true);
    setError(null);
    try {
      const res = await api.startInvestigation({
        case_id: currentCaseId,
        objective: objective.trim(),
        autorun,
      });
      setInvestigationData(res);
      await fetchSupplementaryData();
    } catch (err: any) {
      setError(err.message || "Failed to start autonomous investigation");
    } finally {
      setIsLoading(false);
    }
  };

  const handleIterate = async () => {
    setIsIterating(true);
    setError(null);
    try {
      const res = await api.iterateInvestigation(currentCaseId);
      setInvestigationData(res);
      await fetchSupplementaryData();
    } catch (err: any) {
      setError(err.message || "Iteration failed");
    } finally {
      setIsIterating(false);
    }
  };

  const handleCancel = async () => {
    try {
      const res = await api.cancelInvestigation(currentCaseId, "Investigator cancelled session.");
      setInvestigationData(res);
    } catch (err: any) {
      setError(err.message || "Cancellation failed");
    }
  };

  const handleResumeAfterApproval = async (token?: any) => {
    setIsLoading(true);
    setIsApprovalModalOpen(false);
    try {
      const res = await api.resumeInvestigation(currentCaseId, {
        approval_token: token,
        autorun: true,
      });
      setInvestigationData(res);
      await fetchSupplementaryData();
    } catch (err: any) {
      setError(err.message || "Failed to resume investigation");
    } finally {
      setIsLoading(false);
    }
  };

  const getStateColor = (state: string) => {
    switch (state) {
      case "completed":
        return "bg-emerald-950/80 text-emerald-300 border-emerald-700/80";
      case "executing":
      case "planning":
      case "evaluating":
        return "bg-cyan-950/80 text-cyan-300 border-cyan-700/80 animate-pulse";
      case "awaiting_approval":
        return "bg-rose-950/80 text-rose-300 border-rose-700/80 animate-bounce";
      case "needs_more_data":
      case "partially_completed":
        return "bg-amber-950/80 text-amber-300 border-amber-700/80";
      case "failed":
      case "cancelled":
        return "bg-rose-950/80 text-rose-300 border-rose-700/80";
      default:
        return "bg-slate-800 text-slate-300 border-slate-700";
    }
  };

  return (
    <div className="h-[calc(100vh-64px)] w-full flex flex-col bg-[#070b14] text-slate-200 overflow-y-auto font-sans p-6 space-y-6">
      {/* Top Banner & State Card */}
      <div className="bg-[#0e1626] border border-slate-800 rounded-xl p-5 shadow-xl flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-lg bg-cyan-950/80 border border-cyan-800 text-cyan-400">
              <Bot className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center space-x-3">
                <h1 className="text-lg font-bold tracking-tight text-white">
                  Autonomous Investigation Controller
                </h1>
                <span className="font-mono text-xs px-2.5 py-0.5 rounded-full bg-slate-800 text-cyan-300 border border-slate-700">
                  Case: {currentCaseId}
                </span>
                {investigationData?.lifecycle_state && (
                  <span
                    className={`font-mono text-xs uppercase px-2.5 py-0.5 rounded-full border font-bold ${getStateColor(
                      investigationData.lifecycle_state
                    )}`}
                  >
                    State: {investigationData.lifecycle_state}
                  </span>
                )}
              </div>
              <p className="text-xs text-slate-400 mt-1">
                Controlled-autonomy DFIR agent: evaluates evidence, coordinates specialists, and tests competing hypotheses.
              </p>
            </div>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex items-center space-x-3">
          {investigationData?.lifecycle_state === "awaiting_approval" && (
            <button
              onClick={() => setIsApprovalModalOpen(true)}
              className="flex items-center space-x-2 px-4 py-2 rounded-lg text-xs font-bold bg-rose-600 hover:bg-rose-500 text-white shadow-lg shadow-rose-900/40 animate-bounce"
            >
              <ShieldAlert className="w-4 h-4" />
              <span>Operation Requires Approval</span>
            </button>
          )}

          {!isAuditor && (
            <>
              {(!investigationData ||
                investigationData.lifecycle_state === "created" ||
                investigationData.lifecycle_state === "completed" ||
                investigationData.lifecycle_state === "failed") && (
                <button
                  onClick={() => handleStart(false)}
                  disabled={isLoading}
                  className="flex items-center space-x-2 px-4 py-2 rounded-lg text-xs font-bold bg-cyan-500 hover:bg-cyan-400 text-slate-950 shadow-md shadow-cyan-500/20 active:scale-95 transition-all disabled:opacity-50"
                >
                  <Play className="w-4 h-4 fill-current" />
                  <span>{isLoading ? "Starting..." : "Start Investigation"}</span>
                </button>
              )}

              {investigationData &&
                investigationData.lifecycle_state !== "completed" &&
                investigationData.lifecycle_state !== "cancelled" &&
                investigationData.lifecycle_state !== "awaiting_approval" && (
                  <button
                    onClick={handleIterate}
                    disabled={isIterating}
                    className="flex items-center space-x-2 px-3.5 py-2 rounded-lg text-xs font-bold bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 shadow transition-all disabled:opacity-50"
                  >
                    <RotateCcw className={`w-3.5 h-3.5 ${isIterating ? "animate-spin" : ""}`} />
                    <span>{isIterating ? "Reasoning..." : "Step Once"}</span>
                  </button>
                )}

              {investigationData &&
                investigationData.lifecycle_state !== "completed" &&
                investigationData.lifecycle_state !== "cancelled" && (
                  <button
                    onClick={handleCancel}
                    className="flex items-center space-x-1.5 px-3 py-2 rounded-lg text-xs font-medium bg-slate-900 hover:bg-rose-950 text-slate-400 hover:text-rose-300 border border-slate-800 transition-all"
                  >
                    <Ban className="w-3.5 h-3.5" />
                    <span>Cancel</span>
                  </button>
                )}
            </>
          )}
        </div>
      </div>

      {error && (
        <div className="bg-rose-950/60 border border-rose-800 text-rose-300 text-xs p-3 rounded-lg flex items-center space-x-2">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Honest Degraded State Alert Banners */}
      {investigationData?.lifecycle_state === "partially_completed" && (
        <div className="bg-amber-950/40 border border-amber-600/70 text-amber-200 text-xs p-4 rounded-xl flex items-start space-x-3 shadow-lg">
          <AlertCircle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
          <div className="space-y-1">
            <span className="font-bold text-amber-300">
              Investigation Partially Completed (Execution Budget Reached / Unanalyzed Leads In Scope)
            </span>
            <p className="text-[11px] text-amber-300/80 leading-relaxed font-mono">
              The autonomous investigation halted cleanly because configured bounds (iterations or tool actions) were reached before all pivots could be analyzed. Existing findings in DuckDB are verified, but open leads remain.
            </p>
          </div>
        </div>
      )}

      {investigationData?.lifecycle_state === "failed" && (
        <div className="bg-rose-950/50 border border-rose-600/80 text-rose-200 text-xs p-4 rounded-xl flex items-start space-x-3 shadow-lg">
          <ShieldAlert className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
          <div className="space-y-1">
            <span className="font-bold text-rose-300">
              Investigation Terminated Fail-Closed (Analyzer Discrepancy or Policy Denial)
            </span>
            <p className="text-[11px] text-rose-300/80 leading-relaxed font-mono">
              The autonomous engine encountered unrecoverable tool failures or evidence validation errors. In accordance with AGENTS.md Rule 9, the execution was degraded rather than falsely reported as complete.
            </p>
          </div>
        </div>
      )}

      {/* Objective Input Card */}
      <div className="bg-[#0e1626] border border-slate-800 rounded-xl p-4 shadow-lg space-y-2">
        <label className="text-xs font-bold text-slate-300 flex items-center space-x-2">
          <Terminal className="w-4 h-4 text-cyan-400" />
          <span>Investigation Objective & Scope</span>
        </label>
        <textarea
          value={objective}
          onChange={(e) => setObjective(e.target.value)}
          disabled={Boolean(investigationData && investigationData.lifecycle_state === "executing")}
          rows={2}
          className="w-full bg-[#080d18] border border-slate-700/80 rounded-lg p-3 text-xs text-slate-200 font-mono focus:outline-none focus:border-cyan-500 transition-all resize-none"
          placeholder="Enter investigation goal or hypothesis question..."
        />
      </div>

      {/* Grid: Specialists & Budgets */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Card 1: Investigation Budget & Iterations */}
        <div className="bg-[#0e1626] border border-slate-800 rounded-xl p-4 shadow-lg space-y-3">
          <div className="flex items-center justify-between pb-2 border-b border-slate-800">
            <span className="text-xs font-bold text-slate-200 flex items-center space-x-2">
              <Activity className="w-4 h-4 text-cyan-400" />
              <span>Execution Boundaries</span>
            </span>
            <span className="text-[10px] font-mono text-slate-400 uppercase">Finite Budget</span>
          </div>

          <div className="space-y-2.5 text-xs">
            <div>
              <div className="flex justify-between text-slate-400 mb-1">
                <span>Iterations</span>
                <span className="font-mono text-slate-200">
                  {investigationData?.current_iteration ?? 0} /{" "}
                  {investigationData?.budget?.max_iterations ?? 5}
                </span>
              </div>
              <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden">
                <div
                  className="h-full bg-cyan-400 rounded-full"
                  style={{
                    width: `${Math.min(
                      100,
                      ((investigationData?.current_iteration ?? 0) /
                        (investigationData?.budget?.max_iterations ?? 5)) *
                        100
                    )}%`,
                  }}
                />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-slate-400 mb-1">
                <span>Tool Invocations</span>
                <span className="font-mono text-slate-200">
                  {investigationData?.completed_actions?.length ?? 0} /{" "}
                  {investigationData?.budget?.max_tool_executions ?? 10}
                </span>
              </div>
              <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden">
                <div
                  className="h-full bg-emerald-400 rounded-full"
                  style={{
                    width: `${Math.min(
                      100,
                      (((investigationData?.completed_actions?.length ?? 0) /
                        (investigationData?.budget?.max_tool_executions ?? 10)) *
                        100)
                    )}%`,
                  }}
                />
              </div>
            </div>

            <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between text-slate-400">
              <span>Verified Findings Count</span>
              <span className="font-mono font-bold text-cyan-300">
                {investigationData?.findings_count ?? recentFindings.length}
              </span>
            </div>
          </div>
        </div>

        {/* Card 2: Specialized DFIR Capabilities */}
        <div className="bg-[#0e1626] border border-slate-800 rounded-xl p-4 shadow-lg space-y-3 lg:col-span-2">
          <div className="flex items-center justify-between pb-2 border-b border-slate-800">
            <span className="text-xs font-bold text-slate-200 flex items-center space-x-2">
              <Shield className="w-4 h-4 text-emerald-400" />
              <span>Specialized DFIR Capabilities (Level 3)</span>
            </span>
            <span className="text-[10px] font-mono text-slate-400 uppercase">Modular Allowlist</span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {specialists.map((spec) => (
              <div
                key={spec.specialist_id}
                className="bg-[#080d18] border border-slate-800/80 rounded-lg p-3 space-y-1.5"
              >
                <div className="flex items-center justify-between">
                  <span className="font-bold text-xs text-white">{spec.name}</span>
                  <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-cyan-300">
                    {spec.domain}
                  </span>
                </div>
                <p className="text-[11px] text-slate-400 leading-relaxed line-clamp-2">
                  {spec.objective_definition}
                </p>
                <div className="flex flex-wrap gap-1 pt-1">
                  {spec.allowlisted_capabilities?.map((cap: string) => (
                    <span
                      key={cap}
                      className="text-[9px] font-mono px-1.5 py-0.2 rounded bg-slate-900 border border-slate-800 text-slate-300"
                    >
                      {cap}
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Competing Hypotheses & Evidence Gaps */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Competing Hypotheses Card */}
        <div className="bg-[#0e1626] border border-slate-800 rounded-xl p-4 shadow-lg space-y-3">
          <div className="flex items-center justify-between pb-2 border-b border-slate-800">
            <span className="text-xs font-bold text-slate-200 flex items-center space-x-2">
              <Sparkles className="w-4 h-4 text-indigo-400" />
              <span>Competing Hypotheses</span>
            </span>
            <span className="text-[10px] font-mono text-slate-400 uppercase">Empirical Evaluation</span>
          </div>

          {investigationData?.hypotheses && investigationData.hypotheses.length > 0 ? (
            <div className="space-y-2.5">
              {investigationData.hypotheses.map((hyp: any) => (
                <div
                  key={hyp.hypothesis_id}
                  className="bg-[#080d18] border border-slate-800 rounded-lg p-3 space-y-1.5"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-xs text-slate-200">{hyp.title}</span>
                    <span
                      className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold uppercase ${
                        hyp.status === "supported"
                          ? "bg-emerald-950 text-emerald-300 border border-emerald-800"
                          : hyp.status === "refuted"
                          ? "bg-rose-950 text-rose-300 border border-rose-800"
                          : "bg-slate-800 text-slate-400 border border-slate-700"
                      }`}
                    >
                      {hyp.status} ({Math.round((hyp.confidence ?? 0.5) * 100)}%)
                    </span>
                  </div>
                  <p className="text-xs text-slate-300 font-mono leading-relaxed">{hyp.description}</p>
                  <div className="flex items-center space-x-4 text-[11px] text-slate-400 pt-1 font-mono">
                    <span>Supporting Facts: {hyp.supporting_finding_ids?.length ?? 0}</span>
                    <span>Contradicting: {hyp.contradicting_finding_ids?.length ?? 0}</span>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="p-6 text-center text-slate-500 font-mono text-xs">
              No hypotheses formulated yet. Start an investigation to generate and evaluate competing hypotheses.
            </div>
          )}
        </div>

        {/* Evidence Gaps Card */}
        <div className="bg-[#0e1626] border border-slate-800 rounded-xl p-4 shadow-lg space-y-3">
          <div className="flex items-center justify-between pb-2 border-b border-slate-800">
            <span className="text-xs font-bold text-slate-200 flex items-center space-x-2">
              <HelpCircle className="w-4 h-4 text-amber-400" />
              <span>Evidence Gaps & Data Deficits</span>
            </span>
            <span className="text-[10px] font-mono text-slate-400 uppercase">Absence vs Unavailable</span>
          </div>

          {investigationData?.evidence_gaps && investigationData.evidence_gaps.length > 0 ? (
            <div className="space-y-2.5">
              {investigationData.evidence_gaps.map((gap: any) => (
                <div
                  key={gap.gap_id}
                  className="bg-[#080d18] border border-slate-800 rounded-lg p-3 space-y-1.5"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-xs text-amber-300 font-mono">
                      Missing: {gap.missing_artifact_type}
                    </span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-950/80 text-amber-300 border border-amber-800">
                      {gap.is_evidence_of_absence ? "Evidence of Absence" : "Data Unavailable"}
                    </span>
                  </div>
                  <p className="text-xs text-slate-300">{gap.tactical_reason}</p>
                  <p className="text-[11px] text-slate-400 font-mono">
                    Recommended: {gap.recommended_collection}
                  </p>
                </div>
              ))}
            </div>
          ) : (
            <div className="p-6 text-center text-slate-500 font-mono text-xs">
              No evidence gaps flagged. All required telemetry artifacts are satisfied.
            </div>
          )}
        </div>
      </div>

      {/* Tool Execution History Table */}
      <div className="bg-[#0e1626] border border-slate-800 rounded-xl p-4 shadow-lg space-y-3">
        <div className="flex items-center justify-between pb-2 border-b border-slate-800">
          <span className="text-xs font-bold text-slate-200 flex items-center space-x-2">
            <Wrench className="w-4 h-4 text-cyan-400" />
            <span>Deterministic Tool Execution History</span>
          </span>
          <span className="text-[10px] font-mono text-slate-400 uppercase">Provenance Audit</span>
        </div>

        {toolHistory && toolHistory.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-[#080d18] text-slate-400 border-b border-slate-800">
                <tr>
                  <th className="p-2.5">Action ID</th>
                  <th className="p-2.5">Capability / Tool</th>
                  <th className="p-2.5">Target Artifact</th>
                  <th className="p-2.5">Justification</th>
                  <th className="p-2.5">Status</th>
                  <th className="p-2.5">Facts Generated</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {toolHistory.map((act) => (
                  <tr key={act.action_id} className="hover:bg-slate-900/40">
                    <td className="p-2.5 text-cyan-400">{act.action_id}</td>
                    <td className="p-2.5 font-bold text-white">{act.capability_id}</td>
                    <td className="p-2.5 text-slate-300">{act.artifact_id || "Case Storage"}</td>
                    <td className="p-2.5 text-slate-400 max-w-xs truncate" title={act.justification}>
                      {act.justification || "Automated analysis step"}
                    </td>
                    <td className="p-2.5">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold ${
                          act.status === "completed"
                            ? "bg-emerald-950 text-emerald-300"
                            : act.status === "failed"
                            ? "bg-rose-950 text-rose-300"
                            : "bg-slate-800 text-slate-400"
                        }`}
                      >
                        {act.status}
                      </span>
                    </td>
                    <td className="p-2.5 text-emerald-400 font-bold">{act.findings_count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="p-6 text-center text-slate-500 font-mono text-xs">
            No external tools executed in this session yet.
          </div>
        )}
      </div>

      {/* Verified Findings Preview */}
      <div className="bg-[#0e1626] border border-slate-800 rounded-xl p-4 shadow-lg space-y-3">
        <div className="flex items-center justify-between pb-2 border-b border-slate-800">
          <span className="text-xs font-bold text-slate-200 flex items-center space-x-2">
            <FileCheck className="w-4 h-4 text-emerald-400" />
            <span>Verified Findings & Empirical Telemetry</span>
          </span>
          <button
            onClick={() => setActiveTab("report")}
            className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center space-x-1"
          >
            <span>View Full Cited Report</span>
            <ExternalLink className="w-3.5 h-3.5" />
          </button>
        </div>

        {recentFindings && recentFindings.length > 0 ? (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {recentFindings.map((fnd) => (
              <div
                key={fnd.finding_id}
                onClick={() => openCitationDrawer(fnd)}
                className="bg-[#080d18] border border-slate-800/80 hover:border-cyan-500/50 rounded-lg p-3 space-y-1.5 cursor-pointer transition-all"
              >
                <div className="flex items-center justify-between">
                  <span className="font-mono text-[11px] text-cyan-400 font-bold">{fnd.finding_id}</span>
                  <span
                    className={`text-[9px] font-mono px-1.5 py-0.5 rounded font-bold uppercase ${
                      fnd.severity === "critical"
                        ? "bg-rose-950 text-rose-300"
                        : fnd.severity === "high"
                        ? "bg-orange-950 text-orange-300"
                        : fnd.severity === "medium"
                        ? "bg-amber-950 text-amber-300"
                        : "bg-slate-800 text-slate-400"
                    }`}
                  >
                    {fnd.severity}
                  </span>
                </div>
                <p className="text-xs text-slate-200 font-mono line-clamp-2">{fnd.summary}</p>
                <div className="flex items-center justify-between text-[10px] text-slate-400 font-mono pt-1">
                  <span>Host: {fnd.host || "N/A"}</span>
                  <span>{fnd.timestamp_utc || "No Timestamp"}</span>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="p-6 text-center text-slate-500 font-mono text-xs">
            No findings indexed in case storage yet.
          </div>
        )}
      </div>

      {/* Human Approval Gate Modal */}
      <ApprovalReviewModal
        isOpen={isApprovalModalOpen}
        request={currentApprovalRequest}
        onClose={() => setIsApprovalModalOpen(false)}
        onDecisionComplete={(updated) => handleResumeAfterApproval(updated.token || undefined)}
      />
    </div>
  );
};
