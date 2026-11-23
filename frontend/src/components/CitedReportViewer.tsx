import React, { useState, useEffect } from "react";
import {
  FileText,
  ShieldCheck,
  ShieldAlert,
  Download,
  Copy,
  Check,
  Clock,
  User,
  Server,
  Terminal,
  ExternalLink,
  ThumbsUp,
  RotateCcw,
  Sparkles,
  AlertTriangle,
  Search,
  CheckCircle2,
  HelpCircle,
  FileCode,
  Layers,
  Share2,
  Globe,
} from "lucide-react";
import { useForensicStore } from "../store/useForensicStore";
import { useInvestigation } from "../context/InvestigationContext";
import { api, triggerBrowserDownload } from "../services/api";
import { CitedClaim, ForensicFinding, FindingSeverity } from "../types";

export const CitedReportViewer: React.FC = () => {
  const {
    currentCaseId,
    report,
    reportMarkdown,
    setReportData,
    openCitationDrawer,
  } = useForensicStore();
  const { caseId, wizardState, updateWizardState } = useInvestigation();
  const [isSharingVault, setIsSharingVault] = useState<boolean>(false);

  const [activeTab, setActiveTab] = useState<"visual" | "markdown">("visual");
  const [copiedMd, setCopiedMd] = useState<boolean>(false);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [isExporting, setIsExporting] = useState<boolean>(false);
  const [feedbackSuccess, setFeedbackSuccess] = useState<string | null>(null);

  // Load report on mount if not loaded
  useEffect(() => {
    if (!report) {
      loadReport();
    }
  }, [currentCaseId]);

  const loadReport = async () => {
    setIsLoading(true);
    try {
      const data = await api.getReport(currentCaseId);
      setReportData(data.report, data.markdown);
    } catch {
      // If no report compiled yet, keep null
    } finally {
      setIsLoading(false);
    }
  };

  const copyMarkdown = () => {
    navigator.clipboard.writeText(reportMarkdown);
    setCopiedMd(true);
    setTimeout(() => setCopiedMd(false), 2000);
  };

  const handleExport = async (format: "markdown" | "json") => {
    setIsExporting(true);
    try {
      const { blob, filename } = await api.exportReport(currentCaseId, format);
      triggerBrowserDownload(blob, filename);
    } catch (err: any) {
      alert(`Export failed: ${err.message}`);
    } finally {
      setIsExporting(false);
    }
  };

  const downloadMarkdown = () => {
    handleExport("markdown");
  };

  const handleCitationClick = async (findingId: string) => {
    try {
      const finding = await api.getFinding(findingId, currentCaseId);
      openCitationDrawer(finding);
    } catch (err: any) {
      alert(`Could not load finding ${findingId}: ${err.message}`);
    }
  };

  const handleMicroFeedback = async (
    claim: CitedClaim,
    feedbackType: "true_positive" | "false_positive_benign_baseline" | "query_correction"
  ) => {
    try {
      await api.submitFeedback({
        case_id: currentCaseId,
        finding_id: claim.citing_finding_ids[0] || undefined,
        feedback_type: feedbackType,
        scope: feedbackType === "false_positive_benign_baseline" ? "organization_baseline" : "this_case_only",
        analyst_note: `Micro-feedback on claim: ${claim.statement.substring(0, 60)}...`,
      });
      setFeedbackSuccess(`Feedback logged: ${feedbackType.replace("_", " ")}`);
      setTimeout(() => setFeedbackSuccess(null), 3000);
    } catch (err: any) {
      alert(`Feedback submission failed: ${err.message}`);
    }
  };

  const handleToggleVaultShare = async () => {
    const targetCaseId = currentCaseId || caseId;
    if (!targetCaseId) return;
    const nextShare = !wizardState.isSharedToVault;
    setIsSharingVault(true);
    try {
      const res = await api.shareCaseToVault(targetCaseId, nextShare);
      updateWizardState({ isSharedToVault: res.is_shared_to_vault });
      setFeedbackSuccess(res.is_shared_to_vault ? "Case published to Forensic Peer Review Vault" : "Case removed from Vault");
      setTimeout(() => setFeedbackSuccess(null), 3500);
    } catch (err: any) {
      alert(`Failed to update vault share status: ${err.message || err}`);
    } finally {
      setIsSharingVault(false);
    }
  };

  if (isLoading) {
    return (
      <div className="flex flex-col items-center justify-center h-[calc(100vh-68px)] bg-slate-950 text-slate-400 gap-3">
        <Sparkles className="w-8 h-8 text-cyan-400 animate-spin" />
        <span className="font-mono text-xs">Compiling Cited Forensic Report from Verified Store...</span>
      </div>
    );
  }

  if (!report && !reportMarkdown) {
    return (
      <div className="flex flex-col items-center justify-center h-[calc(100vh-68px)] bg-slate-950 text-slate-400 p-8 text-center">
        <div className="p-4 bg-slate-900 border border-slate-800 rounded-2xl max-w-md space-y-4 shadow-xl">
          <FileText className="w-10 h-10 text-slate-500 mx-auto" />
          <div>
            <h3 className="font-bold text-slate-200 text-sm">No Report Generated Yet</h3>
            <p className="text-xs text-slate-400 mt-1">
              Run a triage workflow on the Canvas or execute tools to generate a 6-section verified forensic report.
            </p>
          </div>
          <button
            onClick={loadReport}
            className="px-4 py-2 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-xs rounded-lg transition-colors"
          >
            Check for Available Report
          </button>
        </div>
      </div>
    );
  }

  const exec = report?.executive_summary;
  const custody = report?.custody_and_filter_audit;
  const patientZero = report?.patient_zero_and_remediation;

  return (
    <div className="h-[calc(100vh-68px)] flex flex-col bg-slate-950 overflow-hidden text-slate-200">
      {/* Top Report Toolbar */}
      <div className="h-14 border-b border-slate-800 bg-slate-900/90 backdrop-blur-md px-6 flex items-center justify-between z-10 shrink-0">
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2 text-cyan-400 font-semibold text-sm">
            <FileText className="w-4 h-4" />
            <span>Forensic Evidence Report</span>
          </div>
          <span className="text-xs font-mono text-slate-400">[{currentCaseId}]</span>
          {report?.status && (
            <span
              className={`text-[10px] font-mono uppercase px-2 py-0.5 rounded font-bold border ${
                report.status === "signed" || report.status === "finalized"
                  ? "bg-emerald-950/80 text-emerald-400 border-emerald-700/60"
                  : report.status === "blocked"
                  ? "bg-rose-950/80 text-rose-400 border-rose-700/60"
                  : report.status === "incomplete"
                  ? "bg-amber-950/80 text-amber-400 border-amber-700/60"
                  : "bg-slate-800 text-slate-300 border-slate-700"
              }`}
            >
              {report.status} (v{report.version || 1})
            </span>
          )}

          <div className="h-4 w-px bg-slate-700" />

          {/* Tab Switcher */}
          <div className="flex items-center bg-slate-950 p-1 rounded-lg border border-slate-800 text-xs">
            <button
              onClick={() => setActiveTab("visual")}
              className={`px-3 py-1 rounded-md font-medium transition-colors ${
                activeTab === "visual"
                  ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/30"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              Structured Visual Report
            </button>
            <button
              onClick={() => setActiveTab("markdown")}
              className={`px-3 py-1 rounded-md font-medium transition-colors ${
                activeTab === "markdown"
                  ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/30"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              Raw Forensic Markdown
            </button>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-3">
          {feedbackSuccess && (
            <span className="text-xs text-emerald-400 bg-emerald-950/80 px-2.5 py-1 rounded-full border border-emerald-700/50 flex items-center gap-1 font-mono">
              <CheckCircle2 className="w-3.5 h-3.5" /> {feedbackSuccess}
            </span>
          )}

          <button
            onClick={copyMarkdown}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium rounded-lg border border-slate-700 transition-colors"
          >
            {copiedMd ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copiedMd ? "Copied" : "Copy Markdown"}</span>
          </button>

          <button
            onClick={() => handleExport("markdown")}
            disabled={isExporting}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-semibold rounded-lg shadow-md transition-colors disabled:opacity-50"
            title="Download verified cited forensic report as Markdown"
          >
            <Download className="w-3.5 h-3.5" />
            <span>{isExporting ? "Exporting..." : "Export .MD"}</span>
          </button>

          <button
            onClick={() => handleExport("json")}
            disabled={isExporting}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-cyan-300 text-xs font-semibold rounded-lg border border-cyan-800/50 transition-colors disabled:opacity-50"
            title="Download structured forensic report with telemetry as JSON"
          >
            <FileCode className="w-3.5 h-3.5" />
            <span>Export .JSON</span>
          </button>
        </div>
      </div>

      {/* Main Content Area */}
      <div className="flex-1 overflow-y-auto p-8 max-w-6xl mx-auto w-full">
        {activeTab === "markdown" ? (
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 font-mono text-xs leading-relaxed text-slate-300 whitespace-pre-wrap selection:bg-cyan-500/30">
            {reportMarkdown}
          </div>
        ) : (
          <div className="space-y-8 pb-12">
            {/* Peer Review & Case Vault Sharing Card */}
            <div className="bg-[#0b1324] border border-cyan-800/40 rounded-2xl p-5 shadow-xl flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
              <div className="flex items-start space-x-3.5">
                <div className="p-2.5 rounded-xl bg-cyan-950/70 border border-cyan-700/50 text-cyan-400 mt-0.5">
                  <Share2 className="w-5 h-5" />
                </div>
                <div>
                  <div className="flex items-center space-x-2">
                    <h3 className="text-sm font-semibold text-white">
                      Forensic Peer Review & Case Vault Sharing
                    </h3>
                    {wizardState.isSharedToVault ? (
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950/80 border border-emerald-700/50 text-emerald-400 flex items-center gap-1">
                        <Globe className="w-3 h-3" /> Published in Vault
                      </span>
                    ) : (
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-gray-800 border border-gray-700 text-gray-400">
                        Private / Local Only
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-gray-400 mt-0.5 max-w-2xl">
                    Publish this verified investigation to the team-wide Forensic Case Vault so peers can review verified [fnd-xxx] citations, ACH hypothesis reasoning, and chain-of-custody hashes.
                  </p>
                </div>
              </div>

              <div className="flex items-center space-x-3 self-end md:self-center shrink-0">
                <button
                  onClick={handleToggleVaultShare}
                  disabled={isSharingVault}
                  className={`flex items-center space-x-2 px-4 py-2 rounded-xl text-xs font-semibold border transition-all ${
                    wizardState.isSharedToVault
                      ? "bg-rose-950/40 border-rose-800 text-rose-300 hover:bg-rose-900/50"
                      : "bg-cyan-500 hover:bg-cyan-400 text-slate-950 border-cyan-400 shadow-md shadow-cyan-500/10"
                  }`}
                >
                  <Share2 className="w-3.5 h-3.5" />
                  <span>
                    {isSharingVault
                      ? "Updating..."
                      : wizardState.isSharedToVault
                      ? "Revoke Vault Access (Make Private)"
                      : "Share to Forensic Case Vault (Optional)"}
                  </span>
                </button>
              </div>
            </div>

            {/* SECTION 1: Executive Summary & Timeline */}
            <section className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-6">
              <div className="flex items-center justify-between pb-4 border-b border-slate-800">
                <div className="space-y-1">
                  <h2 className="text-lg font-bold text-slate-100 flex items-center gap-2">
                    <ShieldCheck className="w-5 h-5 text-cyan-400" />
                    <span>1. Executive Summary & Incident Timeline</span>
                  </h2>
                  <p className="text-xs text-slate-400">
                    High-level assessment and chronological sequence of verified adversarial activity
                  </p>
                </div>
                {exec?.severity && (
                  <span
                    className={`text-xs font-bold uppercase px-3 py-1 rounded-full border ${
                      exec.severity === "critical"
                        ? "bg-rose-950/80 text-rose-300 border-rose-700"
                        : exec.severity === "high"
                        ? "bg-orange-950/80 text-orange-300 border-orange-700"
                        : "bg-blue-950/80 text-blue-300 border-blue-700"
                    }`}
                  >
                    Severity: {exec.severity}
                  </span>
                )}
              </div>

              {/* Stats Grid */}
              <div className="grid grid-cols-4 gap-4 text-xs font-mono">
                <div className="bg-slate-950/80 p-3 rounded-xl border border-slate-800">
                  <span className="text-slate-500 block text-[10px] uppercase">Earliest Activity</span>
                  <span className="text-cyan-300 font-semibold">{exec?.earliest_timestamp_utc || "N/A"}</span>
                </div>
                <div className="bg-slate-950/80 p-3 rounded-xl border border-slate-800">
                  <span className="text-slate-500 block text-[10px] uppercase">Latest Activity</span>
                  <span className="text-cyan-300 font-semibold">{exec?.latest_timestamp_utc || "N/A"}</span>
                </div>
                <div className="bg-slate-950/80 p-3 rounded-xl border border-slate-800">
                  <span className="text-slate-500 block text-[10px] uppercase">Impacted Hosts</span>
                  <span className="text-amber-300 font-semibold">{exec?.impacted_hosts?.join(", ") || "None"}</span>
                </div>
                <div className="bg-slate-950/80 p-3 rounded-xl border border-slate-800">
                  <span className="text-slate-500 block text-[10px] uppercase">Impacted Users</span>
                  <span className="text-emerald-300 font-semibold">{exec?.impacted_users?.join(", ") || "None"}</span>
                </div>
              </div>

              {/* Overview text */}
              <div className="text-xs text-slate-300 leading-relaxed bg-slate-950/50 p-4 rounded-xl border border-slate-800/80">
                {exec?.incident_overview || "Detailed incident timeline derived from userspace artifact streams."}
              </div>

              {/* Evidence Conflicts Table (Never suppress contradictory observations) */}
              {report?.evidence_conflicts && report.evidence_conflicts.length > 0 && (
                <div className="p-4 bg-amber-950/30 border border-amber-800/50 rounded-xl space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-amber-300 uppercase tracking-wider font-mono flex items-center gap-1.5">
                      <AlertTriangle className="w-4 h-4 text-amber-400" />
                      Preserved Evidence Conflicts & Contradictions ({report.evidence_conflicts.length})
                    </span>
                    <span className="text-[10px] text-amber-400/80 font-mono">Contradictory observations preserved without suppression</span>
                  </div>
                  <div className="space-y-2">
                    {report.evidence_conflicts.map((c, cIdx) => (
                      <div key={cIdx} className="bg-slate-950/80 border border-amber-900/40 p-2.5 rounded-lg text-xs flex items-start justify-between gap-3 font-mono">
                        <div className="space-y-1">
                          <div className="flex items-center gap-2">
                            <span className="text-amber-400 font-semibold uppercase text-[10px] bg-amber-950/80 px-1.5 py-0.5 rounded border border-amber-700/50">
                              {c.conflict_type}
                            </span>
                            <span className="text-slate-200">{c.description}</span>
                          </div>
                          {c.affected_finding_ids && c.affected_finding_ids.length > 0 && (
                            <span className="text-[11px] text-slate-400 block">
                              Affected Findings: {c.affected_finding_ids.join(", ")}
                            </span>
                          )}
                        </div>
                        <span className="text-[10px] uppercase font-bold text-amber-400 px-2 py-0.5 bg-amber-950 rounded">
                          {c.severity}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Chronological Timeline */}
              {exec?.timeline && exec.timeline.length > 0 && (
                <div className="space-y-3 pt-2">
                  <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider font-mono">
                    Incident Chronology ({exec.timeline.length} events)
                  </h3>
                  <div className="relative pl-6 space-y-4 before:absolute before:left-2 before:top-2 before:bottom-2 before:w-0.5 before:bg-slate-800">
                    {exec.timeline.map((entry, idx) => (
                      <div key={idx} className="relative group">
                        <div className="absolute -left-6 top-1.5 w-2.5 h-2.5 rounded-full bg-cyan-400 border-2 border-slate-950 group-hover:scale-125 transition-transform" />
                        <div className="bg-slate-950/80 border border-slate-800 group-hover:border-slate-700 rounded-xl p-3 text-xs space-y-1.5 transition-colors">
                          <div className="flex items-center justify-between text-[11px]">
                            <span className="font-mono text-cyan-400 font-semibold">{entry.timestamp_utc}</span>
                            <span
                              className={`uppercase text-[10px] px-1.5 py-0.2 rounded font-bold ${
                                entry.severity === "critical"
                                  ? "text-rose-400 bg-rose-950/80"
                                  : entry.severity === "high"
                                  ? "text-orange-400 bg-orange-950/80"
                                  : "text-slate-400 bg-slate-800"
                              }`}
                            >
                              {entry.severity}
                            </span>
                          </div>
                          <p className="text-slate-200 font-medium">{entry.summary}</p>
                          <div className="flex items-center justify-between pt-1 text-[11px] font-mono text-slate-400 border-t border-slate-900">
                            <span>Process: {entry.process_or_event}</span>
                            <button
                              onClick={() => handleCitationClick(entry.citing_finding_id)}
                              className="text-cyan-400 hover:text-cyan-300 underline flex items-center gap-1"
                            >
                              <span>[{entry.citing_finding_id}]</span>
                              <ExternalLink className="w-3 h-3" />
                            </button>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </section>

            {/* SECTION 2: Chain of Custody & Evidence Audit */}
            <section className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
              <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
                  <ShieldCheck className="w-5 h-5 text-emerald-400" />
                  <span>2. Chain of Custody & Column Projection Audit</span>
                </h2>
                {custody?.tamper_check_passed !== undefined && (
                  <span
                    className={`text-xs font-semibold px-2.5 py-1 rounded-full border ${
                      custody.tamper_check_passed
                        ? "bg-emerald-950/80 text-emerald-300 border-emerald-700/60"
                        : "bg-rose-950/80 text-rose-300 border-rose-700/60"
                    }`}
                  >
                    {custody.tamper_check_passed ? "✓ HASH CHAIN VERIFIED" : "⚠ INTEGRITY BREACH / INCOMPLETE"}
                  </span>
                )}
              </div>

              {custody?.verification_errors && custody.verification_errors.length > 0 && (
                <div className="p-3 bg-rose-950/40 border border-rose-800/60 rounded-xl space-y-1 text-xs font-mono text-rose-300">
                  <span className="font-bold flex items-center gap-1.5 text-rose-400">
                    <AlertTriangle className="w-4 h-4" /> Custody Chain Discrepancies:
                  </span>
                  <ul className="list-disc list-inside space-y-0.5 text-[11px] text-rose-200">
                    {custody.verification_errors.map((err, eIdx) => (
                      <li key={eIdx}>{err}</li>
                    ))}
                  </ul>
                </div>
              )}

              <div className="border border-slate-800 rounded-xl overflow-hidden">
                <table className="w-full text-left border-collapse text-xs">
                  <thead>
                    <tr className="bg-slate-950 border-b border-slate-800 text-slate-400 text-[11px] font-mono uppercase">
                      <th className="p-3">Artifact ID</th>
                      <th className="p-3">Type</th>
                      <th className="p-3">Original Source Path</th>
                      <th className="p-3">SHA-256 Digest</th>
                      <th className="p-3">Access Tier</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 font-mono text-[11px] text-slate-300">
                    {(custody?.evidence_items || []).map((ev: any, idx: number) => (
                      <tr key={idx} className="hover:bg-slate-800/30">
                        <td className="p-3 text-cyan-400 font-semibold">{ev.artifact_id}</td>
                        <td className="p-3 text-amber-300">{ev.type}</td>
                        <td className="p-3 text-slate-300 truncate max-w-[200px]" title={ev.original_path}>
                          {ev.original_path}
                        </td>
                        <td className="p-3 text-emerald-400 truncate max-w-[150px]" title={ev.sha256}>
                          {ev.sha256 ? `${ev.sha256.substring(0, 16)}...` : "-"}
                        </td>
                        <td className="p-3 text-slate-400">
                          <span className="bg-slate-800 px-1.5 py-0.5 rounded text-[10px]">
                            {ev.blob_path?.startsWith(":ro:") ? "Zero-Copy :ro:" : "0400 Vault"}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>

            {/* SECTION 3: Observed Facts */}
            <section className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
              <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
                  <CheckCircle2 className="w-5 h-5 text-cyan-400" />
                  <span>3. Observed Facts (Deterministic Tool Extractions)</span>
                </h2>
                <span className="text-xs text-slate-400 font-mono">
                  {report?.observed_facts?.length || 0} facts verified
                </span>
              </div>

              <div className="space-y-3">
                {(report?.observed_facts || []).map((fact, idx) => (
                  <div
                    key={fact.claim_id || idx}
                    className="p-4 bg-slate-950/80 border border-slate-800 rounded-xl space-y-2 hover:border-slate-700 transition-colors"
                  >
                    <div className="flex items-center justify-between text-xs">
                      <span className="font-mono text-cyan-400 font-semibold">FACT #{idx + 1}</span>
                      <span className="text-[11px] text-emerald-400 font-mono bg-emerald-950/60 px-2 py-0.5 rounded">
                        Confidence: {Math.round((fact.confidence || 1.0) * 100)}%
                      </span>
                    </div>
                    <p className="text-xs font-semibold text-slate-200">{fact.statement}</p>

                    {/* Citations and Micro-feedback */}
                    <div className="flex items-center justify-between pt-2 border-t border-slate-900 text-xs">
                      <div className="flex items-center gap-2 font-mono text-[11px]">
                        <span className="text-slate-500">Citations:</span>
                        {fact.citing_finding_ids?.map((fId) => (
                          <button
                            key={fId}
                            onClick={() => handleCitationClick(fId)}
                            className="text-cyan-400 hover:text-cyan-300 underline"
                          >
                            [{fId}]
                          </button>
                        ))}
                      </div>

                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => handleMicroFeedback(fact, "true_positive")}
                          className="flex items-center gap-1 text-[11px] text-emerald-400 hover:text-emerald-300 bg-emerald-950/40 px-2 py-0.5 rounded border border-emerald-800/40"
                        >
                          <ThumbsUp className="w-3 h-3" />
                          <span>Confirm TP</span>
                        </button>
                        <button
                          onClick={() => handleMicroFeedback(fact, "false_positive_benign_baseline")}
                          className="flex items-center gap-1 text-[11px] text-amber-400 hover:text-amber-300 bg-amber-950/40 px-2 py-0.5 rounded border border-amber-800/40"
                        >
                          <ShieldAlert className="w-3 h-3" />
                          <span>Mark Benign</span>
                        </button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </section>

            {/* SECTION 4: Derived Correlations */}
            <section className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
              <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
                  <Sparkles className="w-5 h-5 text-purple-400" />
                  <span>4. Derived Correlations (Cross-Source Synthesis)</span>
                </h2>
                <span className="text-xs text-slate-400 font-mono">
                  {report?.derived_correlations?.length || 0} correlations
                </span>
              </div>

              <div className="space-y-3">
                {(report?.derived_correlations || []).map((corr, idx) => (
                  <div
                    key={corr.claim_id || idx}
                    className="p-4 bg-slate-950/80 border border-purple-900/40 rounded-xl space-y-2 hover:border-purple-700/60 transition-colors"
                  >
                    <div className="flex items-center justify-between text-xs">
                      <span className="font-mono text-purple-300 font-semibold">CORRELATION #{idx + 1}</span>
                      <span className="text-[11px] text-purple-300 font-mono bg-purple-950/60 px-2 py-0.5 rounded">
                        Confidence: {Math.round((corr.confidence || 0.85) * 100)}%
                      </span>
                    </div>
                    <p className="text-xs font-semibold text-slate-200">{corr.statement}</p>
                    {corr.why_it_matters && (
                      <p className="text-xs text-slate-400 italic">“{corr.why_it_matters}”</p>
                    )}

                    <div className="flex items-center justify-between pt-2 border-t border-slate-900 text-xs">
                      <div className="flex items-center gap-2 font-mono text-[11px]">
                        <span className="text-slate-500">Citing Findings:</span>
                        {corr.citing_finding_ids?.map((fId) => (
                          <button
                            key={fId}
                            onClick={() => handleCitationClick(fId)}
                            className="text-purple-300 hover:text-purple-200 underline"
                          >
                            [{fId}]
                          </button>
                        ))}
                      </div>

                      <button
                        onClick={() => handleMicroFeedback(corr, "true_positive")}
                        className="flex items-center gap-1 text-[11px] text-purple-300 hover:text-purple-200 bg-purple-950/40 px-2 py-0.5 rounded border border-purple-800/40"
                      >
                        <ThumbsUp className="w-3 h-3" />
                        <span>Confirm Correlation</span>
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </section>

            {/* SECTION 4B: Unverified Hypotheses & Evaluated Leads */}
            {report?.unverified_hypotheses && report.unverified_hypotheses.length > 0 && (
              <section className="bg-amber-950/20 border border-amber-800/50 rounded-2xl p-6 shadow-xl space-y-4">
                <div className="flex flex-col md:flex-row md:items-center justify-between pb-3 border-b border-amber-800/40 gap-2">
                  <div className="space-y-1">
                    <h2 className="text-base font-bold text-amber-200 flex items-center gap-2">
                      <AlertTriangle className="w-5 h-5 text-amber-400" />
                      <span>4B. Unverified Hypotheses & Evaluated Leads (Analyst Review Required)</span>
                    </h2>
                    <p className="text-xs text-amber-300/80 font-mono">
                      FORENSIC DISCLAIMER: The following assertions represent investigative leads, downgraded hypotheses, or ungrounded claims. They are NOT confirmed forensic facts and must NOT be cited as verified evidence in legal or containment proceedings.
                    </p>
                  </div>
                  <span className="text-xs text-amber-400 font-mono shrink-0">
                    {report.unverified_hypotheses.length} unverified leads
                  </span>
                </div>

                <div className="space-y-3">
                  {report.unverified_hypotheses.map((hyp, idx) => (
                    <div
                      key={hyp.claim_id || idx}
                      className="p-4 bg-slate-950/90 border border-amber-900/60 rounded-xl space-y-2 hover:border-amber-700/80 transition-colors"
                    >
                      <div className="flex items-center justify-between text-xs">
                        <span className="font-mono text-amber-400 font-semibold">LEAD #{idx + 1} ({hyp.claim_type})</span>
                        <span className="text-[11px] text-amber-300 font-mono bg-amber-950/80 px-2 py-0.5 rounded border border-amber-800/50">
                          Confidence: {Math.round((hyp.confidence || 0.4) * 100)}% (UNVERIFIED)
                        </span>
                      </div>
                      <p className="text-xs font-semibold text-slate-200">{hyp.statement}</p>
                      {hyp.review_notes && (
                        <p className="text-xs text-amber-300/90 bg-amber-950/40 p-2 rounded border border-amber-900/50 font-mono">
                          Review Notes: {hyp.review_notes}
                        </p>
                      )}

                      <div className="flex items-center justify-between pt-2 border-t border-slate-900 text-xs">
                        <div className="flex items-center gap-2 font-mono text-[11px]">
                          <span className="text-slate-500">Related Findings:</span>
                          {hyp.citing_finding_ids && hyp.citing_finding_ids.length > 0 ? (
                            hyp.citing_finding_ids.map((fId) => (
                              <button
                                key={fId}
                                onClick={() => handleCitationClick(fId)}
                                className="text-amber-400 hover:text-amber-300 underline"
                              >
                                [{fId}]
                              </button>
                            ))
                          ) : (
                            <span className="text-slate-600">None cited</span>
                          )}
                        </div>

                        <button
                          onClick={() => handleMicroFeedback(hyp, "query_correction")}
                          className="flex items-center gap-1 text-[11px] text-amber-400 hover:text-amber-300 bg-amber-950/60 px-2 py-0.5 rounded border border-amber-800/50"
                        >
                          <RotateCcw className="w-3 h-3" />
                          <span>Correct Lead</span>
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </section>
            )}

            {/* SECTION 5: AIFT 4-Part Rubric */}
            <section className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
              <div className="pb-3 border-b border-slate-800">
                <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
                  <Layers className="w-5 h-5 text-amber-400" />
                  <span>5. AIFT 4-Part Evaluation Rubric</span>
                </h2>
                <p className="text-xs text-slate-400 mt-1">
                  Rigorous adversarial defense: Operational Impact, Benign Alternative, Verification Steps, and Telemetry Gaps
                </p>
              </div>

              <div className="space-y-4">
                {(report?.aift_rubric || []).map((item, idx) => (
                  <div
                    key={item.claim_id || idx}
                    className="p-5 bg-slate-950/80 border border-slate-800 rounded-xl space-y-4"
                  >
                    <div className="font-semibold text-xs text-slate-200 border-b border-slate-900 pb-2">
                      Claim: {item.statement}
                    </div>

                    <div className="grid grid-cols-2 gap-4 text-xs">
                      {/* 1. Why it matters */}
                      <div className="p-3 bg-slate-900/80 rounded-lg border border-slate-800 space-y-1">
                        <span className="text-rose-400 font-semibold flex items-center gap-1.5">
                          <AlertTriangle className="w-3.5 h-3.5" /> 1. Why It Matters
                        </span>
                        <p className="text-slate-300 leading-relaxed text-[11px]">{item.why_it_matters}</p>
                      </div>

                      {/* 2. Benign Alternative */}
                      <div className="p-3 bg-slate-900/80 rounded-lg border border-slate-800 space-y-1">
                        <span className="text-emerald-400 font-semibold flex items-center gap-1.5">
                          <CheckCircle2 className="w-3.5 h-3.5" /> 2. Benign Alternative
                        </span>
                        <p className="text-slate-300 leading-relaxed text-[11px]">{item.benign_alternative}</p>
                      </div>

                      {/* 3. How to verify */}
                      <div className="p-3 bg-slate-900/80 rounded-lg border border-slate-800 space-y-1">
                        <span className="text-cyan-400 font-semibold flex items-center gap-1.5">
                          <Search className="w-3.5 h-3.5" /> 3. How to Verify
                        </span>
                        <ul className="list-disc list-inside text-slate-300 text-[11px] space-y-0.5">
                          {(item.verification_steps || []).map((step, sIdx) => (
                            <li key={sIdx}>{step}</li>
                          ))}
                        </ul>
                      </div>

                      {/* 4. Data Gaps */}
                      <div className="p-3 bg-slate-900/80 rounded-lg border border-slate-800 space-y-1">
                        <span className="text-amber-400 font-semibold flex items-center gap-1.5">
                          <HelpCircle className="w-3.5 h-3.5" /> 4. Data Gaps
                        </span>
                        <ul className="list-disc list-inside text-slate-300 text-[11px] space-y-0.5">
                          {(item.data_gaps || []).map((gap, gIdx) => (
                            <li key={gIdx}>{gap}</li>
                          ))}
                        </ul>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </section>

            {/* SECTION 6: Patient Zero & Remediation */}
            <section className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
              <div className="pb-3 border-b border-slate-800">
                <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
                  <Server className="w-5 h-5 text-rose-400" />
                  <span>6. Patient Zero & Remediation Playbook</span>
                </h2>
              </div>

              <div className="grid grid-cols-3 gap-4 text-xs font-mono">
                <div className="bg-slate-950/80 p-3 rounded-xl border border-slate-800">
                  <span className="text-slate-500 block text-[10px] uppercase">Patient Zero Host</span>
                  <span className="text-rose-400 font-bold">{patientZero?.patient_zero_host || "Pending"}</span>
                </div>
                <div className="bg-slate-950/80 p-3 rounded-xl border border-slate-800">
                  <span className="text-slate-500 block text-[10px] uppercase">Initial Access Vector</span>
                  <span className="text-amber-300 font-bold">{patientZero?.initial_access_vector || "Pending"}</span>
                </div>
                <div className="bg-slate-950/80 p-3 rounded-xl border border-slate-800">
                  <span className="text-slate-500 block text-[10px] uppercase">Initial Timestamp</span>
                  <span className="text-cyan-300 font-bold">{patientZero?.initial_timestamp_utc || "Pending"}</span>
                </div>
              </div>

              {/* Containment & Remediation */}
              <div className="grid grid-cols-2 gap-4 text-xs pt-2">
                <div className="p-4 bg-slate-950/80 rounded-xl border border-slate-800 space-y-2">
                  <h4 className="font-semibold text-amber-300 flex items-center gap-1.5">
                    <AlertTriangle className="w-4 h-4" /> Containment Actions
                  </h4>
                  <ul className="space-y-1.5 text-slate-300">
                    {(patientZero?.containment_actions || [
                      "Isolate impacted endpoint from enterprise network segment.",
                      "Revoke active Kerberos and SSH user credentials.",
                    ]).map((action, aIdx) => (
                      <li key={aIdx} className="flex items-start gap-2">
                        <span className="text-amber-400">▸</span>
                        <span>{action}</span>
                      </li>
                    ))}
                  </ul>
                </div>

                <div className="p-4 bg-slate-950/80 rounded-xl border border-slate-800 space-y-2">
                  <h4 className="font-semibold text-emerald-300 flex items-center gap-1.5">
                    <CheckCircle2 className="w-4 h-4" /> Remediation Steps
                  </h4>
                  <ul className="space-y-1.5 text-slate-300">
                    {(patientZero?.remediation_steps || [
                      "Acquire Volatility 3 memory snapshot for kernel rootkit triage.",
                      "Deploy updated Sigma detection rule to SIEM index.",
                    ]).map((step, sIdx) => (
                      <li key={sIdx} className="flex items-start gap-2">
                        <span className="text-emerald-400">✓</span>
                        <span>{step}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            </section>
          </div>
        )}
      </div>
    </div>
  );
};
