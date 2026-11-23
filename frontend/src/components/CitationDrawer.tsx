import React, { useState } from "react";
import {
  X,
  ShieldCheck,
  Copy,
  Check,
  ThumbsUp,
  ShieldAlert,
  Edit3,
  ExternalLink,
  Hash,
  Clock,
  Terminal,
  User,
  Server,
  Layers,
} from "lucide-react";
import { useForensicStore } from "../store/useForensicStore";
import { api } from "../services/api";

export const CitationDrawer: React.FC = () => {
  const { isCitationDrawerOpen, closeCitationDrawer, selectedFinding, currentCaseId } =
    useForensicStore();
  const [copiedField, setCopiedField] = useState<string | null>(null);
  const [feedbackSuccess, setFeedbackSuccess] = useState<string | null>(null);

  if (!isCitationDrawerOpen || !selectedFinding) return null;

  const copyToClipboard = (text: string, fieldName: string) => {
    navigator.clipboard.writeText(text);
    setCopiedField(fieldName);
    setTimeout(() => setCopiedField(null), 2000);
  };

  const handleFeedback = async (
    type: "true_positive" | "false_positive_benign_baseline" | "query_correction",
    scope: "this_case_only" | "organization_baseline" = "this_case_only"
  ) => {
    try {
      await api.submitFeedback({
        case_id: currentCaseId,
        finding_id: selectedFinding.finding_id,
        feedback_type: type,
        scope,
        entity_pattern: selectedFinding.process_name || selectedFinding.user || undefined,
        artifact_type: selectedFinding.artifact_type,
        analyst_note: `Analyst micro-feedback from CitationDrawer on ${selectedFinding.summary}`,
      });
      setFeedbackSuccess(`Feedback recorded: ${type}`);
      setTimeout(() => setFeedbackSuccess(null), 3000);
    } catch (err: any) {
      alert(`Feedback submission failed: ${err.message}`);
    }
  };

  return (
    <div className="fixed inset-0 bg-slate-950/70 backdrop-blur-sm z-50 flex justify-end animate-in fade-in duration-200">
      <div className="w-full max-w-xl bg-slate-900 border-l border-slate-800 h-full shadow-2xl flex flex-col animate-in slide-in-from-right duration-300">
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-800 bg-slate-950/70 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-cyan-950/70 border border-cyan-500/50 rounded-lg text-cyan-400">
              <Hash className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="font-bold text-sm text-slate-100">Cryptographic Citation Inspector</h3>
                <span className="flex items-center gap-1 text-[10px] text-emerald-400 bg-emerald-950/60 border border-emerald-700/50 px-2 py-0.5 rounded-full font-mono">
                  <ShieldCheck className="w-3 h-3" /> VERIFIED CUSTODY
                </span>
              </div>
              <p className="text-[11px] text-slate-400 font-mono">
                Immutable Provenance Link (RFC 3227 & NIST SP 800-86)
              </p>
            </div>
          </div>
          <button
            onClick={closeCitationDrawer}
            className="p-1 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Feedback Alert */}
        {feedbackSuccess && (
          <div className="mx-6 mt-4 p-3 bg-emerald-950/80 border border-emerald-700 rounded-lg text-xs text-emerald-300 flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 shrink-0" />
            <span>{feedbackSuccess}</span>
          </div>
        )}

        {/* Drawer Body */}
        <div className="p-6 overflow-y-auto flex-1 space-y-5 text-xs text-slate-300">
          {/* Finding Summary Banner */}
          <div className="p-4 bg-slate-950/80 border border-slate-800 rounded-xl space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-mono uppercase tracking-wider text-slate-500">
                Finding ID
              </span>
              <button
                onClick={() => copyToClipboard(selectedFinding.finding_id, "finding_id")}
                className="flex items-center gap-1 text-[11px] text-cyan-400 hover:text-cyan-300 font-mono"
              >
                {copiedField === "finding_id" ? (
                  <Check className="w-3 h-3 text-emerald-400" />
                ) : (
                  <Copy className="w-3 h-3" />
                )}
                <span>{selectedFinding.finding_id}</span>
              </button>
            </div>
            <p className="text-sm font-semibold text-slate-100 leading-snug">
              {selectedFinding.summary}
            </p>
            <div className="flex items-center gap-2 pt-1">
              <span
                className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded ${
                  selectedFinding.severity === "critical"
                    ? "bg-rose-950 text-rose-300 border border-rose-800"
                    : selectedFinding.severity === "high"
                    ? "bg-orange-950 text-orange-300 border border-orange-800"
                    : "bg-blue-950 text-blue-300 border border-blue-800"
                }`}
              >
                {selectedFinding.severity}
              </span>
              <span className="text-[11px] text-slate-400 font-mono">
                Category: {selectedFinding.category}
              </span>
            </div>
          </div>

          {/* Cryptographic SHA-256 Hash Card */}
          <div className="p-4 bg-slate-950/60 border border-slate-800 rounded-xl space-y-3 font-mono text-[11px]">
            <div className="flex items-center justify-between text-slate-400">
              <span className="font-sans font-semibold flex items-center gap-1.5 text-slate-200">
                <ShieldCheck className="w-4 h-4 text-emerald-400" /> Source Evidence Hash
              </span>
              <button
                onClick={() =>
                  copyToClipboard(selectedFinding.source_artifact_hash, "hash")
                }
                className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
              >
                {copiedField === "hash" ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                <span>Copy SHA-256</span>
              </button>
            </div>
            <div className="p-2.5 bg-slate-900 rounded-lg border border-slate-800/80 break-all text-emerald-400">
              {selectedFinding.source_artifact_hash}
            </div>
            <div className="text-[10px] text-slate-500 space-y-1">
              <div className="flex justify-between">
                <span>Artifact ID:</span>
                <span className="text-slate-400">{selectedFinding.source_artifact_id}</span>
              </div>
              <div className="flex justify-between">
                <span>Generating Tool:</span>
                <span className="text-amber-400">{selectedFinding.tool_id}</span>
              </div>
            </div>
          </div>

          {/* Forensic Entity Attributes */}
          <div className="grid grid-cols-2 gap-3 text-xs">
            <div className="p-3 bg-slate-950/60 border border-slate-800 rounded-xl space-y-1">
              <span className="text-slate-500 flex items-center gap-1">
                <Clock className="w-3.5 h-3.5" /> Timestamp (UTC)
              </span>
              <p className="font-mono text-cyan-300 font-medium">
                {selectedFinding.timestamp_utc || "N/A"}
              </p>
            </div>
            <div className="p-3 bg-slate-950/60 border border-slate-800 rounded-xl space-y-1">
              <span className="text-slate-500 flex items-center gap-1">
                <Server className="w-3.5 h-3.5" /> Impacted Host
              </span>
              <p className="font-mono text-slate-200 font-medium">
                {selectedFinding.host || "N/A"}
              </p>
            </div>
            <div className="p-3 bg-slate-950/60 border border-slate-800 rounded-xl space-y-1">
              <span className="text-slate-500 flex items-center gap-1">
                <User className="w-3.5 h-3.5" /> Target User
              </span>
              <p className="font-mono text-amber-300 font-medium">
                {selectedFinding.user || "N/A"}
              </p>
            </div>
            <div className="p-3 bg-slate-950/60 border border-slate-800 rounded-xl space-y-1">
              <span className="text-slate-500 flex items-center gap-1">
                <Terminal className="w-3.5 h-3.5" /> Process
              </span>
              <p className="font-mono text-emerald-400 font-medium truncate">
                {selectedFinding.process_name || "N/A"}
              </p>
            </div>
          </div>

          {/* Command Line */}
          {selectedFinding.command_line && (
            <div className="p-3 bg-slate-950/80 border border-slate-800 rounded-xl space-y-1.5">
              <span className="text-slate-400 font-semibold block">Full Command Line</span>
              <pre className="p-2.5 bg-slate-900 border border-slate-800 rounded-lg font-mono text-[11px] text-amber-300 whitespace-pre-wrap break-all">
                {selectedFinding.command_line}
              </pre>
            </div>
          )}

          {/* Raw Projected Data */}
          <div className="p-3 bg-slate-950/80 border border-slate-800 rounded-xl space-y-2">
            <span className="text-slate-400 font-semibold block">Projected Schema Fields</span>
            <pre className="p-2.5 bg-slate-900 border border-slate-800 rounded-lg font-mono text-[10px] text-slate-300 max-h-48 overflow-y-auto">
              {JSON.stringify(selectedFinding.projected_data, null, 2)}
            </pre>
          </div>

          {/* v2.0 Micro-Feedback Loop Controls */}
          <div className="p-4 bg-slate-950/90 border border-cyan-900/40 rounded-xl space-y-3">
            <div className="flex items-center gap-2 text-cyan-400 font-semibold text-xs">
              <Layers className="w-4 h-4" />
              <span>Analyst Micro-Feedback & Baseline Engine</span>
            </div>
            <p className="text-[11px] text-slate-400">
              Train the local Bayesian baseline store to suppress known enterprise noise or elevate verified malicious patterns.
            </p>
            <div className="grid grid-cols-2 gap-2 pt-1">
              <button
                onClick={() => handleFeedback("true_positive")}
                className="flex items-center justify-center gap-1.5 p-2 bg-emerald-950/80 hover:bg-emerald-900 border border-emerald-700/60 rounded-lg text-emerald-300 font-medium transition-colors"
              >
                <ThumbsUp className="w-3.5 h-3.5" />
                <span>Confirm True Positive</span>
              </button>
              <button
                onClick={() =>
                  handleFeedback("false_positive_benign_baseline", "organization_baseline")
                }
                className="flex items-center justify-center gap-1.5 p-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg text-slate-200 font-medium transition-colors"
              >
                <ShieldAlert className="w-3.5 h-3.5 text-amber-400" />
                <span>Mark Benign Baseline</span>
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
