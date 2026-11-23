import React, { useState } from "react";
import {
  ShieldAlert,
  ShieldCheck,
  XCircle,
  Clock,
  User,
  Folder,
  Target,
  Hash,
  Terminal,
  AlertTriangle,
  Info,
} from "lucide-react";
import { ApprovalRequest, ActionRiskLevel } from "../types";
import { api } from "../services/api";
import { useAuth } from "../context/AuthContext";

interface ApprovalReviewModalProps {
  isOpen: boolean;
  request: ApprovalRequest | null;
  onClose: () => void;
  onDecisionComplete?: (updated: ApprovalRequest) => void;
}

export const ApprovalReviewModal: React.FC<ApprovalReviewModalProps> = ({
  isOpen,
  request,
  onClose,
  onDecisionComplete,
}) => {
  const { user } = useAuth();
  const [decisionReason, setDecisionReason] = useState<string>("");
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  if (!isOpen || !request) return null;

  const isSelfApproval =
    Boolean(user?.username) &&
    user?.username.toLowerCase() === request.requesting_investigator.toLowerCase();

  const isAuditor = user?.role === "auditor";
  const canDecide = !isAuditor && !isSelfApproval && request.status === "pending";

  const getRiskBadge = (level: ActionRiskLevel) => {
    switch (level) {
      case "critical":
        return "bg-rose-950/80 text-rose-300 border-rose-700/80";
      case "high":
        return "bg-orange-950/80 text-orange-300 border-orange-700/80";
      case "medium":
        return "bg-amber-950/80 text-amber-300 border-amber-700/80";
      case "low":
      default:
        return "bg-cyan-950/80 text-cyan-300 border-cyan-700/80";
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case "approved":
        return "bg-emerald-950/80 text-emerald-300 border-emerald-700/80";
      case "rejected":
        return "bg-rose-950/80 text-rose-300 border-rose-700/80";
      case "consumed":
        return "bg-purple-950/80 text-purple-300 border-purple-700/80";
      case "expired":
        return "bg-slate-800 text-slate-400 border-slate-700";
      case "pending":
      default:
        return "bg-amber-950/80 text-amber-300 border-amber-700/80";
    }
  };

  const handleApprove = async () => {
    setIsSubmitting(true);
    setErrorMessage(null);
    try {
      if (request.approval_id.startsWith("gate-")) {
        if (onDecisionComplete) {
          onDecisionComplete(request);
        }
        onClose();
        return;
      }
      const updated = await api.approveRequest(
        request.approval_id,
        decisionReason.trim() || `Approved by ${user?.username || "investigator"}`
      );
      if (onDecisionComplete) {
        onDecisionComplete(updated);
      }
      onClose();
    } catch (err: any) {
      setErrorMessage(err.message || "Failed to approve operation");
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleReject = async () => {
    if (!decisionReason.trim()) {
      setErrorMessage("A rejection reason is mandatory for audit accountability.");
      return;
    }
    setIsSubmitting(true);
    setErrorMessage(null);
    try {
      if (!request.approval_id.startsWith("gate-")) {
        const updated = await api.rejectRequest(request.approval_id, decisionReason.trim());
        if (onDecisionComplete) {
          onDecisionComplete(updated);
        }
      }
      onClose();
    } catch (err: any) {
      setErrorMessage(err.message || "Failed to reject operation");
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-slate-900 border border-slate-700 rounded-2xl w-full max-w-2xl shadow-2xl p-6 text-slate-200 space-y-5 animate-in fade-in zoom-in-95 duration-150 max-h-[90vh] overflow-y-auto">
        {/* Header */}
        <div className="flex items-start justify-between pb-3 border-b border-slate-800">
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-rose-950/60 border border-rose-800/60 rounded-xl text-rose-400">
              <ShieldAlert className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="font-semibold text-lg text-white">Action Authorization Request</h3>
                <span
                  className={`px-2 py-0.5 text-[10px] font-mono uppercase tracking-wider rounded-full border ${getRiskBadge(
                    request.risk_level
                  )}`}
                >
                  {request.risk_level} Risk
                </span>
                <span
                  className={`px-2 py-0.5 text-[10px] font-mono uppercase tracking-wider rounded-full border ${getStatusBadge(
                    request.status
                  )}`}
                >
                  {request.status}
                </span>
              </div>
              <p className="text-xs text-slate-400 font-mono mt-0.5">
                Approval ID: <span className="text-cyan-400">{request.approval_id}</span>
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-slate-200 text-lg font-bold p-1"
          >
            &times;
          </button>
        </div>

        {/* Warning Banners */}
        {isSelfApproval && (
          <div className="flex items-start gap-2.5 p-3 rounded-lg bg-amber-950/50 border border-amber-800/80 text-amber-200 text-xs">
            <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
            <span>
              <strong>Dual-Control Enforcement:</strong> You are the requesting investigator (
              <code>{request.requesting_investigator}</code>). Under AGENTS.md safety principles, an
              investigator cannot approve their own sensitive operations. Another authorized investigator must review this.
            </span>
          </div>
        )}

        {isAuditor && (
          <div className="flex items-start gap-2.5 p-3 rounded-lg bg-slate-800/80 border border-slate-700 text-slate-300 text-xs">
            <Info className="w-4 h-4 text-slate-400 shrink-0 mt-0.5" />
            <span>
              <strong>Read-Only Auditor Mode:</strong> You are signed in as an auditor and cannot execute approval decisions.
            </span>
          </div>
        )}

        {errorMessage && (
          <div className="p-3 rounded-lg bg-rose-950/70 border border-rose-800 text-rose-200 text-xs font-mono">
            {errorMessage}
          </div>
        )}

        {/* Operation Details Grid */}
        <div className="grid grid-cols-2 gap-3 text-xs">
          <div className="bg-slate-950/70 p-3 rounded-lg border border-slate-800/80 space-y-1">
            <div className="flex items-center gap-1.5 text-slate-400 font-medium">
              <Folder className="w-3.5 h-3.5 text-cyan-400" />
              <span>Case ID</span>
            </div>
            <p className="font-mono text-slate-200 font-semibold">{request.case_id}</p>
          </div>

          <div className="bg-slate-950/70 p-3 rounded-lg border border-slate-800/80 space-y-1">
            <div className="flex items-center gap-1.5 text-slate-400 font-medium">
              <User className="w-3.5 h-3.5 text-cyan-400" />
              <span>Requesting Investigator</span>
            </div>
            <p className="font-mono text-slate-200 font-semibold">{request.requesting_investigator}</p>
          </div>

          <div className="bg-slate-950/70 p-3 rounded-lg border border-slate-800/80 space-y-1">
            <div className="flex items-center gap-1.5 text-slate-400 font-medium">
              <Terminal className="w-3.5 h-3.5 text-cyan-400" />
              <span>Action / Capability</span>
            </div>
            <p className="font-mono text-cyan-300 font-semibold">
              {request.action_type} <span className="text-slate-500">({request.capability_id})</span>
            </p>
          </div>

          <div className="bg-slate-950/70 p-3 rounded-lg border border-slate-800/80 space-y-1">
            <div className="flex items-center gap-1.5 text-slate-400 font-medium">
              <Target className="w-3.5 h-3.5 text-cyan-400" />
              <span>Target Asset / Endpoint</span>
            </div>
            <p className="font-mono text-slate-200 font-semibold">{request.target}</p>
          </div>

          <div className="bg-slate-950/70 p-3 rounded-lg border border-slate-800/80 space-y-1">
            <div className="flex items-center gap-1.5 text-slate-400 font-medium">
              <Clock className="w-3.5 h-3.5 text-cyan-400" />
              <span>Expires At (UTC)</span>
            </div>
            <p className="font-mono text-slate-300 text-[11px]">{request.expires_at_utc}</p>
          </div>

          <div className="bg-slate-950/70 p-3 rounded-lg border border-slate-800/80 space-y-1">
            <div className="flex items-center gap-1.5 text-slate-400 font-medium">
              <Hash className="w-3.5 h-3.5 text-cyan-400" />
              <span>Parameter Digest (SHA-256)</span>
            </div>
            <p className="font-mono text-slate-400 text-[10px] truncate" title={request.parameter_digest}>
              {request.parameter_digest}
            </p>
          </div>
        </div>

        {/* Evidence Scope */}
        {request.evidence_scope && request.evidence_scope.length > 0 && (
          <div className="bg-slate-950/50 p-3 rounded-lg border border-slate-800/80 text-xs space-y-1.5">
            <span className="text-slate-400 font-medium">Authorized Evidence Scope:</span>
            <div className="flex flex-wrap gap-1.5">
              {request.evidence_scope.map((scope, idx) => (
                <span
                  key={idx}
                  className="px-2 py-0.5 bg-slate-800 text-cyan-300 font-mono text-[10px] rounded border border-slate-700"
                >
                  {scope}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Justification / Reason */}
        <div className="bg-slate-950/50 p-3 rounded-lg border border-slate-800/80 text-xs space-y-1">
          <span className="text-slate-400 font-medium">Investigative Justification:</span>
          <p className="text-slate-200 leading-relaxed font-sans">
            {request.justification || "No explicit justification provided."}
          </p>
        </div>

        {/* Bound Parameters Viewer */}
        <div className="space-y-1.5">
          <div className="flex items-center justify-between text-xs text-slate-400 font-medium">
            <span>Cryptographically Bound Parameters</span>
            <span className="text-[10px] font-mono text-slate-500">
              Immutably hashed: Any parameter change invalidates approval
            </span>
          </div>
          <pre className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-[11px] font-mono text-cyan-300 overflow-x-auto max-h-36 scrollbar-thin">
            {JSON.stringify(request.parameters, null, 2)}
          </pre>
        </div>

        {/* Decision Reason Input & Action Buttons */}
        {request.status === "pending" && (
          <div className="space-y-3 pt-2 border-t border-slate-800">
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Decision Audit Note / Reason {canDecide && <span className="text-rose-400">*</span>}
              </label>
              <input
                type="text"
                placeholder={
                  canDecide
                    ? "Enter reason or sign-off comment for the custody ledger..."
                    : "Decision disabled"
                }
                value={decisionReason}
                onChange={(e) => setDecisionReason(e.target.value)}
                disabled={!canDecide || isSubmitting}
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div className="flex items-center justify-end gap-3">
              <button
                type="button"
                onClick={onClose}
                className="px-3.5 py-1.5 rounded-lg border border-slate-700 hover:bg-slate-800 text-xs font-medium text-slate-300 transition-colors"
                disabled={isSubmitting}
              >
                Close
              </button>
              <button
                type="button"
                onClick={handleReject}
                disabled={!canDecide || isSubmitting}
                className="flex items-center gap-1.5 px-4 py-1.5 rounded-lg bg-rose-950/80 hover:bg-rose-900 border border-rose-800 text-xs font-semibold text-rose-200 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <XCircle className="w-3.5 h-3.5" />
                Reject Action
              </button>
              <button
                type="button"
                onClick={handleApprove}
                disabled={!canDecide || isSubmitting}
                className="flex items-center gap-1.5 px-4 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-xs font-semibold text-white shadow-lg shadow-emerald-900/40 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <ShieldCheck className="w-3.5 h-3.5" />
                {isSubmitting ? "Signing Token..." : "Approve & Sign Token"}
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
