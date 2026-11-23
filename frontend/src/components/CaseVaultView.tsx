import React, { useState, useEffect } from "react";
import {
  ShieldCheck,
  Share2,
  Search,
  Building,
  User,
  Clock,
  Layers,
  HelpCircle,
  FileCheck,
  CheckCircle,
  ShieldAlert,
  ArrowRight,
  Database,
  ExternalLink,
  RefreshCw,
  FolderLock,
} from "lucide-react";
import { api } from "../services/api";
import { useInvestigation } from "../context/InvestigationContext";
import { CaseRecord, CitedClaim } from "../types";

export const CaseVaultView: React.FC = () => {
  const { loadCase, setActiveTab } = useInvestigation();
  const [vaultCases, setVaultCases] = useState<CaseRecord[]>([]);
  const [selectedCase, setSelectedCase] = useState<CaseRecord | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [error, setError] = useState<string | null>(null);

  const fetchVaultCases = async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await api.getVaultCases();
      setVaultCases(res);
      if (res.length > 0 && !selectedCase) {
        setSelectedCase(res[0]);
      }
    } catch (err: any) {
      setError(err.message || "Failed to load shared peer-review cases");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchVaultCases();
  }, []);

  const filteredCases = vaultCases.filter((c) => {
    if (!searchQuery.trim()) return true;
    const term = searchQuery.toLowerCase();
    return (
      c.case_id.toLowerCase().includes(term) ||
      c.case_name.toLowerCase().includes(term) ||
      c.organization_name.toLowerCase().includes(term) ||
      (c.investigation_goal && c.investigation_goal.toLowerCase().includes(term))
    );
  });

  const hypDraft = selectedCase?.serialized_state?.wizard_state?.hypothesisDraft;
  const recentCustody = selectedCase?.serialized_state?.wizard_state?.recentCustody || [];

  return (
    <div className="max-w-7xl mx-auto p-8 space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-gray-800">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center space-x-3">
            <FolderLock className="w-7 h-7 text-emerald-400" />
            <span>Forensic Case Vault & Peer Review</span>
          </h1>
          <p className="text-xs text-gray-400 mt-1 font-mono">
            Shared peer-review repository displaying verified cases with ACH competing hypotheses, cryptographically cited findings, and chain-of-custody ledgers.
          </p>
        </div>

        <button
          onClick={fetchVaultCases}
          className="px-3.5 py-1.5 bg-gray-800 hover:bg-gray-700 text-gray-300 font-mono text-xs rounded-lg border border-gray-700 flex items-center space-x-2 shrink-0"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Refresh Vault</span>
        </button>
      </div>

      {loading ? (
        <div className="py-24 text-center text-xs font-mono text-gray-500 flex items-center justify-center space-x-2">
          <RefreshCw className="w-4 h-4 animate-spin text-cyan-400" />
          <span>Loading published peer-review cases...</span>
        </div>
      ) : vaultCases.length === 0 ? (
        <div className="py-24 text-center font-mono space-y-3 bg-[#111827] border border-gray-800 rounded-2xl p-8">
          <Share2 className="w-12 h-12 text-gray-600 mx-auto" />
          <h3 className="text-base font-bold text-white">No Shared Cases in the Vault</h3>
          <p className="text-xs text-gray-400 max-w-md mx-auto">
            Investigations published via the "Share to Forensic Case Vault" toggle on reports or in the Case Manager will appear here for collaborative peer review.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start font-mono">
          {/* Left Column: Shared Cases List (4 cols) */}
          <div className="lg:col-span-4 bg-[#111827] border border-gray-800 rounded-2xl p-4 space-y-3">
            <div className="relative">
              <Search className="w-4 h-4 text-gray-400 absolute left-3 top-2.5" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search shared cases..."
                className="w-full bg-[#161f30] border border-gray-700 rounded-lg pl-9 pr-3 py-1.5 text-xs text-cyan-200 placeholder-gray-500 focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div className="space-y-2 max-h-[70vh] overflow-y-auto pr-1">
              {filteredCases.map((c) => {
                const isSelected = selectedCase?.case_id === c.case_id;
                return (
                  <div
                    key={c.case_id}
                    onClick={() => setSelectedCase(c)}
                    className={`p-3.5 rounded-xl border cursor-pointer transition-all ${
                      isSelected
                        ? "bg-emerald-950/40 border-emerald-600/80 shadow-md shadow-emerald-950/30"
                        : "bg-[#161f30] border-gray-800 hover:border-gray-700"
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-[11px] font-bold text-emerald-400">{c.case_id}</span>
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-950 border border-emerald-800 text-emerald-300">
                        Peer Review
                      </span>
                    </div>

                    <h4 className="text-xs font-bold text-white mt-1 line-clamp-1">{c.case_name}</h4>

                    <div className="flex items-center justify-between text-[10px] text-gray-400 mt-2">
                      <span className="flex items-center gap-1">
                        <Building className="w-3 h-3" />
                        <span>{c.organization_name}</span>
                      </span>
                      <span>{new Date(c.updated_at_utc).toLocaleDateString()}</span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Right Column: Case Dossier & Peer Review Details (8 cols) */}
          <div className="lg:col-span-8 bg-[#111827] border border-gray-800 rounded-2xl p-6 shadow-2xl space-y-6">
            {selectedCase ? (
              <>
                {/* Dossier Header */}
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-5 border-b border-gray-800">
                  <div>
                    <div className="flex items-center space-x-2">
                      <span className="text-xs text-cyan-400 font-bold">{selectedCase.case_id}</span>
                      <span className="text-gray-600">•</span>
                      <span className="text-xs text-gray-400">{selectedCase.organization_name}</span>
                    </div>
                    <h2 className="text-lg font-bold text-white mt-1">{selectedCase.case_name}</h2>
                    {selectedCase.investigation_goal && (
                      <p className="text-xs text-gray-300 mt-1">{selectedCase.investigation_goal}</p>
                    )}
                  </div>

                  <button
                    onClick={async () => {
                      await loadCase(selectedCase.case_id);
                      setActiveTab("canvas");
                    }}
                    className="px-4 py-2 bg-gradient-to-r from-cyan-600 to-sky-600 hover:from-cyan-500 hover:to-sky-500 text-white text-xs font-bold rounded-lg shadow-md flex items-center space-x-2 shrink-0"
                  >
                    <span>Open in Workflow Studio</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                </div>

                {/* ACH Dual Hypotheses (Threat vs. Benign Alternative) */}
                {hypDraft ? (
                  <div className="space-y-4">
                    <h3 className="text-xs font-bold uppercase tracking-wider text-gray-400 flex items-center gap-1.5">
                      <ShieldCheck className="w-4 h-4 text-cyan-400" />
                      <span>Analysis of Competing Hypotheses (ACH)</span>
                    </h3>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      {/* Threat Hypothesis Card */}
                      <div className="bg-gradient-to-b from-rose-950/40 to-slate-900 border border-rose-800/60 rounded-xl p-4 space-y-2">
                        <div className="flex items-center justify-between">
                          <span className="px-2 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-700 text-[10px] font-bold uppercase flex items-center gap-1">
                            <ShieldAlert className="w-3 h-3 text-rose-400" />
                            <span>Threat Hypothesis</span>
                          </span>
                          <span className="text-[10px] text-rose-400">
                            Confidence: {(hypDraft.confidence_score * 100).toFixed(0)}%
                          </span>
                        </div>
                        <p className="text-xs text-rose-100 leading-relaxed pt-1">
                          {hypDraft.threat_hypothesis}
                        </p>
                      </div>

                      {/* Benign Alternative Card */}
                      <div className="bg-gradient-to-b from-emerald-950/40 to-slate-900 border border-emerald-800/60 rounded-xl p-4 space-y-2">
                        <div className="flex items-center justify-between">
                          <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-700 text-[10px] font-bold uppercase flex items-center gap-1">
                            <CheckCircle className="w-3 h-3 text-emerald-400" />
                            <span>Benign Alternative</span>
                          </span>
                          <span className="text-[10px] text-emerald-400">Neutral Baseline</span>
                        </div>
                        <p className="text-xs text-emerald-100 leading-relaxed pt-1">
                          {hypDraft.benign_hypothesis}
                        </p>
                      </div>
                    </div>

                    {/* Verified Evidence Findings */}
                    {hypDraft.cited_findings && hypDraft.cited_findings.length > 0 && (
                      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 space-y-3">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center space-x-2 text-xs font-semibold text-gray-300">
                            <FileCheck className="w-4 h-4 text-emerald-400" />
                            <span>Verified Evidence Citations (RFC 3227 & ISO 27037)</span>
                          </div>
                          <span className="text-[10px] text-emerald-400 bg-emerald-950 px-2 py-0.5 rounded border border-emerald-800">
                            Cryptographically Verified
                          </span>
                        </div>

                        <div className="overflow-x-auto">
                          <table className="w-full text-left text-xs">
                            <thead>
                              <tr className="border-b border-gray-800 text-gray-400">
                                <th className="pb-2">Finding ID</th>
                                <th className="pb-2">Claim Type</th>
                                <th className="pb-2">Observed Claim Statement</th>
                                <th className="pb-2">Source Artifact Hash</th>
                              </tr>
                            </thead>
                            <tbody className="divide-y divide-gray-800/60 text-gray-300">
                              {hypDraft.cited_findings.map((claim: CitedClaim, idx: number) => (
                                <tr key={claim.claim_id || idx} className="hover:bg-gray-800/40">
                                  <td className="py-2.5 text-cyan-400 font-semibold">
                                    {claim.citing_finding_ids?.join(", ") || "N/A"}
                                  </td>
                                  <td className="py-2.5">
                                    <span className="px-1.5 py-0.5 rounded bg-cyan-950 border border-cyan-800 text-cyan-300 text-[10px]">
                                      {claim.claim_type}
                                    </span>
                                  </td>
                                  <td className="py-2.5 text-gray-200">{claim.statement}</td>
                                  <td className="py-2.5 text-gray-400">
                                    {claim.source_artifact_hashes && claim.source_artifact_hashes.length > 0
                                      ? `${claim.source_artifact_hashes[0].substring(0, 16)}...`
                                      : "N/A"}
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="p-4 bg-slate-900/60 border border-gray-800 rounded-xl text-xs text-gray-400 text-center">
                    No ACH hypothesis formulation saved for this case yet.
                  </div>
                )}

                {/* Chain of Custody & Lead Details */}
                <div className="p-4 bg-slate-900/60 border border-gray-800 rounded-xl flex items-center justify-between text-xs">
                  <div className="flex items-center space-x-2">
                    <Database className="w-4 h-4 text-cyan-400" />
                    <span>Cryptographic Custody:</span>
                    <span className="text-emerald-400 font-semibold">Tamper-Proof & Chained</span>
                  </div>

                  <div className="flex items-center space-x-2 text-gray-400">
                    <User className="w-3.5 h-3.5" />
                    <span>Lead: {selectedCase.lead_analyst}</span>
                  </div>
                </div>
              </>
            ) : (
              <div className="py-24 text-center text-xs text-gray-500">
                Select a shared case from the left panel to inspect the peer review dossier.
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
