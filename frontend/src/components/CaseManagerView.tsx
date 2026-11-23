import React, { useState, useEffect } from "react";
import {
  Briefcase,
  Search,
  Plus,
  FolderOpen,
  Share2,
  Trash2,
  Clock,
  Building,
  CheckCircle,
  AlertCircle,
  Filter,
  RefreshCw,
  ArrowRight,
  ShieldCheck,
  Radio,
  FileText,
  User,
  X,
} from "lucide-react";
import { api } from "../services/api";
import { useInvestigation } from "../context/InvestigationContext";
import { CaseRecord, CaseStatus } from "../types";

export const CaseManagerView: React.FC = () => {
  const { caseId, loadCase, setActiveTab } = useInvestigation();
  const [cases, setCases] = useState<CaseRecord[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [statusFilter, setStatusFilter] = useState<string>("ALL");
  const [error, setError] = useState<string | null>(null);

  // New Case Modal States
  const [isNewCaseModalOpen, setIsNewCaseModalOpen] = useState<boolean>(false);
  const [newCaseId, setNewCaseId] = useState<string>(`CASE-${new Date().getFullYear()}-${Math.random().toString(36).substring(2, 7).toUpperCase()}`);
  const [newCaseName, setNewCaseName] = useState<string>("");
  const [newOrgName, setNewOrgName] = useState<string>("Acme Financial Corp");
  const [newGoal, setNewGoal] = useState<string>("Investigate potential unauthorized access, credential dumping, and persistence.");
  const [isCreating, setIsCreating] = useState<boolean>(false);

  const fetchCases = async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await api.listCases(searchQuery, statusFilter);
      setCases(res);
    } catch (err: any) {
      setError(err.message || "Failed to load cases");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchCases();
  }, [searchQuery, statusFilter]);

  const handleCreateCase = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newCaseId.trim() || !newCaseName.trim()) return;

    try {
      setIsCreating(true);
      const created = await api.createOrUpdateCase({
        case_id: newCaseId.trim(),
        case_name: newCaseName.trim(),
        organization_name: newOrgName.trim(),
        investigation_goal: newGoal.trim(),
        status: "OPEN",
      });
      setIsNewCaseModalOpen(false);
      await loadCase(created.case_id);
      setActiveTab("wizard");
    } catch (err: any) {
      setError(`Failed to create case: ${err.message || err}`);
    } finally {
      setIsCreating(false);
    }
  };

  const handleStatusChange = async (targetCaseId: string, newStatus: CaseStatus) => {
    try {
      await api.updateCase(targetCaseId, { status: newStatus });
      setCases((prev) =>
        prev.map((c) => (c.case_id === targetCaseId ? { ...c, status: newStatus } : c))
      );
    } catch (err: any) {
      setError(`Failed to update status: ${err.message || err}`);
    }
  };

  const handleToggleVault = async (targetCaseId: string, currentVal: boolean) => {
    try {
      const res = await api.shareCaseToVault(targetCaseId, !currentVal);
      setCases((prev) =>
        prev.map((c) =>
          c.case_id === targetCaseId ? { ...c, is_shared_to_vault: res.is_shared_to_vault } : c
        )
      );
    } catch (err: any) {
      setError(`Failed to update vault share: ${err.message || err}`);
    }
  };

  const handleDeleteCase = async (targetCaseId: string) => {
    if (!confirm(`Are you sure you want to delete case '${targetCaseId}'?`)) return;
    try {
      await api.deleteCase(targetCaseId);
      setCases((prev) => prev.filter((c) => c.case_id !== targetCaseId));
    } catch (err: any) {
      setError(`Failed to delete case: ${err.message || err}`);
    }
  };

  const handleOpenCase = async (targetCaseId: string) => {
    await loadCase(targetCaseId);
    setActiveTab("wizard");
  };

  // Metrics
  const totalCount = cases.length;
  const openCount = cases.filter((c) => c.status === "OPEN").length;
  const inReviewCount = cases.filter((c) => c.status === "IN_REVIEW").length;
  const vaultSharedCount = cases.filter((c) => c.is_shared_to_vault).length;

  return (
    <div className="max-w-7xl mx-auto p-8 space-y-8">
      {/* Header & New Case Action */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-gray-800">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center space-x-3">
            <Briefcase className="w-7 h-7 text-cyan-400" />
            <span>Forensic Case Manager & Registry</span>
          </h1>
          <p className="text-xs text-gray-400 mt-1 font-mono">
            SQLite-backed persistent case lifecycle, organization governance, and peer-review vault publishing.
          </p>
        </div>

        <button
          onClick={() => {
            setNewCaseId(`CASE-${new Date().getFullYear()}-${Math.random().toString(36).substring(2, 7).toUpperCase()}`);
            setIsNewCaseModalOpen(true);
          }}
          className="px-5 py-2.5 bg-gradient-to-r from-cyan-500 to-sky-600 hover:from-cyan-400 hover:to-sky-500 text-white font-mono text-xs font-bold rounded-xl shadow-lg shadow-cyan-500/20 flex items-center space-x-2 shrink-0 transition-all"
        >
          <Plus className="w-4 h-4" />
          <span>New Investigation Case</span>
        </button>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 font-mono">
        <div className="bg-[#111827] border border-gray-800 rounded-xl p-4 flex items-center justify-between">
          <div>
            <span className="text-[11px] text-gray-400 uppercase">Total Cases</span>
            <div className="text-2xl font-bold text-white mt-1">{totalCount}</div>
          </div>
          <FolderOpen className="w-8 h-8 text-cyan-500/40" />
        </div>

        <div className="bg-[#111827] border border-gray-800 rounded-xl p-4 flex items-center justify-between">
          <div>
            <span className="text-[11px] text-gray-400 uppercase">Active / Open</span>
            <div className="text-2xl font-bold text-cyan-400 mt-1">{openCount}</div>
          </div>
          <Radio className="w-8 h-8 text-cyan-500/40 animate-pulse" />
        </div>

        <div className="bg-[#111827] border border-gray-800 rounded-xl p-4 flex items-center justify-between">
          <div>
            <span className="text-[11px] text-gray-400 uppercase">In Review</span>
            <div className="text-2xl font-bold text-amber-400 mt-1">{inReviewCount}</div>
          </div>
          <Clock className="w-8 h-8 text-amber-500/40" />
        </div>

        <div className="bg-[#111827] border border-gray-800 rounded-xl p-4 flex items-center justify-between">
          <div>
            <span className="text-[11px] text-gray-400 uppercase">Shared to Vault</span>
            <div className="text-2xl font-bold text-emerald-400 mt-1">{vaultSharedCount}</div>
          </div>
          <Share2 className="w-8 h-8 text-emerald-500/40" />
        </div>
      </div>

      {/* Search & Filters */}
      <div className="bg-[#111827] border border-gray-800 rounded-xl p-4 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="relative flex-1">
          <Search className="w-4 h-4 text-gray-400 absolute left-3.5 top-3" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search by case ID, title, organization, or goal..."
            className="w-full bg-[#161f30] border border-gray-700 rounded-lg pl-10 pr-4 py-2 text-xs font-mono text-cyan-200 placeholder-gray-500 focus:outline-none focus:border-cyan-500"
          />
        </div>

        {/* Status Filter Buttons */}
        <div className="flex items-center space-x-1.5 font-mono text-xs">
          <Filter className="w-3.5 h-3.5 text-gray-400 mr-1" />
          {["ALL", "OPEN", "IN_REVIEW", "COMPLETED"].map((st) => (
            <button
              key={st}
              onClick={() => setStatusFilter(st)}
              className={`px-3 py-1.5 rounded-lg transition-colors ${
                statusFilter === st
                  ? "bg-cyan-950 border border-cyan-700 text-cyan-300 font-bold"
                  : "bg-gray-800/80 hover:bg-gray-700 text-gray-400"
              }`}
            >
              {st}
            </button>
          ))}
        </div>
      </div>

      {error && (
        <div className="p-3 bg-rose-950/60 border border-rose-800 rounded-xl text-rose-300 text-xs font-mono flex items-center space-x-2">
          <AlertCircle className="w-4 h-4 shrink-0 text-rose-400" />
          <span>{error}</span>
        </div>
      )}

      {/* Case List Table */}
      <div className="bg-[#111827] border border-gray-800 rounded-2xl overflow-hidden shadow-2xl">
        {loading ? (
          <div className="py-16 text-center text-xs font-mono text-gray-500 flex items-center justify-center space-x-2">
            <RefreshCw className="w-4 h-4 animate-spin text-cyan-400" />
            <span>Loading registered cases...</span>
          </div>
        ) : cases.length === 0 ? (
          <div className="py-16 text-center text-xs font-mono text-gray-500 space-y-2">
            <p>No investigation cases found matching filter criteria.</p>
            <button
              onClick={() => setIsNewCaseModalOpen(true)}
              className="px-4 py-2 bg-gray-800 hover:bg-gray-700 text-cyan-400 rounded-lg text-xs"
            >
              Create your first case
            </button>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="border-b border-gray-800 bg-gray-900/60 text-gray-400">
                  <th className="py-3 px-5">Case Identifier</th>
                  <th className="py-3 px-4">Organization</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Vault Peer Review</th>
                  <th className="py-3 px-4">Lead Analyst</th>
                  <th className="py-3 px-4">Last Updated</th>
                  <th className="py-3 px-5 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800/60 text-gray-300">
                {cases.map((c) => {
                  const isCurrent = c.case_id === caseId;
                  return (
                    <tr
                      key={c.case_id}
                      className={`hover:bg-gray-800/40 transition-colors ${
                        isCurrent ? "bg-cyan-950/20" : ""
                      }`}
                    >
                      <td className="py-3.5 px-5">
                        <div className="flex flex-col">
                          <span className="font-bold text-white flex items-center gap-2">
                            <span>{c.case_name}</span>
                            {isCurrent && (
                              <span className="px-1.5 py-0.2 rounded bg-cyan-900 border border-cyan-700 text-cyan-300 text-[10px]">
                                Active
                              </span>
                            )}
                          </span>
                          <span className="text-[11px] text-cyan-400 mt-0.5">{c.case_id}</span>
                          {c.investigation_goal && (
                            <span className="text-[11px] text-gray-400 mt-1 line-clamp-1">
                              {c.investigation_goal}
                            </span>
                          )}
                        </div>
                      </td>

                      <td className="py-3.5 px-4 text-gray-300">
                        <div className="flex items-center space-x-1.5">
                          <Building className="w-3.5 h-3.5 text-gray-500" />
                          <span>{c.organization_name}</span>
                        </div>
                      </td>

                      <td className="py-3.5 px-4">
                        <select
                          value={c.status}
                          onChange={(e) => handleStatusChange(c.case_id, e.target.value as CaseStatus)}
                          className={`px-2 py-1 rounded text-[11px] font-mono border focus:outline-none cursor-pointer ${
                            c.status === "COMPLETED"
                              ? "bg-emerald-950/80 border-emerald-700 text-emerald-300"
                              : c.status === "IN_REVIEW"
                              ? "bg-amber-950/80 border-amber-700 text-amber-300"
                              : "bg-cyan-950/80 border-cyan-700 text-cyan-300"
                          }`}
                        >
                          <option value="OPEN">OPEN</option>
                          <option value="IN_REVIEW">IN_REVIEW</option>
                          <option value="COMPLETED">COMPLETED</option>
                        </select>
                      </td>

                      <td className="py-3.5 px-4">
                        <button
                          type="button"
                          onClick={() => handleToggleVault(c.case_id, c.is_shared_to_vault)}
                          className={`flex items-center space-x-1.5 px-2.5 py-1 rounded text-[11px] border transition-colors ${
                            c.is_shared_to_vault
                              ? "bg-emerald-950 border-emerald-700 text-emerald-300"
                              : "bg-gray-800 border-gray-700 text-gray-400 hover:text-gray-200"
                          }`}
                        >
                          <Share2 className="w-3 h-3" />
                          <span>{c.is_shared_to_vault ? "Published" : "Private"}</span>
                        </button>
                      </td>

                      <td className="py-3.5 px-4 text-gray-400 text-[11px]">
                        <div className="flex items-center space-x-1">
                          <User className="w-3 h-3 text-gray-500" />
                          <span>{c.lead_analyst}</span>
                        </div>
                      </td>

                      <td className="py-3.5 px-4 text-gray-400 text-[11px]">
                        {new Date(c.updated_at_utc).toLocaleString()}
                      </td>

                      <td className="py-3.5 px-5 text-right">
                        <div className="flex items-center justify-end space-x-2">
                          <button
                            onClick={() => handleOpenCase(c.case_id)}
                            className="px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-xs font-semibold flex items-center space-x-1 shadow-md shadow-cyan-900/30 transition-all"
                          >
                            <span>Open</span>
                            <ArrowRight className="w-3.5 h-3.5" />
                          </button>

                          <button
                            onClick={() => handleDeleteCase(c.case_id)}
                            title="Delete case"
                            className="p-1.5 text-gray-400 hover:text-rose-400 hover:bg-rose-950/40 rounded-lg transition-colors"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Create New Case Modal */}
      {isNewCaseModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#111827] border border-cyan-800/80 rounded-2xl w-full max-w-xl shadow-2xl overflow-hidden font-mono">
            <div className="flex items-center justify-between px-6 py-4 border-b border-gray-800 bg-gray-900/80">
              <div className="flex items-center space-x-2">
                <Briefcase className="w-5 h-5 text-cyan-400" />
                <h3 className="text-sm font-bold text-white">Create New Forensic Investigation Case</h3>
              </div>
              <button
                type="button"
                onClick={() => setIsNewCaseModalOpen(false)}
                className="text-gray-400 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleCreateCase} className="p-6 space-y-4">
              <div>
                <label className="block text-xs text-gray-300 mb-1">Case Identifier (Unique)</label>
                <input
                  type="text"
                  value={newCaseId}
                  onChange={(e) => setNewCaseId(e.target.value)}
                  className="w-full bg-[#161f30] border border-gray-700 rounded-lg px-3 py-2 text-xs text-cyan-300 focus:outline-none focus:border-cyan-500"
                  required
                />
              </div>

              <div>
                <label className="block text-xs text-gray-300 mb-1">Case Name / Incident Title</label>
                <input
                  type="text"
                  value={newCaseName}
                  onChange={(e) => setNewCaseName(e.target.value)}
                  placeholder="e.g. Finance Server PsExec Intrusion"
                  className="w-full bg-[#161f30] border border-gray-700 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500"
                  required
                />
              </div>

              <div>
                <label className="block text-xs text-gray-300 mb-1">Organization Name</label>
                <input
                  type="text"
                  value={newOrgName}
                  onChange={(e) => setNewOrgName(e.target.value)}
                  className="w-full bg-[#161f30] border border-gray-700 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500"
                  required
                />
              </div>

              <div>
                <label className="block text-xs text-gray-300 mb-1">Investigation Goal / Inquiry</label>
                <textarea
                  value={newGoal}
                  onChange={(e) => setNewGoal(e.target.value)}
                  rows={3}
                  className="w-full bg-[#161f30] border border-gray-700 rounded-lg p-3 text-xs text-cyan-200 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="pt-4 border-t border-gray-800 flex items-center justify-end space-x-3">
                <button
                  type="button"
                  onClick={() => setIsNewCaseModalOpen(false)}
                  className="px-4 py-2 bg-gray-800 hover:bg-gray-700 text-xs text-gray-300 rounded-lg"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isCreating}
                  className="px-5 py-2 bg-gradient-to-r from-cyan-500 to-sky-600 hover:from-cyan-400 hover:to-sky-500 text-white text-xs font-bold rounded-lg shadow-lg shadow-cyan-500/20 disabled:opacity-50"
                >
                  {isCreating ? "Initializing Case..." : "Initialize & Open Case"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
