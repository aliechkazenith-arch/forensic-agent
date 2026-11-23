import React, { useEffect } from "react";
import {
  Shield,
  Layers,
  Wrench,
  FileText,
  Database,
  Activity,
  CheckCircle,
  AlertTriangle,
  Radio,
  Users,
  LogOut,
  BadgeCheck,
  Briefcase,
  FolderLock,
  Bot,
} from "lucide-react";
import { useForensicStore, ActiveTab } from "../store/useForensicStore";
import { useAuth } from "../context/AuthContext";
import { api } from "../services/api";

interface NavbarProps {
  onOpenUserManagement?: () => void;
  onToggleCopilot?: () => void;
  isCopilotOpen?: boolean;
}

export const Navbar: React.FC<NavbarProps> = ({
  onOpenUserManagement,
  onToggleCopilot,
  isCopilotOpen,
}) => {
  const {
    currentCaseId,
    setCaseId,
    activeTab,
    setActiveTab,
    isChainValid,
    setCustodyEntries,
  } = useForensicStore();

  const { user, logout } = useAuth();

  useEffect(() => {
    // Initial fetch of custody status
    api
      .getCustodyLedger(currentCaseId)
      .then((res) => {
        setCustodyEntries(res.entries, res.is_tamper_free);
      })
      .catch(() => {
        // Fallback for initial state
      });
  }, [currentCaseId, setCustodyEntries]);

  const navItems: Array<{ id: ActiveTab; label: string; icon: React.ReactNode }> = [
    { id: "wizard", label: "Intake Wizard", icon: <Radio className="w-4 h-4" /> },
    { id: "cases", label: "Case Manager", icon: <Briefcase className="w-4 h-4" /> },
    { id: "investigation", label: "Autonomous Controller", icon: <Bot className="w-4 h-4" /> },
    { id: "canvas", label: "Workflow Studio", icon: <Layers className="w-4 h-4" /> },
    { id: "plugins", label: "Custom Tools", icon: <Wrench className="w-4 h-4" /> },
    { id: "report", label: "Cited Report", icon: <FileText className="w-4 h-4" /> },
    { id: "vault", label: "Case Vault", icon: <FolderLock className="w-4 h-4" /> },
    { id: "custody", label: "Custody Chain", icon: <Database className="w-4 h-4" /> },
  ];

  return (
    <header className="h-16 bg-[#0e1422] border-b border-gray-800 px-6 flex items-center justify-between sticky top-0 z-40 select-none shadow-lg">
      {/* Brand & Platform Identifier */}
      <div className="flex items-center space-x-3">
        <div className="w-9 h-9 rounded-lg bg-gradient-to-tr from-cyan-600 to-emerald-500 p-0.5 flex items-center justify-center shadow-md shadow-cyan-500/20">
          <div className="w-full h-full bg-[#0b0f19] rounded-[7px] flex items-center justify-center">
            <Shield className="w-5 h-5 text-cyan-400" />
          </div>
        </div>
        <div>
          <div className="flex items-center space-x-2">
            <span className="font-extrabold text-base tracking-wide bg-gradient-to-r from-cyan-400 via-sky-300 to-emerald-400 bg-clip-text text-transparent">
              ForensicOps AI
            </span>
            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-cyan-950/70 border border-cyan-800/60 text-cyan-400">
              v2.0 RAG-Ready
            </span>
          </div>
          <p className="text-[11px] text-gray-400 font-sans tracking-tight">
            Local-First Workflow Cyber-Forensics
          </p>
        </div>
      </div>

      {/* Navigation Tabs */}
      <nav className="flex items-center space-x-1 bg-[#131b2e] p-1 rounded-xl border border-gray-800">
        {navItems.map((item) => {
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              className={`flex items-center space-x-2 px-3.5 py-1.5 rounded-lg text-xs font-medium transition-all duration-150 ${
                isActive
                  ? "bg-gradient-to-r from-cyan-500 to-sky-600 text-white shadow-md shadow-cyan-500/20"
                  : "text-gray-400 hover:text-gray-200 hover:bg-gray-800/60"
              }`}
            >
              {item.icon}
              <span>{item.label}</span>
            </button>
          );
        })}
      </nav>

      {/* Identity Bar, Case Selector & Custody Integrity Badge */}
      <div className="flex items-center space-x-3">
        {/* Investigator Identity & Role Chip */}
        {user && (
          <div className="flex items-center space-x-2 bg-[#131b2e] pl-2.5 pr-1.5 py-1 rounded-xl border border-gray-800">
            <div className="flex items-center space-x-1.5">
              <BadgeCheck className="w-3.5 h-3.5 text-cyan-400" />
              <span className="text-[11px] font-mono text-cyan-300 font-bold">
                {user.badge_id}
              </span>
            </div>

            {/* Role Badge Chip */}
            {user.role === "lead_investigator" && (
              <span className="px-2 py-0.5 rounded-md text-[10px] font-mono font-bold bg-gradient-to-r from-purple-950 to-indigo-950 border border-purple-700/60 text-purple-300">
                LEAD
              </span>
            )}
            {user.role === "soc_analyst" && (
              <span className="px-2 py-0.5 rounded-md text-[10px] font-mono font-bold bg-cyan-950/80 border border-cyan-800/60 text-cyan-300">
                SOC ANALYST
              </span>
            )}
            {user.role === "auditor" && (
              <span className="px-2 py-0.5 rounded-md text-[10px] font-mono font-bold bg-amber-950/80 border border-amber-800/60 text-amber-300">
                AUDITOR
              </span>
            )}

            {/* Manage Users Button (Lead only) */}
            {user.role === "lead_investigator" && onOpenUserManagement && (
              <button
                onClick={onOpenUserManagement}
                title="Manage Investigator Accounts & RBAC"
                className="p-1.5 rounded-lg text-purple-300 hover:text-white hover:bg-purple-900/40 transition"
              >
                <Users className="w-3.5 h-3.5" />
              </button>
            )}

            {/* Lock / Sign Out */}
            <button
              onClick={logout}
              title="Lock / Sign Out Session"
              className="p-1.5 rounded-lg text-gray-400 hover:text-rose-300 hover:bg-rose-950/40 transition"
            >
              <LogOut className="w-3.5 h-3.5" />
            </button>
          </div>
        )}

        {/* Case Selector */}
        <div className="flex items-center space-x-2 bg-[#131b2e] px-3 py-1.5 rounded-lg border border-gray-800">
          <Activity className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
          <span className="text-[11px] font-mono text-gray-400 uppercase tracking-wider">
            Case:
          </span>
          <input
            type="text"
            value={currentCaseId}
            onChange={(e) => setCaseId(e.target.value)}
            className="bg-transparent font-mono text-xs text-cyan-300 font-semibold focus:outline-none w-32 border-b border-transparent focus:border-cyan-500"
            placeholder="Case ID"
          />
        </div>

        {/* Chain of Custody Integrity Pill */}
        <button
          onClick={() => setActiveTab("custody")}
          title="Click to view full cryptographic hash chain"
          className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-mono border transition-all ${
            isChainValid
              ? "bg-emerald-950/40 border-emerald-800/60 text-emerald-400 hover:bg-emerald-900/40"
              : "bg-rose-950/40 border-rose-800/60 text-rose-400 hover:bg-rose-900/40"
          }`}
        >
          {isChainValid ? (
            <CheckCircle className="w-3.5 h-3.5 text-emerald-400" />
          ) : (
            <AlertTriangle className="w-3.5 h-3.5 text-rose-400 animate-bounce" />
          )}
          <span>
            {isChainValid ? "Custody: Intact" : "Custody: Tampered!"}
          </span>
        </button>

        {/* Co-Pilot Chatbot Drawer Toggle */}
        {onToggleCopilot && (
          <button
            onClick={onToggleCopilot}
            title="Toggle DFIR Co-Pilot Chatbot Drawer"
            className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold border transition-all shadow-sm ${
              isCopilotOpen
                ? "bg-cyan-500 text-slate-950 border-cyan-400 shadow-cyan-500/20"
                : "bg-gradient-to-r from-cyan-950/80 to-indigo-950/80 border-cyan-800/60 text-cyan-300 hover:border-cyan-500 hover:text-white"
            }`}
          >
            <Bot className="w-3.5 h-3.5 text-cyan-400" />
            <span>Co-Pilot</span>
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
          </button>
        )}
      </div>
    </header>
  );
};

