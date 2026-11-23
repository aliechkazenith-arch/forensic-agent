import React, { useState } from "react";
import {
  Shield,
  Key,
  User as UserIcon,
  BadgeCheck,
  Lock,
  ArrowRight,
  AlertCircle,
  FileCheck2,
  FolderOpen,
  Eye,
  EyeOff,
} from "lucide-react";
import { useAuth } from "../context/AuthContext";
import { useForensicStore } from "../store/useForensicStore";

export const AuthGate: React.FC = () => {
  const { isInitialized, login, setupFirstBoot, error, clearError, isLoading } = useAuth();
  const { currentCaseId, setCaseId } = useForensicStore();

  // Login form state
  const [loginIdentifier, setLoginIdentifier] = useState("admin");
  const [loginPassword, setLoginPassword] = useState("123456");
  const [showPassword, setShowPassword] = useState(false);

  // First boot form state
  const [setupUsername, setSetupUsername] = useState("lead_admin");
  const [setupBadge, setSetupBadge] = useState("BADGE-001");
  const [setupFullName, setSetupFullName] = useState("Chief Lead Investigator");
  const [setupPassword, setSetupPassword] = useState("ForensicOps2026!");
  const [setupConfirm, setSetupConfirm] = useState("ForensicOps2026!");
  const [setupError, setSetupError] = useState<string | null>(null);

  // Active Case input
  const [selectedCase, setSelectedCase] = useState(currentCaseId || "CASE-2026-LIVE-01");

  const handleLoginSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!loginIdentifier.trim() || !loginPassword) return;

    if (selectedCase.trim()) {
      setCaseId(selectedCase.trim());
    }

    try {
      await login(loginIdentifier.trim(), loginPassword);
    } catch {
      // Error is set in AuthContext
    }
  };

  const handleSetupSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSetupError(null);

    if (!setupUsername.trim() || !setupBadge.trim() || !setupPassword) {
      setSetupError("All fields are required.");
      return;
    }

    if (setupPassword !== setupConfirm) {
      setSetupError("Passwords do not match.");
      return;
    }

    if (setupPassword.length < 6) {
      setSetupError("Password must be at least 6 characters.");
      return;
    }

    if (selectedCase.trim()) {
      setCaseId(selectedCase.trim());
    }

    try {
      await setupFirstBoot({
        username: setupUsername.trim(),
        badge_id: setupBadge.trim(),
        full_name: setupFullName.trim(),
        password: setupPassword,
      });
    } catch (err: any) {
      setSetupError(err.message || "Failed to initialize Lead account.");
    }
  };

  return (
    <div className="min-h-screen bg-[#070a12] text-slate-200 flex flex-col justify-center items-center p-6 relative overflow-hidden select-none font-sans">
      {/* Background Ambient Glows */}
      <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-gradient-to-tr from-cyan-600/10 via-sky-500/10 to-emerald-500/10 rounded-full blur-3xl pointer-events-none" />
      <div className="absolute bottom-10 right-10 w-96 h-96 bg-indigo-600/10 rounded-full blur-3xl pointer-events-none" />

      {/* Main Glassmorphic Card */}
      <div className="relative z-10 w-full max-w-lg bg-[#0e1422]/90 backdrop-blur-xl border border-gray-800 rounded-2xl shadow-2xl p-8 transition-all duration-300">
        {/* Brand & Platform Header */}
        <div className="flex flex-col items-center text-center mb-8">
          <div className="w-14 h-14 rounded-2xl bg-gradient-to-tr from-cyan-500 via-sky-400 to-emerald-400 p-0.5 flex items-center justify-center shadow-lg shadow-cyan-500/20 mb-4">
            <div className="w-full h-full bg-[#0b0f19] rounded-[14px] flex items-center justify-center">
              <Shield className="w-7 h-7 text-cyan-400" />
            </div>
          </div>
          <h1 className="text-2xl font-extrabold tracking-wide bg-gradient-to-r from-cyan-400 via-sky-200 to-emerald-400 bg-clip-text text-transparent">
            ForensicOps AI
          </h1>
          <p className="text-xs text-gray-400 mt-1">
            Local-First Workflow Cyber-Forensics • NIST SP 800-86 Identity Binding
          </p>
        </div>

        {/* Global Error Banner */}
        {(error || setupError) && (
          <div className="mb-6 bg-rose-950/40 border border-rose-800/60 rounded-xl p-3.5 flex items-start space-x-3 text-rose-300 text-xs animate-shake">
            <AlertCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
            <div className="flex-1">
              <p className="font-semibold">{error || setupError}</p>
            </div>
            <button
              onClick={() => {
                clearError();
                setSetupError(null);
              }}
              className="text-rose-400 hover:text-rose-200 text-xs"
            >
              ✕
            </button>
          </div>
        )}

        {!isInitialized ? (
          /* ================= FIRST-BOOT SETUP FORM ================= */
          <form onSubmit={handleSetupSubmit} className="space-y-4">
            <div className="bg-cyan-950/30 border border-cyan-800/40 rounded-xl p-3 text-cyan-300 text-xs flex items-center space-x-2.5 mb-2">
              <Key className="w-4 h-4 text-cyan-400 shrink-0" />
              <span>
                <strong>First-Boot Setup:</strong> Initialize the Master Lead Investigator account.
              </span>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-[11px] font-semibold text-gray-300 uppercase tracking-wider mb-1">
                  Username
                </label>
                <div className="relative">
                  <UserIcon className="w-4 h-4 text-gray-400 absolute left-3 top-2.5" />
                  <input
                    type="text"
                    required
                    value={setupUsername}
                    onChange={(e) => setSetupUsername(e.target.value)}
                    className="w-full bg-[#131b2e] border border-gray-700/80 rounded-lg pl-9 pr-3 py-2 text-xs text-slate-100 placeholder-gray-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500"
                    placeholder="lead_admin"
                  />
                </div>
              </div>

              <div>
                <label className="block text-[11px] font-semibold text-gray-300 uppercase tracking-wider mb-1">
                  Badge ID
                </label>
                <div className="relative">
                  <BadgeCheck className="w-4 h-4 text-cyan-400 absolute left-3 top-2.5" />
                  <input
                    type="text"
                    required
                    value={setupBadge}
                    onChange={(e) => setSetupBadge(e.target.value)}
                    className="w-full bg-[#131b2e] border border-gray-700/80 rounded-lg pl-9 pr-3 py-2 text-xs text-slate-100 placeholder-gray-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 font-mono"
                    placeholder="BADGE-001"
                  />
                </div>
              </div>
            </div>

            <div>
              <label className="block text-[11px] font-semibold text-gray-300 uppercase tracking-wider mb-1">
                Full Name / DFIR Title
              </label>
              <input
                type="text"
                value={setupFullName}
                onChange={(e) => setSetupFullName(e.target.value)}
                className="w-full bg-[#131b2e] border border-gray-700/80 rounded-lg px-3 py-2 text-xs text-slate-100 placeholder-gray-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500"
                placeholder="Chief Lead Investigator"
              />
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-[11px] font-semibold text-gray-300 uppercase tracking-wider mb-1">
                  Master Password
                </label>
                <div className="relative">
                  <Lock className="w-4 h-4 text-gray-400 absolute left-3 top-2.5" />
                  <input
                    type="password"
                    required
                    value={setupPassword}
                    onChange={(e) => setSetupPassword(e.target.value)}
                    className="w-full bg-[#131b2e] border border-gray-700/80 rounded-lg pl-9 pr-3 py-2 text-xs text-slate-100 placeholder-gray-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500"
                    placeholder="••••••••"
                  />
                </div>
              </div>

              <div>
                <label className="block text-[11px] font-semibold text-gray-300 uppercase tracking-wider mb-1">
                  Confirm Password
                </label>
                <div className="relative">
                  <Lock className="w-4 h-4 text-gray-400 absolute left-3 top-2.5" />
                  <input
                    type="password"
                    required
                    value={setupConfirm}
                    onChange={(e) => setSetupConfirm(e.target.value)}
                    className="w-full bg-[#131b2e] border border-gray-700/80 rounded-lg pl-9 pr-3 py-2 text-xs text-slate-100 placeholder-gray-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500"
                    placeholder="••••••••"
                  />
                </div>
              </div>
            </div>

            <div>
              <label className="block text-[11px] font-semibold text-gray-300 uppercase tracking-wider mb-1">
                Active Forensic Case ID
              </label>
              <div className="relative">
                <FolderOpen className="w-4 h-4 text-emerald-400 absolute left-3 top-2.5" />
                <input
                  type="text"
                  required
                  value={selectedCase}
                  onChange={(e) => setSelectedCase(e.target.value)}
                  className="w-full bg-[#131b2e] border border-gray-700/80 rounded-lg pl-9 pr-3 py-2 text-xs font-mono text-emerald-300 placeholder-gray-500 focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500"
                  placeholder="CASE-2026-LIVE-01"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={isLoading}
              className="w-full mt-2 bg-gradient-to-r from-cyan-500 to-emerald-500 hover:from-cyan-400 hover:to-emerald-400 text-slate-950 font-bold py-2.5 px-4 rounded-xl text-xs flex items-center justify-center space-x-2 shadow-lg shadow-cyan-500/20 transition-all disabled:opacity-50"
            >
              <span>{isLoading ? "Provisioning..." : "Initialize Lead & Open Studio"}</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </form>
        ) : (
          /* ================= STANDARD INVESTIGATOR LOGIN FORM ================= */
          <form onSubmit={handleLoginSubmit} className="space-y-4">
            <div>
              <label className="block text-[11px] font-semibold text-gray-300 uppercase tracking-wider mb-1.5">
                Username or Badge ID
              </label>
              <div className="relative">
                <BadgeCheck className="w-4 h-4 text-cyan-400 absolute left-3 top-3" />
                <input
                  type="text"
                  required
                  value={loginIdentifier}
                  onChange={(e) => setLoginIdentifier(e.target.value)}
                  className="w-full bg-[#131b2e] border border-gray-700/80 rounded-xl pl-9 pr-3 py-2.5 text-xs text-slate-100 placeholder-gray-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 font-mono"
                  placeholder="BADGE-001 or username"
                  autoFocus
                />
              </div>
            </div>

            <div>
              <label className="block text-[11px] font-semibold text-gray-300 uppercase tracking-wider mb-1.5">
                Master Password
              </label>
              <div className="relative">
                <Lock className="w-4 h-4 text-gray-400 absolute left-3 top-3" />
                <input
                  type={showPassword ? "text" : "password"}
                  required
                  value={loginPassword}
                  onChange={(e) => setLoginPassword(e.target.value)}
                  className="w-full bg-[#131b2e] border border-gray-700/80 rounded-xl pl-9 pr-10 py-2.5 text-xs text-slate-100 placeholder-gray-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500"
                  placeholder="••••••••••••"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-3 text-gray-400 hover:text-gray-200"
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            <div>
              <label className="block text-[11px] font-semibold text-gray-300 uppercase tracking-wider mb-1.5">
                Target Case Assignment
              </label>
              <div className="relative">
                <FolderOpen className="w-4 h-4 text-emerald-400 absolute left-3 top-3" />
                <input
                  type="text"
                  required
                  value={selectedCase}
                  onChange={(e) => setSelectedCase(e.target.value)}
                  className="w-full bg-[#131b2e] border border-gray-700/80 rounded-xl pl-9 pr-3 py-2.5 text-xs font-mono text-emerald-300 placeholder-gray-500 focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500"
                  placeholder="CASE-2026-LIVE-01"
                />
              </div>
              <p className="text-[10px] text-gray-500 mt-1">
                Cryptographic custody entries will be chained under this Case identifier.
              </p>
            </div>

            <div className="flex items-center justify-between text-[11px] text-gray-400 bg-cyan-950/20 border border-cyan-800/30 rounded-lg px-3 py-1.5">
              <span>Demo Account: <strong className="text-cyan-300 font-mono">admin</strong> / <span className="font-mono text-cyan-400">123456</span></span>
              <button
                type="button"
                onClick={() => {
                  setLoginIdentifier("admin");
                  setLoginPassword("123456");
                }}
                className="text-cyan-400 hover:text-cyan-200 underline font-semibold"
              >
                Auto-fill
              </button>
            </div>

            <button
              type="submit"
              disabled={isLoading}
              className="w-full mt-3 bg-gradient-to-r from-cyan-500 via-sky-500 to-emerald-500 hover:from-cyan-400 hover:to-emerald-400 text-slate-950 font-bold py-2.5 px-4 rounded-xl text-xs flex items-center justify-center space-x-2 shadow-lg shadow-cyan-500/20 transition-all disabled:opacity-50"
            >
              <span>{isLoading ? "Authenticating..." : "Enter Forensic Studio"}</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </form>
        )}

        {/* Roles & Compliance Footer */}
        <div className="mt-8 pt-6 border-t border-gray-800/80 flex items-center justify-between text-[11px] text-gray-500">
          <div className="flex items-center space-x-1.5">
            <FileCheck2 className="w-3.5 h-3.5 text-cyan-400" />
            <span>RFC 3227 & ISO/IEC 27037</span>
          </div>
          <div className="flex items-center space-x-2 font-mono text-[10px]">
            <span className="text-purple-400">LEAD</span>
            <span>•</span>
            <span className="text-cyan-400">SOC ANALYST</span>
            <span>•</span>
            <span className="text-amber-400">AUDITOR</span>
          </div>
        </div>
      </div>
    </div>
  );
};
