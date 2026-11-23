import React, { useEffect, useState } from "react";
import {
  X,
  Users,
  UserPlus,
  ShieldAlert,
  CheckCircle,
  AlertTriangle,
  BadgeCheck,
  User as UserIcon,
  Lock,
} from "lucide-react";
import { User, UserCreatePayload, UserRole } from "../types";
import { api } from "../services/api";
import { useAuth } from "../context/AuthContext";

interface UserManagementModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const UserManagementModal: React.FC<UserManagementModalProps> = ({
  isOpen,
  onClose,
}) => {
  const { user: currentUser } = useAuth();
  const [users, setUsers] = useState<User[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [activeTab, setActiveTab] = useState<"list" | "create">("list");
  const [message, setMessage] = useState<{ type: "success" | "error"; text: string } | null>(null);

  // Form state
  const [newUsername, setNewUsername] = useState("");
  const [newBadge, setNewBadge] = useState("");
  const [newRole, setNewRole] = useState<UserRole>("soc_analyst");
  const [newFullName, setNewFullName] = useState("");
  const [newPassword, setNewPassword] = useState("");

  const loadUsers = async () => {
    setIsLoading(true);
    try {
      const data = await api.listUsers();
      setUsers(data);
    } catch (err: any) {
      setMessage({ type: "error", text: err.message || "Failed to load users" });
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    if (isOpen) {
      loadUsers();
      setMessage(null);
    }
  }, [isOpen]);

  const handleCreateSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setMessage(null);

    if (!newUsername.trim() || !newBadge.trim() || !newPassword) {
      setMessage({ type: "error", text: "Username, Badge ID, and Password are required." });
      return;
    }

    try {
      const payload: UserCreatePayload = {
        username: newUsername.trim(),
        badge_id: newBadge.trim(),
        role: newRole,
        full_name: newFullName.trim() || undefined,
        password: newPassword,
      };

      await api.createUser(payload);
      setMessage({ type: "success", text: `Account for '${newUsername}' created successfully.` });

      // Reset form
      setNewUsername("");
      setNewBadge("");
      setNewFullName("");
      setNewPassword("");
      setActiveTab("list");
      loadUsers();
    } catch (err: any) {
      setMessage({ type: "error", text: err.message || "Failed to create user" });
    }
  };

  const handleToggleStatus = async (targetUser: User) => {
    if (targetUser.id === currentUser?.id) {
      setMessage({ type: "error", text: "You cannot suspend your own Lead account." });
      return;
    }

    try {
      await api.updateUserStatus(targetUser.id, !targetUser.is_active);
      setMessage({
        type: "success",
        text: `Account '${targetUser.username}' ${targetUser.is_active ? "suspended" : "activated"}.`,
      });
      loadUsers();
    } catch (err: any) {
      setMessage({ type: "error", text: err.message || "Failed to update user status" });
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm select-none font-sans">
      <div className="w-full max-w-3xl bg-[#0e1422] border border-gray-800 rounded-2xl shadow-2xl flex flex-col overflow-hidden max-h-[90vh]">
        {/* Modal Header */}
        <div className="h-16 px-6 border-b border-gray-800 flex items-center justify-between bg-[#131b2e]/60">
          <div className="flex items-center space-x-3">
            <div className="w-9 h-9 rounded-xl bg-purple-950/80 border border-purple-700/60 flex items-center justify-center">
              <Users className="w-5 h-5 text-purple-400" />
            </div>
            <div>
              <h2 className="text-sm font-bold text-slate-100 flex items-center space-x-2">
                <span>Investigator Identity & RBAC Management</span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-purple-950/80 border border-purple-800 text-purple-300">
                  Lead Only
                </span>
              </h2>
              <p className="text-[11px] text-gray-400">
                Provision and audit SOC Analyst and Compliance Auditor credentials
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="w-8 h-8 rounded-lg flex items-center justify-center text-gray-400 hover:text-white hover:bg-gray-800 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Tab Controls */}
        <div className="px-6 pt-4 border-b border-gray-800 flex items-center space-x-4 bg-[#0e1422]">
          <button
            onClick={() => setActiveTab("list")}
            className={`pb-3 text-xs font-semibold flex items-center space-x-2 border-b-2 transition ${
              activeTab === "list"
                ? "border-cyan-500 text-cyan-400"
                : "border-transparent text-gray-400 hover:text-gray-200"
            }`}
          >
            <Users className="w-4 h-4" />
            <span>Active Investigators ({users.length})</span>
          </button>
          <button
            onClick={() => setActiveTab("create")}
            className={`pb-3 text-xs font-semibold flex items-center space-x-2 border-b-2 transition ${
              activeTab === "create"
                ? "border-cyan-500 text-cyan-400"
                : "border-transparent text-gray-400 hover:text-gray-200"
            }`}
          >
            <UserPlus className="w-4 h-4" />
            <span>Provision New Investigator</span>
          </button>
        </div>

        {/* Message Banner */}
        {message && (
          <div
            className={`mx-6 mt-4 p-3 rounded-xl text-xs flex items-center space-x-2.5 ${
              message.type === "success"
                ? "bg-emerald-950/40 border border-emerald-800/60 text-emerald-300"
                : "bg-rose-950/40 border border-rose-800/60 text-rose-300"
            }`}
          >
            {message.type === "success" ? (
              <CheckCircle className="w-4 h-4 text-emerald-400 shrink-0" />
            ) : (
              <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
            )}
            <span className="flex-1">{message.text}</span>
            <button onClick={() => setMessage(null)} className="hover:text-white text-xs">
              ✕
            </button>
          </div>
        )}

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto flex-1">
          {activeTab === "list" ? (
            /* ================= USER LIST TABLE ================= */
            <div className="border border-gray-800 rounded-xl overflow-hidden bg-[#111827]/40">
              <table className="w-full text-left text-xs">
                <thead className="bg-[#131b2e] text-gray-400 uppercase text-[10px] tracking-wider border-b border-gray-800">
                  <tr>
                    <th className="py-3 px-4 font-semibold">Investigator</th>
                    <th className="py-3 px-4 font-semibold font-mono">Badge ID</th>
                    <th className="py-3 px-4 font-semibold">Role</th>
                    <th className="py-3 px-4 font-semibold">Status</th>
                    <th className="py-3 px-4 text-right font-semibold">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-800/60 text-slate-200">
                  {users.map((u) => {
                    const isSelf = u.id === currentUser?.id;
                    return (
                      <tr key={u.id} className="hover:bg-gray-800/20 transition">
                        <td className="py-3 px-4">
                          <div className="font-semibold text-slate-100 flex items-center space-x-2">
                            <span>{u.username}</span>
                            {isSelf && (
                              <span className="text-[9px] bg-purple-950 text-purple-400 px-1.5 py-0.2 rounded font-mono">
                                YOU
                              </span>
                            )}
                          </div>
                          {u.full_name && (
                            <div className="text-[11px] text-gray-400">{u.full_name}</div>
                          )}
                        </td>
                        <td className="py-3 px-4 font-mono text-cyan-300">{u.badge_id}</td>
                        <td className="py-3 px-4">
                          {u.role === "lead_investigator" && (
                            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-purple-950/80 border border-purple-800/60 text-purple-300 font-semibold">
                              LEAD
                            </span>
                          )}
                          {u.role === "soc_analyst" && (
                            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-cyan-950/80 border border-cyan-800/60 text-cyan-300 font-semibold">
                              SOC ANALYST
                            </span>
                          )}
                          {u.role === "auditor" && (
                            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-amber-950/80 border border-amber-800/60 text-amber-300 font-semibold">
                              AUDITOR
                            </span>
                          )}
                        </td>
                        <td className="py-3 px-4">
                          {u.is_active ? (
                            <span className="inline-flex items-center text-emerald-400 text-[11px]">
                              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 mr-1.5"></span>
                              Active
                            </span>
                          ) : (
                            <span className="inline-flex items-center text-rose-400 text-[11px]">
                              <span className="w-1.5 h-1.5 rounded-full bg-rose-400 mr-1.5"></span>
                              Suspended
                            </span>
                          )}
                        </td>
                        <td className="py-3 px-4 text-right">
                          {!isSelf && (
                            <button
                              onClick={() => handleToggleStatus(u)}
                              className={`text-[11px] font-medium px-2.5 py-1 rounded-lg border transition ${
                                u.is_active
                                  ? "border-rose-800/60 text-rose-300 hover:bg-rose-950/40"
                                  : "border-emerald-800/60 text-emerald-300 hover:bg-emerald-950/40"
                              }`}
                            >
                              {u.is_active ? "Suspend" : "Activate"}
                            </button>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          ) : (
            /* ================= PROVISION USER FORM ================= */
            <form onSubmit={handleCreateSubmit} className="space-y-4 max-w-xl mx-auto">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-[11px] font-semibold text-gray-300 uppercase tracking-wider mb-1">
                    Username
                  </label>
                  <div className="relative">
                    <UserIcon className="w-4 h-4 text-gray-400 absolute left-3 top-2.5" />
                    <input
                      type="text"
                      required
                      value={newUsername}
                      onChange={(e) => setNewUsername(e.target.value)}
                      className="w-full bg-[#131b2e] border border-gray-700 rounded-lg pl-9 pr-3 py-2 text-xs text-slate-100 placeholder-gray-500 focus:outline-none focus:border-cyan-500"
                      placeholder="analyst_jane"
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
                      value={newBadge}
                      onChange={(e) => setNewBadge(e.target.value)}
                      className="w-full bg-[#131b2e] border border-gray-700 rounded-lg pl-9 pr-3 py-2 text-xs font-mono text-cyan-300 placeholder-gray-500 focus:outline-none focus:border-cyan-500"
                      placeholder="BADGE-102"
                    />
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-[11px] font-semibold text-gray-300 uppercase tracking-wider mb-1">
                    Assigned Role
                  </label>
                  <select
                    value={newRole}
                    onChange={(e) => setNewRole(e.target.value as UserRole)}
                    className="w-full bg-[#131b2e] border border-gray-700 rounded-lg px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-cyan-500"
                  >
                    <option value="soc_analyst">SOC Analyst (Intake, Workflows, Feedback)</option>
                    <option value="auditor">Compliance Auditor (Read-Only Custody & Reports)</option>
                  </select>
                </div>

                <div>
                  <label className="block text-[11px] font-semibold text-gray-300 uppercase tracking-wider mb-1">
                    Full Name (Optional)
                  </label>
                  <input
                    type="text"
                    value={newFullName}
                    onChange={(e) => setNewFullName(e.target.value)}
                    className="w-full bg-[#131b2e] border border-gray-700 rounded-lg px-3 py-2 text-xs text-slate-100 placeholder-gray-500 focus:outline-none focus:border-cyan-500"
                    placeholder="Jane Doe, Senior Analyst"
                  />
                </div>
              </div>

              <div>
                <label className="block text-[11px] font-semibold text-gray-300 uppercase tracking-wider mb-1">
                  Temporary / Initial Password
                </label>
                <div className="relative">
                  <Lock className="w-4 h-4 text-gray-400 absolute left-3 top-2.5" />
                  <input
                    type="password"
                    required
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    className="w-full bg-[#131b2e] border border-gray-700 rounded-lg pl-9 pr-3 py-2 text-xs text-slate-100 placeholder-gray-500 focus:outline-none focus:border-cyan-500"
                    placeholder="••••••••••••"
                  />
                </div>
              </div>

              <div className="pt-2">
                <button
                  type="submit"
                  className="w-full bg-gradient-to-r from-cyan-500 to-sky-600 hover:from-cyan-400 hover:to-sky-500 text-white font-bold py-2.5 px-4 rounded-xl text-xs shadow-md shadow-cyan-500/20 transition"
                >
                  Register Investigator Account
                </button>
              </div>
            </form>
          )}
        </div>
      </div>
    </div>
  );
};
