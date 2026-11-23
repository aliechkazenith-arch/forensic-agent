import React, { useEffect, useState } from "react";
import {
  Wrench,
  Plus,
  Terminal,
  ShieldCheck,
  Cpu,
  Layers,
  Sparkles,
  ExternalLink,
  Search,
} from "lucide-react";
import { useForensicStore } from "../store/useForensicStore";
import { api } from "../services/api";
import { ToolPluginCard } from "../types";

interface PluginsViewProps {
  onOpenOnboardModal: () => void;
}

export const PluginsView: React.FC<PluginsViewProps> = ({ onOpenOnboardModal }) => {
  const { plugins, setPlugins } = useForensicStore();
  const [searchTerm, setSearchTerm] = useState<string>("");
  const [isLoading, setIsLoading] = useState<boolean>(false);

  useEffect(() => {
    setIsLoading(true);
    api
      .getPlugins()
      .then((data) => setPlugins(data))
      .catch(() => {})
      .finally(() => setIsLoading(false));
  }, [setPlugins]);

  const filtered = plugins.filter(
    (p) =>
      p.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      p.tool_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      p.category.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="h-[calc(100vh-68px)] flex flex-col bg-slate-950 overflow-y-auto p-8 text-slate-200">
      <div className="max-w-6xl mx-auto w-full space-y-6">
        {/* Header & Controls */}
        <div className="flex items-center justify-between">
          <div className="space-y-1">
            <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
              <Wrench className="w-6 h-6 text-amber-400" />
              <span>Tool Plugins & Adapters Registry</span>
            </h1>
            <p className="text-xs text-slate-400">
              Zero-YAML modular forensic analyzers executed via air-gapped userspace sandboxes (shell=False)
            </p>
          </div>

          <div className="flex items-center gap-3">
            <div className="relative">
              <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
              <input
                type="text"
                placeholder="Search tools..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="bg-slate-900 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 w-56 font-sans"
              />
            </div>

            <button
              onClick={onOpenOnboardModal}
              className="flex items-center gap-1.5 px-4 py-2 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs rounded-lg shadow-lg shadow-cyan-500/20 transition-all"
            >
              <Plus className="w-4 h-4" />
              <span>Onboard New Tool</span>
            </button>
          </div>
        </div>

        {/* Plugin Cards Grid */}
        {isLoading ? (
          <div className="text-center py-16 text-slate-500 text-xs font-mono">
            Loading active plugins...
          </div>
        ) : filtered.length === 0 ? (
          <div className="text-center py-16 bg-slate-900/50 border border-slate-800 rounded-2xl p-8 space-y-3">
            <Terminal className="w-10 h-10 text-slate-600 mx-auto" />
            <h3 className="font-semibold text-slate-300 text-sm">No Matching Tool Plugins</h3>
            <p className="text-xs text-slate-500">
              Click "Onboard New Tool" to register Zimmerman EZ Tools, Chainsaw, YARA, or custom CLI analyzers.
            </p>
          </div>
        ) : (
          <div className="grid grid-cols-2 gap-5">
            {filtered.map((tool) => (
              <div
                key={tool.tool_id}
                className="bg-slate-900/90 border border-slate-800 hover:border-slate-700 rounded-2xl p-5 shadow-xl space-y-3 transition-all"
              >
                <div className="flex items-start justify-between">
                  <div>
                    <div className="flex items-center gap-2">
                      <h3 className="font-bold text-sm text-slate-100">{tool.name}</h3>
                      <span className="text-[10px] font-mono text-slate-400 bg-slate-800 px-1.5 py-0.2 rounded">
                        v{tool.version}
                      </span>
                    </div>
                    <span className="text-[11px] font-mono text-cyan-400">tool_id: {tool.tool_id}</span>
                  </div>

                  <span
                    className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded border ${
                      tool.execution_tier === "tier_a_builtin"
                        ? "bg-emerald-950/80 text-emerald-300 border-emerald-700/60"
                        : "bg-amber-950/80 text-amber-300 border-amber-700/60"
                    }`}
                  >
                    {tool.execution_tier.replace("_", " ")}
                  </span>
                </div>

                <p className="text-xs text-slate-400 leading-relaxed">{tool.description}</p>

                {/* Command Preview */}
                <div className="bg-slate-950/80 border border-slate-800 rounded-lg p-2.5 font-mono text-[11px] text-amber-300 truncate">
                  {tool.command_template?.join(" ")}
                </div>

                {/* Metadata Badges */}
                <div className="flex items-center justify-between pt-2 border-t border-slate-800/80 text-xs">
                  <div className="flex items-center gap-1.5 text-slate-400">
                    <Layers className="w-3.5 h-3.5" />
                    <span>Artifacts:</span>
                    <span className="text-slate-200 font-mono">
                      {tool.supported_artifact_types?.join(", ")}
                    </span>
                  </div>

                  <div className="flex items-center gap-1 text-emerald-400 text-[11px]">
                    <ShieldCheck className="w-3.5 h-3.5" />
                    <span>Sandboxed (0-Shell)</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
