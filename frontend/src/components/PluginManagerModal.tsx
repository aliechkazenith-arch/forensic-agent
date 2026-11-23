import React, { useState } from "react";
import {
  Wrench,
  Terminal,
  Play,
  CheckCircle2,
  Columns,
  Layers,
  Sparkles,
  ArrowRight,
  ArrowLeft,
  X,
  FileCode,
  ShieldCheck,
} from "lucide-react";
import { api } from "../services/api";
import { useForensicStore } from "../store/useForensicStore";
import { ToolPluginCard, DryRunAutoMapperResult, FindingSeverity } from "../types";

interface PluginManagerModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const PluginManagerModal: React.FC<PluginManagerModalProps> = ({
  isOpen,
  onClose,
}) => {
  const { plugins, setPlugins } = useForensicStore();
  const [currentStep, setCurrentStep] = useState<number>(1);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // Step 1 Form
  const [toolId, setToolId] = useState<string>("chainsaw_custom");
  const [name, setName] = useState<string>("Chainsaw EVTX Hunter");
  const [version, setVersion] = useState<string>("2.10.0");
  const [description, setDescription] = useState<string>("Rapid Windows EVTX Sigma & hunt engine");
  const [category, setCategory] = useState<string>("evtx");
  const [artifactTypes, setArtifactTypes] = useState<string>("evtx, logs");
  const [executionTier, setExecutionTier] = useState<"tier_a_builtin" | "tier_b_adapter">("tier_b_adapter");
  const [commandTemplate, setCommandTemplate] = useState<string>("chainsaw hunt {input_file} --json -o {output_file}");
  const [defaultSeverity, setDefaultSeverity] = useState<FindingSeverity>("high");

  // Step 2 Form
  const defaultSampleRows = [
    {
      Timestamp: "2026-10-31T03:15:22.000Z",
      EventID: 4624,
      Computer: "FIN-SRV-01.corp.local",
      TargetUserName: "svc_admin",
      CommandLine: "powershell.exe -ExecutionPolicy Bypass -enc SQBFAFgA...",
      DetectionRule: "Suspicious PowerShell Encoded Payload",
    },
    {
      Timestamp: "2026-10-31T03:16:04.000Z",
      EventID: 4688,
      Computer: "FIN-SRV-01.corp.local",
      TargetUserName: "svc_admin",
      CommandLine: "cmd.exe /c whoami /priv",
      DetectionRule: "Privilege Enumeration",
    },
  ];
  const [sampleDataJson, setSampleDataJson] = useState<string>(
    JSON.stringify(defaultSampleRows, null, 2)
  );
  const [dryRunResult, setDryRunResult] = useState<DryRunAutoMapperResult | null>(null);

  // Step 3 Form (Mappings)
  const [fieldMap, setFieldMap] = useState<Record<string, string>>({});
  const [aiKeepFields, setAiKeepFields] = useState<string[]>([]);

  if (!isOpen) return null;

  const handleDryRun = async () => {
    setIsLoading(true);
    setErrorMsg(null);
    try {
      const parsedRows = JSON.parse(sampleDataJson);
      const res = await api.dryRunAutoMapper(parsedRows);
      setDryRunResult(res);
      setFieldMap(res.suggested_field_map || {});
      setAiKeepFields(res.suggested_ai_keep_fields || []);
      setCurrentStep(3);
    } catch (err: any) {
      setErrorMsg(`Dry run failed: ${err.message}`);
    } finally {
      setIsLoading(false);
    }
  };

  const handleRegister = async () => {
    setIsLoading(true);
    setErrorMsg(null);

    const card: ToolPluginCard = {
      tool_id: toolId,
      name,
      version,
      description,
      category,
      supported_artifact_types: artifactTypes.split(",").map((s) => s.trim()),
      execution_tier: executionTier,
      command_template: commandTemplate.split(" "),
      input_type: "file",
      output_format: "json",
      field_map: fieldMap,
      ai_keep_fields: aiKeepFields,
      default_severity: defaultSeverity,
      timeout_seconds: 120,
    };

    try {
      const res = await api.registerPlugin(card);
      setPlugins([...plugins, res.card]);
      onClose();
    } catch (err: any) {
      setErrorMsg(`Registration failed: ${err.message}`);
    } finally {
      setIsLoading(false);
    }
  };

  const canonicalTargetOptions = [
    "timestamp_utc",
    "event_id",
    "host",
    "user",
    "process_name",
    "command_line",
    "summary",
    "ignore",
  ];

  return (
    <div className="fixed inset-0 bg-slate-950/85 backdrop-blur-md flex items-center justify-center z-50 p-6 animate-in fade-in duration-200">
      <div className="bg-slate-900 border border-slate-700/80 rounded-2xl w-full max-w-3xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-800 bg-slate-950/60 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-amber-950/60 border border-amber-600/40 rounded-lg text-amber-400">
              <Wrench className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-slate-100">Zero-YAML Tool Onboarding Wizard</h2>
              <p className="text-xs text-slate-400">Register new forensic analyzers with air-gapped sandboxing</p>
            </div>
          </div>
          <button onClick={onClose} className="text-slate-400 hover:text-slate-200 transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Steps Progress Bar */}
        <div className="px-6 py-3 bg-slate-900 border-b border-slate-800 flex items-center justify-between text-xs">
          {[
            { step: 1, label: "1. Tool & Command" },
            { step: 2, label: "2. Sample Dry-Run" },
            { step: 3, label: "3. Smart Projection" },
            { step: 4, label: "4. Register Card" },
          ].map((item) => (
            <div
              key={item.step}
              className={`flex items-center gap-2 font-medium ${
                currentStep === item.step
                  ? "text-cyan-400"
                  : currentStep > item.step
                  ? "text-emerald-400"
                  : "text-slate-500"
              }`}
            >
              <div
                className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold border ${
                  currentStep === item.step
                    ? "border-cyan-400 bg-cyan-950 text-cyan-300"
                    : currentStep > item.step
                    ? "border-emerald-500 bg-emerald-950 text-emerald-300"
                    : "border-slate-700 bg-slate-800 text-slate-500"
                }`}
              >
                {currentStep > item.step ? "✓" : item.step}
              </div>
              <span>{item.label}</span>
            </div>
          ))}
        </div>

        {/* Error message */}
        {errorMsg && (
          <div className="mx-6 mt-4 p-3 bg-rose-950/80 border border-rose-800 rounded-lg text-xs text-rose-300">
            {errorMsg}
          </div>
        )}

        {/* Body Content */}
        <div className="p-6 overflow-y-auto flex-1 text-xs space-y-4 text-slate-200">
          {/* STEP 1: Metadata & Command */}
          {currentStep === 1 && (
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-slate-400 mb-1 font-medium">Tool ID (alphanumeric_snake)</label>
                  <input
                    type="text"
                    value={toolId}
                    onChange={(e) => setToolId(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-slate-100 font-mono focus:border-cyan-500 focus:outline-none"
                  />
                </div>
                <div>
                  <label className="block text-slate-400 mb-1 font-medium">Tool Display Name</label>
                  <input
                    type="text"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-slate-100 focus:border-cyan-500 focus:outline-none"
                  />
                </div>
              </div>

              <div className="grid grid-cols-3 gap-4">
                <div>
                  <label className="block text-slate-400 mb-1 font-medium">Category</label>
                  <select
                    value={category}
                    onChange={(e) => setCategory(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-slate-100 focus:border-cyan-500 focus:outline-none"
                  >
                    <option value="evtx">Windows EVTX</option>
                    <option value="mft">NTFS $MFT / USN</option>
                    <option value="memory">RAM / Volatility</option>
                    <option value="network">PCAP / Network</option>
                    <option value="linux_triage">Linux Syslog/Auth</option>
                  </select>
                </div>
                <div>
                  <label className="block text-slate-400 mb-1 font-medium">Execution Tier</label>
                  <select
                    value={executionTier}
                    onChange={(e) => setExecutionTier(e.target.value as any)}
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-slate-100 focus:border-cyan-500 focus:outline-none"
                  >
                    <option value="tier_b_adapter">Tier B: CLI Adapter (shell=False)</option>
                    <option value="tier_a_builtin">Tier A: Builtin Userspace Parser</option>
                  </select>
                </div>
                <div>
                  <label className="block text-slate-400 mb-1 font-medium">Default Severity</label>
                  <select
                    value={defaultSeverity}
                    onChange={(e) => setDefaultSeverity(e.target.value as FindingSeverity)}
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-slate-100 focus:border-cyan-500 focus:outline-none"
                  >
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-slate-400 mb-1 font-medium">Command Template</label>
                <input
                  type="text"
                  value={commandTemplate}
                  onChange={(e) => setCommandTemplate(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-amber-300 font-mono text-xs focus:border-cyan-500 focus:outline-none"
                />
                <div className="flex gap-2 mt-2">
                  <span className="text-slate-500">Insert token:</span>
                  {["{input_file}", "{output_file}", "{output_dir}"].map((token) => (
                    <button
                      key={token}
                      type="button"
                      onClick={() => setCommandTemplate((prev) => `${prev} ${token}`)}
                      className="bg-slate-800 hover:bg-slate-700 text-cyan-400 font-mono px-2 py-0.5 rounded text-[11px] border border-slate-700"
                    >
                      {token}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* STEP 2: Dry Run on Sample */}
          {currentStep === 2 && (
            <div className="space-y-3">
              <p className="text-slate-400 text-xs">
                Paste 2 to 5 sample output rows produced by this tool (JSON array format).
                The AI auto-mapper will inspect schema types and infer canonical field projections.
              </p>
              <textarea
                value={sampleDataJson}
                onChange={(e) => setSampleDataJson(e.target.value)}
                rows={10}
                className="w-full bg-slate-950 border border-slate-700 rounded-lg p-3 font-mono text-[11px] text-emerald-400 focus:border-cyan-500 focus:outline-none"
              />
            </div>
          )}

          {/* STEP 3: Smart Column Projection */}
          {currentStep === 3 && dryRunResult && (
            <div className="space-y-4">
              <div className="flex items-center justify-between bg-cyan-950/40 border border-cyan-800/50 p-3 rounded-xl">
                <div className="flex items-center gap-2 text-cyan-300">
                  <Sparkles className="w-4 h-4" />
                  <span className="font-semibold">Auto-Mapper Schema Inference</span>
                </div>
                <span className="text-[11px] text-cyan-400 font-mono">
                  {dryRunResult.total_columns_inspected} columns analyzed
                </span>
              </div>

              <div className="border border-slate-800 rounded-xl overflow-hidden">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="bg-slate-950 border-b border-slate-800 text-slate-400 text-[11px]">
                      <th className="p-2.5">Source Tool Column</th>
                      <th className="p-2.5">Confidence</th>
                      <th className="p-2.5">Target Canonical Field</th>
                      <th className="p-2.5 text-center">AI Keep</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
                    {Object.keys(dryRunResult.suggested_field_map || {}).map((col) => {
                      const conf = dryRunResult.confidence_scores[col] || 0.85;
                      const mapped = fieldMap[col] || "ignore";
                      const isAiKeep = aiKeepFields.includes(col);

                      return (
                        <tr key={col} className="hover:bg-slate-800/30">
                          <td className="p-2.5 text-slate-200 font-semibold">{col}</td>
                          <td className="p-2.5">
                            <span className="text-emerald-400 bg-emerald-950/60 px-1.5 py-0.5 rounded text-[10px]">
                              {Math.round(conf * 100)}%
                            </span>
                          </td>
                          <td className="p-2.5">
                            <select
                              value={mapped}
                              onChange={(e) =>
                                setFieldMap({ ...fieldMap, [col]: e.target.value })
                              }
                              className="bg-slate-950 border border-slate-700 text-cyan-300 rounded px-2 py-1 text-xs focus:outline-none"
                            >
                              {canonicalTargetOptions.map((opt) => (
                                <option key={opt} value={opt}>
                                  {opt}
                                </option>
                              ))}
                            </select>
                          </td>
                          <td className="p-2.5 text-center">
                            <input
                              type="checkbox"
                              checked={isAiKeep}
                              onChange={(e) => {
                                if (e.target.checked) {
                                  setAiKeepFields([...aiKeepFields, col]);
                                } else {
                                  setAiKeepFields(aiKeepFields.filter((f) => f !== col));
                                }
                              }}
                              className="rounded bg-slate-950 border-slate-700 text-cyan-500 focus:ring-0 cursor-pointer"
                            />
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* STEP 4: Review Card */}
          {currentStep === 4 && (
            <div className="space-y-4">
              <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 font-mono text-xs space-y-2">
                <div className="flex justify-between border-b border-slate-800 pb-2">
                  <span className="text-slate-500">Tool ID:</span>
                  <span className="text-cyan-400 font-semibold">{toolId}</span>
                </div>
                <div className="flex justify-between border-b border-slate-800 pb-2">
                  <span className="text-slate-500">Display Name:</span>
                  <span className="text-slate-200">{name}</span>
                </div>
                <div className="flex justify-between border-b border-slate-800 pb-2">
                  <span className="text-slate-500">Tier:</span>
                  <span className="text-amber-400">{executionTier}</span>
                </div>
                <div className="flex justify-between border-b border-slate-800 pb-2">
                  <span className="text-slate-500">Command:</span>
                  <span className="text-slate-300">{commandTemplate}</span>
                </div>
                <div>
                  <span className="text-slate-500 block mb-1">Canonical Projections:</span>
                  <pre className="bg-slate-900 p-2 rounded text-[10px] text-emerald-400 overflow-x-auto">
                    {JSON.stringify(fieldMap, null, 2)}
                  </pre>
                </div>
              </div>

              <div className="flex items-center gap-2 text-emerald-400 text-xs">
                <ShieldCheck className="w-4 h-4" />
                <span>Zero Shell Interpolation (shell=False) & Air-Gap Sandbox Verified</span>
              </div>
            </div>
          )}
        </div>

        {/* Footer Navigation */}
        <div className="px-6 py-4 bg-slate-950/80 border-t border-slate-800 flex items-center justify-between">
          <button
            onClick={() => setCurrentStep((prev) => Math.max(1, prev - 1))}
            disabled={currentStep === 1 || isLoading}
            className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            <span>Previous</span>
          </button>

          <div className="flex items-center gap-3">
            {currentStep < 4 ? (
              <button
                onClick={() => {
                  if (currentStep === 2) {
                    handleDryRun();
                  } else {
                    setCurrentStep((prev) => Math.min(4, prev + 1));
                  }
                }}
                disabled={isLoading}
                className="flex items-center gap-1.5 px-5 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-semibold shadow-lg shadow-cyan-500/20 transition-all"
              >
                <span>{currentStep === 2 ? "Run Sandbox Dry-Run" : "Next Step"}</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            ) : (
              <button
                onClick={handleRegister}
                disabled={isLoading}
                className="flex items-center gap-2 px-6 py-2 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-slate-950 text-xs font-bold shadow-lg shadow-emerald-500/20 transition-all"
              >
                <CheckCircle2 className="w-4 h-4" />
                <span>Register Plugin & Write YAML</span>
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
