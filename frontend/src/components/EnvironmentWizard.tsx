import React, { useState, useEffect, useMemo } from "react";
import {
  HardDrive,
  Server,
  ShieldCheck,
  Hash,
  ArrowRight,
  ArrowLeft,
  CheckCircle,
  FileCheck,
  Lock,
  Layers,
  Cpu,
  RefreshCw,
  Globe,
  Shield,
  AlertCircle,
  Check,
  Sparkles,
  Upload,
  FolderOpen,
  FileText,
  Copy,
  X,
  Folder,
  CheckCheck,
  HelpCircle,
  Lightbulb,
  ShieldAlert,
  Play,
  Compass,
  Briefcase,
  Building2,
  Target,
  Key,
} from "lucide-react";
import { useForensicStore } from "../store/useForensicStore";
import { useInvestigation } from "../context/InvestigationContext";
import { api } from "../services/api";
import {
  ArtifactRecord,
  CustodyChainEntry,
  HumanApprovalToken,
  LLMProvider,
  LLMSmokeTestResult,
  EvidenceUploadResult,
  BrowseLocalResult,
  HypothesisDraft,
  SIEMConnectionResponse,
  SIEMConnectionTestResponse,
} from "../types";

export const EnvironmentWizard: React.FC = () => {
  const { currentCaseId, setActiveTab, setCustodyEntries, setReportData } = useForensicStore();
  const { caseId, wizardState, updateWizardState, isSavingSession, setSelectedBlueprintKey } = useInvestigation();

  const [step, setStep] = useState<1 | 2 | 3 | 4>(() =>
    wizardState.hypothesisDraft
      ? 4
      : wizardState.ingestedArtifacts && wizardState.ingestedArtifacts.length > 0
      ? 3
      : 1
  );
  const mode = wizardState.mode || "offline";
  const setMode = (m: "offline" | "siem") => updateWizardState({ mode: m });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Step 4: AI Hypothesis Planner States
  const investigationGoal =
    wizardState.investigationGoal ||
    "Investigate potential unauthorized access, execution anomalies, and persistence.";
  const setInvestigationGoal = (g: string) => updateWizardState({ investigationGoal: g });
  const hypothesisDraft = wizardState.hypothesisDraft || null;
  const setHypothesisDraft = (d: HypothesisDraft | null) => updateWizardState({ hypothesisDraft: d });
  const [planningHypothesis, setPlanningHypothesis] = useState(false);
  const [hypothesisError, setHypothesisError] = useState<string | null>(null);

  const handleGenerateHypothesis = async (goalOverride?: string) => {
    const goalToUse = (goalOverride || investigationGoal).trim();
    if (!goalToUse) {
      setHypothesisError("Please provide an investigation goal or hypothesis query.");
      return;
    }
    setPlanningHypothesis(true);
    setHypothesisError(null);
    try {
      const draft = await api.planHypothesis({
        case_id: currentCaseId,
        investigation_goal: goalToUse,
        auto_approve: true,
      });
      setHypothesisDraft(draft);
      if (draft.report) {
        setReportData(draft.report, draft.report_markdown || "");
      }
      if (draft.recommended_blueprint) {
        setSelectedBlueprintKey(draft.recommended_blueprint);
      }
    } catch (err: any) {
      setHypothesisError(err.message || "Failed to generate AI hypothesis plan.");
    } finally {
      setPlanningHypothesis(false);
    }
  };

  // LLM Multi-Provider States
  const [providers, setProviders] = useState<LLMProvider[]>([]);
  const [activeProviderId, setActiveProviderId] = useState<string>("lm_studio_local");
  const [providersLoading, setProvidersLoading] = useState<boolean>(true);
  const [testingProviders, setTestingProviders] = useState<Record<string, boolean>>({});
  const [smokeTestResults, setSmokeTestResults] = useState<Record<string, LLMSmokeTestResult>>({});

  useEffect(() => {
    let isMounted = true;
    const fetchProviders = async () => {
      try {
        setProvidersLoading(true);
        const list = await api.getLLMProviders();
        if (isMounted) {
          setProviders(list);
          const active = list.find((p) => p.is_active);
          if (active) {
            setActiveProviderId(active.provider_id);
          }
          // Rehydrate persisted smoke test statuses from SQLite store
          const initialResults: Record<string, LLMSmokeTestResult> = {};
          list.forEach((p) => {
            if (p.last_test_success !== undefined && p.last_test_success !== null) {
              initialResults[p.provider_id] = {
                provider_id: p.provider_id,
                success: p.last_test_success,
                latency_ms: p.last_latency_ms || 0,
                response_preview: p.response_preview,
                error_detail: p.error_detail,
              };
            }
          });
          setSmokeTestResults(initialResults);
        }
      } catch (err: any) {
        console.error("Failed to load LLM providers:", err);
      } finally {
        if (isMounted) setProvidersLoading(false);
      }
    };
    fetchProviders();
    return () => {
      isMounted = false;
    };
  }, []);

  const handleSelectProvider = async (providerId: string) => {
    try {
      await api.selectLLMProvider(providerId);
      setActiveProviderId(providerId);
      setProviders((prev) =>
        prev.map((p) => ({
          ...p,
          is_active: p.provider_id === providerId,
        }))
      );
    } catch (err: any) {
      setError(`Failed to select LLM provider: ${err.message || err}`);
    }
  };

  const handleSmokeTest = async (providerId: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setTestingProviders((prev) => ({ ...prev, [providerId]: true }));
    try {
      const res = await api.smokeTestLLMProvider(providerId);
      setSmokeTestResults((prev) => ({ ...prev, [providerId]: res }));
    } catch (err: any) {
      setSmokeTestResults((prev) => ({
        ...prev,
        [providerId]: {
          provider_id: providerId,
          success: false,
          latency_ms: 0,
          error_detail: err.message || "Connection failed",
        },
      }));
    } finally {
      setTestingProviders((prev) => ({ ...prev, [providerId]: false }));
    }
  };

  // Offline Mode States (bound to persistent InvestigationContext and SQLite)
  const offlinePath = wizardState.offlinePath || "";
  const setOfflinePath = (p: string) => updateWizardState({ offlinePath: p });

  const isZeroCopy = wizardState.isZeroCopy || false;
  const setIsZeroCopy = (z: boolean | ((prev: boolean) => boolean)) => {
    const val = typeof z === "function" ? z(wizardState.isZeroCopy || false) : z;
    updateWizardState({ isZeroCopy: val });
  };

  const artifactType = wizardState.artifactType || "evtx";
  const setArtifactType = (a: string) => updateWizardState({ artifactType: a });

  const autoIndex = wizardState.autoIndex !== undefined ? wizardState.autoIndex : true;
  const setAutoIndex = (ai: boolean | ((prev: boolean) => boolean)) => {
    const val = typeof ai === "function" ? ai(wizardState.autoIndex !== undefined ? wizardState.autoIndex : true) : ai;
    updateWizardState({ autoIndex: val });
  };

  // File Upload & Local Browser States
  const fileInputRef = React.useRef<HTMLInputElement | null>(null);
  const [uploading, setUploading] = useState<boolean>(false);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const uploadedMetadata = wizardState.uploadedMetadata || null;
  const setUploadedMetadata = (m: EvidenceUploadResult | null) => updateWizardState({ uploadedMetadata: m });
  const [isDragging, setIsDragging] = useState<boolean>(false);
  const [copiedHash, setCopiedHash] = useState<"sha256" | "sha512" | null>(null);

  // Local Host Browser Modal States
  const [showLocalBrowserModal, setShowLocalBrowserModal] = useState<boolean>(false);
  const [browsingLoading, setBrowsingLoading] = useState<boolean>(false);
  const [localBrowserData, setLocalBrowserData] = useState<BrowseLocalResult | null>(null);

  const handleFileUpload = async (file: File) => {
    try {
      setUploading(true);
      setUploadError(null);
      const res = await api.uploadEvidence(file, currentCaseId);
      updateWizardState({
        uploadedMetadata: res,
        offlinePath: res.file_path,
        artifactType: res.detected_artifact_type || artifactType,
      });
    } catch (err: any) {
      setUploadError(`Upload failed: ${err.message || err}`);
    } finally {
      setUploading(false);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      handleFileUpload(e.target.files[0]);
    }
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleFileUpload(e.dataTransfer.files[0]);
    }
  };

  const handleOpenLocalBrowser = async (targetPath?: string) => {
    setShowLocalBrowserModal(true);
    setBrowsingLoading(true);
    try {
      const res = await api.browseLocal({ current_path: targetPath });
      setLocalBrowserData(res);
    } catch (err: any) {
      setError(`Failed to browse local files: ${err.message || err}`);
    } finally {
      setBrowsingLoading(false);
    }
  };

  const handleSelectLocalFile = (filePath: string, ext?: string) => {
    setOfflinePath(filePath);
    setShowLocalBrowserModal(false);
    if (ext) {
      const detected = ext.replace(".", "").toLowerCase();
      if (detected === "evtx") setArtifactType("evtx");
      else if (["e01", "vmdk", "dd", "img"].includes(detected)) setArtifactType("disk_image");
      else if (["dmp", "raw", "lime", "vmem"].includes(detected)) setArtifactType("memory");
      else if (["zip", "tar", "gz"].includes(detected)) setArtifactType("capsule");
    }
  };

  const copyToClipboard = (text: string, type: "sha256" | "sha512") => {
    navigator.clipboard.writeText(text);
    setCopiedHash(type);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  // Approval Gate States
  const defaultApprovalTokenId = useMemo(
    () => `tok-${Math.random().toString(36).substring(2, 9)}`,
    []
  );
  const approvalTokenId = wizardState.approvalTokenId || defaultApprovalTokenId;
  const setApprovalTokenId = (t: string | ((prev: string) => string)) => {
    const val = typeof t === "function" ? t(wizardState.approvalTokenId || `tok-init`) : t;
    updateWizardState({ approvalTokenId: val });
  };

  const gateApproved = wizardState.gateApproved !== undefined ? wizardState.gateApproved : true;
  const setGateApproved = (g: boolean | ((prev: boolean) => boolean)) => {
    const val = typeof g === "function" ? g(wizardState.gateApproved !== undefined ? wizardState.gateApproved : true) : g;
    updateWizardState({ gateApproved: val });
  };

  // SIEM Mode States
  const siemType = wizardState.siemType || "elasticsearch";
  const setSiemType = (st: "elasticsearch" | "wazuh" | "splunk") => updateWizardState({ siemType: st });

  const siemUrl = wizardState.siemUrl || "https://siem.internal:9200";
  const setSiemUrl = (u: string) => updateWizardState({ siemUrl: u });

  const siemIndex = wizardState.siemIndex || "winlogbeat-*";
  const setSiemIndex = (i: string) => updateWizardState({ siemIndex: i });

  const siemQuery = wizardState.siemQuery || 'event.code: "4624" AND winlog.event_data.LogonType: "3"';
  const setSiemQuery = (q: string) => updateWizardState({ siemQuery: q });

  // SIEM Connection Management States (SEC-UI-001)
  const [siemConnections, setSiemConnections] = useState<SIEMConnectionResponse[]>([]);
  const [selectedConnectionId, setSelectedConnectionId] = useState<string>(wizardState.siemConnectionId || "");
  const [transientApiKey, setTransientApiKey] = useState<string>("");
  const [transientPassword, setTransientPassword] = useState<string>("");
  const [transientUsername, setTransientUsername] = useState<string>("");
  const [testingConnection, setTestingConnection] = useState<boolean>(false);
  const [testResult, setTestResult] = useState<SIEMConnectionTestResponse | null>(null);
  const [savingConnection, setSavingConnection] = useState<boolean>(false);

  useEffect(() => {
    if (mode === "siem" && currentCaseId) {
      api.listSIEMConnections(currentCaseId)
        .then((conns) => {
          setSiemConnections(conns);
          if (conns.length > 0 && !selectedConnectionId) {
            setSelectedConnectionId(conns[0].connection_id);
            updateWizardState({
              siemConnectionId: conns[0].connection_id,
              siemType: conns[0].siem_type,
              siemUrl: conns[0].endpoint_url,
              siemIndex: conns[0].index_pattern || "",
            });
          }
        })
        .catch((e) => console.warn("Failed to load SIEM connections:", e));
    }
  }, [mode, currentCaseId]);

  const handleSaveConnection = async () => {
    setSavingConnection(true);
    setError(null);
    try {
      if (selectedConnectionId && selectedConnectionId !== "new") {
        await api.updateSIEMConnection(selectedConnectionId, {
          siem_type: siemType,
          endpoint_url: siemUrl,
          index_pattern: siemIndex,
          username: transientUsername || undefined,
          password: transientPassword || undefined,
          api_key: transientApiKey || undefined,
        });
        setTransientPassword("");
        setTransientApiKey("");
        const refreshed = await api.listSIEMConnections(currentCaseId);
        setSiemConnections(refreshed);
      } else {
        const created = await api.createSIEMConnection({
          case_id: currentCaseId,
          siem_type: siemType,
          endpoint_url: siemUrl,
          index_pattern: siemIndex,
          username: transientUsername || undefined,
          password: transientPassword || undefined,
          api_key: transientApiKey || undefined,
        });
        setTransientPassword("");
        setTransientApiKey("");
        setSelectedConnectionId(created.connection_id);
        updateWizardState({ siemConnectionId: created.connection_id });
        const refreshed = await api.listSIEMConnections(currentCaseId);
        setSiemConnections(refreshed);
      }
    } catch (err: any) {
      setError(err.message || "Failed to save SIEM connection.");
    } finally {
      setSavingConnection(false);
    }
  };

  const handleTestConnection = async () => {
    if (!selectedConnectionId || selectedConnectionId === "new") {
      setError("Please save the connection first to test reachability.");
      return;
    }
    setTestingConnection(true);
    setTestResult(null);
    try {
      const res = await api.testSIEMConnection(selectedConnectionId);
      setTestResult(res);
    } catch (err: any) {
      setError(err.message || "Connection test failed.");
    } finally {
      setTestingConnection(false);
    }
  };

  const handleClearCredentials = async () => {
    if (selectedConnectionId && selectedConnectionId !== "new") {
      try {
        await api.updateSIEMConnection(selectedConnectionId, {
          clear_credentials: true,
        });
        const refreshed = await api.listSIEMConnections(currentCaseId);
        setSiemConnections(refreshed);
        setTestResult(null);
      } catch (err: any) {
        setError(err.message || "Failed to clear credentials.");
      }
    }
    setTransientPassword("");
    setTransientApiKey("");
  };

  // Intake Result States
  const ingestedArtifacts = wizardState.ingestedArtifacts || [];
  const setIngestedArtifacts = (arts: ArtifactRecord[]) => updateWizardState({ ingestedArtifacts: arts });

  const indexedFindingsCount = wizardState.indexedFindingsCount || 0;
  const setIndexedFindingsCount = (cnt: number) => updateWizardState({ indexedFindingsCount: cnt });

  const recentCustody = wizardState.recentCustody || [];
  const setRecentCustody = (cust: CustodyChainEntry[]) => updateWizardState({ recentCustody: cust });

  // Step 2 Submission & Intake Trigger
  const handlePerformIntake = async () => {
    setLoading(true);
    setError(null);

    try {
      if (mode === "offline") {
        if (!offlinePath.trim()) {
          throw new Error("Please upload an evidence file, browse local disk, or select one of the sample attack files below.");
        }
        const finalPath = isZeroCopy ? `${offlinePath.trim()}:ro` : offlinePath.trim();
        const res = await api.intakeOffline({
          case_id: currentCaseId,
          evidence_path: finalPath,
          artifact_type: artifactType,
          acquisition_method: isZeroCopy ? "zero_copy_reference" : "offline_upload",
          auto_index: autoIndex,
        });
        setIngestedArtifacts(res.artifacts);
        setIndexedFindingsCount(res.findings_indexed_count);
        setRecentCustody(res.custody_entries);
      } else if (mode === "siem") {
        if (selectedConnectionId && selectedConnectionId !== "new") {
          const res = await api.intakeSIEM({
            case_id: currentCaseId,
            connection_id: selectedConnectionId,
            query: siemQuery,
            limit: 100,
          });
          setIndexedFindingsCount(res.findings_count);
        } else {
          const res = await api.intakeSIEM({
            case_id: currentCaseId,
            config: {
              siem_type: siemType,
              endpoint_url: siemUrl,
              api_key: transientApiKey || undefined,
              password: transientPassword || undefined,
              username: transientUsername || undefined,
              index_pattern: siemIndex,
            },
            query: siemQuery,
            limit: 100,
          });
          setIndexedFindingsCount(res.findings_count);
        }
      }

      // Refresh global custody status
      const custodyRes = await api.getCustodyLedger(currentCaseId);
      setCustodyEntries(custodyRes.entries, custodyRes.is_tamper_free);

      setStep(3);
    } catch (err: any) {
      setError(err.message || "Evidence intake failed. Check input parameters.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-5xl mx-auto p-8">
      {/* Wizard Header & Stepper */}
      <div className="mb-8">
        <h1 className="text-2xl font-bold tracking-tight text-white flex items-center space-x-3">
          <ShieldCheck className="w-7 h-7 text-cyan-400" />
          <span>3-Mode Forensic Environment Intake Wizard</span>
        </h1>
        <p className="text-sm text-gray-400 mt-1">
          NIST SP 800-86 & RFC 3227 compliant evidence acquisition, dual-hash verification, and
          cryptographic custody initialization.
        </p>

        {/* Stepper Indicator & Session Status */}
        <div className="flex items-center justify-between mt-6">
          <div className="flex items-center space-x-4">
            <div
              className={`flex items-center space-x-2 px-3 py-1.5 rounded-lg text-xs font-mono font-medium ${
                step >= 1
                  ? "bg-cyan-950/80 border border-cyan-700/80 text-cyan-300"
                  : "bg-gray-800 text-gray-400"
              }`}
            >
              <span className="w-5 h-5 rounded-full bg-cyan-800 flex items-center justify-center text-[10px]">
                1
              </span>
              <span>Intake Mode</span>
            </div>

            <div className="w-8 h-px bg-gray-700" />

            <div
              className={`flex items-center space-x-2 px-3 py-1.5 rounded-lg text-xs font-mono font-medium ${
                step >= 2
                  ? "bg-cyan-950/80 border border-cyan-700/80 text-cyan-300"
                  : "bg-gray-800 text-gray-400"
              }`}
            >
              <span className="w-5 h-5 rounded-full bg-cyan-800 flex items-center justify-center text-[10px]">
                2
              </span>
              <span>Source Config</span>
            </div>

            <div className="w-8 h-px bg-gray-700" />

            <div
              className={`flex items-center space-x-2 px-3 py-1.5 rounded-lg text-xs font-mono font-medium ${
                step === 3
                  ? "bg-emerald-950/80 border border-emerald-700/80 text-emerald-300"
                  : step > 3
                  ? "bg-cyan-950/80 border border-cyan-700/80 text-cyan-300"
                  : "bg-gray-800 text-gray-400"
              }`}
            >
              <span className={`w-5 h-5 rounded-full flex items-center justify-center text-[10px] ${step === 3 ? "bg-emerald-800" : "bg-cyan-800"}`}>
                3
              </span>
              <span>Verification & Custody</span>
            </div>

            <div className="w-8 h-px bg-gray-700" />

            <div
              className={`flex items-center space-x-2 px-3 py-1.5 rounded-lg text-xs font-mono font-medium ${
                step === 4
                  ? "bg-indigo-950/80 border border-indigo-700/80 text-indigo-300"
                  : "bg-gray-800 text-gray-400"
              }`}
            >
              <span className={`w-5 h-5 rounded-full flex items-center justify-center text-[10px] ${step === 4 ? "bg-indigo-700 text-white" : "bg-gray-700"}`}>
                4
              </span>
              <span>AI Hypothesis Planner</span>
            </div>
          </div>

          <div className="flex items-center gap-2 px-3 py-1.5 bg-slate-900/90 border border-slate-800 rounded-lg text-[11px] font-mono">
            <div className={`w-2 h-2 rounded-full ${isSavingSession ? "bg-amber-400 animate-ping" : "bg-emerald-400"}`} />
            <span className="text-slate-400">SQLite Session:</span>
            <span className={isSavingSession ? "text-amber-400 font-semibold" : "text-emerald-400 font-semibold"}>
              {isSavingSession ? "Saving..." : "Persistent"}
            </span>
          </div>
        </div>
      </div>

      {error && (
        <div className="mb-6 p-4 rounded-xl bg-rose-950/60 border border-rose-800/80 text-rose-200 text-xs font-mono flex items-start space-x-3">
          <div className="w-2 h-2 rounded-full bg-rose-500 mt-1 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* STEP 1: Select Mode & Configure Forensic AI Engine */}
      {step === 1 && (
        <div className="space-y-8">
          {/* Case Metadata & Context Initialization */}
          <div className="p-6 rounded-2xl bg-[#0d1527] border border-cyan-800/40 shadow-xl shadow-cyan-950/20">
            <div className="flex items-center justify-between mb-4 pb-3 border-b border-gray-800">
              <div className="flex items-center space-x-3">
                <div className="p-2 rounded-xl bg-cyan-950/70 border border-cyan-700/50">
                  <Briefcase className="w-5 h-5 text-cyan-400" />
                </div>
                <div>
                  <h3 className="text-sm font-semibold text-white tracking-wide">
                    Case Initialization & Chain of Custody Metadata
                  </h3>
                  <p className="text-xs text-gray-400">
                    Define the formal case record. All uploaded evidence blobs and AI hypotheses will be permanently anchored to this case ID.
                  </p>
                </div>
              </div>
              <div className="flex items-center space-x-2">
                <span className="text-[10px] font-mono px-2.5 py-1 rounded-md bg-cyan-950/80 border border-cyan-800 text-cyan-300">
                  ID: {caseId}
                </span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950/60 border border-emerald-700/50 text-emerald-400">
                  SQLite Synced
                </span>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div>
                <label className="block text-xs font-mono text-gray-300 mb-1.5 flex items-center space-x-1.5">
                  <Briefcase className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Case Name *</span>
                </label>
                <input
                  type="text"
                  value={wizardState.caseName || ""}
                  onChange={(e) => updateWizardState({ caseName: e.target.value })}
                  placeholder="e.g. Incident-2026-049A"
                  className="w-full px-3 py-2 text-xs font-mono bg-[#111827] border border-gray-700 rounded-xl text-white placeholder-gray-500 focus:outline-none focus:border-cyan-500 transition-colors"
                />
              </div>

              <div>
                <label className="block text-xs font-mono text-gray-300 mb-1.5 flex items-center space-x-1.5">
                  <Building2 className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Organization / Client</span>
                </label>
                <input
                  type="text"
                  value={wizardState.organizationName || ""}
                  onChange={(e) => updateWizardState({ organizationName: e.target.value })}
                  placeholder="e.g. Global Financial Corp"
                  className="w-full px-3 py-2 text-xs font-mono bg-[#111827] border border-gray-700 rounded-xl text-white placeholder-gray-500 focus:outline-none focus:border-cyan-500 transition-colors"
                />
              </div>

              <div>
                <label className="block text-xs font-mono text-gray-300 mb-1.5 flex items-center space-x-1.5">
                  <ShieldCheck className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Case Lifecycle Status</span>
                </label>
                <select
                  value={wizardState.caseStatus || "OPEN"}
                  onChange={(e) => updateWizardState({ caseStatus: e.target.value as any })}
                  className="w-full px-3 py-2 text-xs font-mono bg-[#111827] border border-gray-700 rounded-xl text-cyan-300 focus:outline-none focus:border-cyan-500 transition-colors"
                >
                  <option value="OPEN">OPEN (Active Investigation)</option>
                  <option value="IN_REVIEW">IN_REVIEW (Peer Validation)</option>
                  <option value="COMPLETED">COMPLETED (Archived & Closed)</option>
                </select>
              </div>
            </div>

            <div className="mt-4">
              <label className="block text-xs font-mono text-gray-300 mb-1.5 flex items-center space-x-1.5">
                <Target className="w-3.5 h-3.5 text-cyan-400" />
                <span>Primary Investigation Goal & Scope</span>
              </label>
              <input
                type="text"
                value={wizardState.investigationGoal || ""}
                onChange={(e) => updateWizardState({ investigationGoal: e.target.value })}
                placeholder="e.g. Determine whether domain controller DC01 was compromised via Pass-the-Hash or lateral movement."
                className="w-full px-3 py-2 text-xs bg-[#111827] border border-gray-700 rounded-xl text-white placeholder-gray-500 focus:outline-none focus:border-cyan-500 transition-colors"
              />
            </div>
          </div>

          <div>
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs font-mono font-semibold text-gray-300 uppercase tracking-wider">
                1. Select Evidence Ingestion Mode
              </span>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {/* Card 1: Offline Evidence */}
              <div
                onClick={() => setMode("offline")}
                className={`cursor-pointer p-6 rounded-2xl border transition-all duration-200 ${
                  mode === "offline"
                    ? "bg-cyan-950/40 border-cyan-500 shadow-xl shadow-cyan-500/10 scale-[1.02]"
                    : "bg-[#111827] border-gray-800 hover:border-gray-700 hover:bg-gray-800/40"
                }`}
              >
                <div className="w-12 h-12 rounded-xl bg-cyan-950/70 border border-cyan-800 flex items-center justify-center mb-4">
                  <HardDrive className="w-6 h-6 text-cyan-400" />
                </div>
                <h3 className="text-base font-semibold text-white">Mode 1: Offline Evidence</h3>
                <p className="text-xs text-gray-400 mt-2 leading-relaxed">
                  Accepts disk images (.E01, .vmdk) with zero-copy read-only (:ro) reference,
                  collector capsules (.zip), or raw artifact hives (.evtx, Registry, memory dumps).
                </p>
                <div className="mt-4 flex flex-wrap gap-1.5">
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-900/40 border border-cyan-700/50 text-cyan-300">
                    Zero-Copy :ro
                  </span>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-900/40 border border-cyan-700/50 text-cyan-300">
                    Streaming Zip Guard
                  </span>
                </div>
              </div>

              {/* Card 2: Hybrid SIEM */}
              <div
                onClick={() => setMode("siem")}
                className={`cursor-pointer p-6 rounded-2xl border transition-all duration-200 ${
                  mode === "siem"
                    ? "bg-cyan-950/40 border-cyan-500 shadow-xl shadow-cyan-500/10 scale-[1.02]"
                    : "bg-[#111827] border-gray-800 hover:border-gray-700 hover:bg-gray-800/40"
                }`}
              >
                <div className="w-12 h-12 rounded-xl bg-cyan-950/70 border border-cyan-800 flex items-center justify-center mb-4">
                  <Server className="w-6 h-6 text-cyan-400" />
                </div>
                <h3 className="text-base font-semibold text-white">Mode 2: Hybrid SIEM</h3>
                <p className="text-xs text-gray-400 mt-2 leading-relaxed">
                  Read-only live query ingestion for Elasticsearch, Wazuh EDR, and Splunk Enterprise.
                  Stores query snapshots with SHA-256 hashes in custody ledger.
                </p>
                <div className="mt-4 flex flex-wrap gap-1.5">
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-900/40 border border-cyan-700/50 text-cyan-300">
                    Read-Only AST
                  </span>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-900/40 border border-cyan-700/50 text-cyan-300">
                    Snapshot Hashed
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* Forensic AI Reasoning Engine (LLM Registry) */}
          <div className="bg-[#111827] border border-gray-800 rounded-2xl p-6 shadow-xl">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-gray-800 gap-3">
              <div className="flex items-center space-x-3">
                <div className="w-10 h-10 rounded-xl bg-cyan-950/80 border border-cyan-700/80 flex items-center justify-center text-cyan-400 shrink-0">
                  <Cpu className="w-5 h-5" />
                </div>
                <div>
                  <div className="flex items-center space-x-2.5">
                    <h3 className="text-sm font-bold text-white tracking-wide">
                      2. Forensic AI Reasoning Engine
                    </h3>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-900/40 border border-cyan-700/50 text-cyan-300 font-medium">
                      Multi-Provider Dynamic Router
                    </span>
                  </div>
                  <p className="text-xs text-gray-400 mt-0.5 font-mono">
                    Select and test the underlying LLM engine for forensic hypothesis synthesis and claim verification.
                  </p>
                </div>
              </div>
              <div className="flex items-center space-x-2 text-xs font-mono bg-gray-900/90 px-3 py-1.5 rounded-lg border border-gray-800 shrink-0">
                <span className="text-gray-400">Active Engine:</span>
                <span className="font-bold text-cyan-400">{activeProviderId}</span>
              </div>
            </div>

            {/* Provider List Table / Rows */}
            <div className="mt-4 divide-y divide-gray-800/60">
              {providersLoading ? (
                <div className="py-8 text-center text-xs font-mono text-gray-500 flex items-center justify-center space-x-2">
                  <RefreshCw className="w-4 h-4 animate-spin text-cyan-400" />
                  <span>Loading model provider registry...</span>
                </div>
              ) : providers.length === 0 ? (
                <div className="py-6 text-center text-xs font-mono text-gray-500">
                  No providers discovered in backend registry.
                </div>
              ) : (
                providers.map((p) => {
                  const isSelected = p.provider_id === activeProviderId;
                  const isTesting = !!testingProviders[p.provider_id];
                  const testResult = smokeTestResults[p.provider_id];

                  return (
                    <div
                      key={p.provider_id}
                      onClick={() => handleSelectProvider(p.provider_id)}
                      className={`py-3.5 px-4 rounded-xl flex flex-col md:flex-row md:items-center justify-between gap-3 transition-all duration-150 cursor-pointer ${
                        isSelected
                          ? "bg-cyan-950/30 border border-cyan-800/80 shadow-md shadow-cyan-950/20"
                          : "hover:bg-gray-800/40 border border-transparent"
                      }`}
                    >
                      {/* Left: Radio + Inline Test Button + Model Info */}
                      <div className="flex items-center space-x-3.5 min-w-0">
                        <input
                          type="radio"
                          name="forensic_llm_provider"
                          checked={isSelected}
                          onChange={() => handleSelectProvider(p.provider_id)}
                          className="w-4 h-4 text-cyan-500 bg-gray-900 border-gray-700 focus:ring-cyan-500 focus:ring-offset-gray-900 cursor-pointer shrink-0"
                        />
                        {/* Inline Test Connection Button in front of model name */}
                        <button
                          type="button"
                          onClick={(e) => handleSmokeTest(p.provider_id, e)}
                          disabled={isTesting}
                          className="px-2.5 py-1 rounded-md bg-gray-800/90 hover:bg-gray-700 active:bg-gray-900 border border-gray-700 text-[11px] font-mono text-gray-200 flex items-center space-x-1.5 transition-all shadow-sm hover:border-cyan-700/70 disabled:opacity-50 shrink-0"
                        >
                          {isTesting ? (
                            <>
                              <RefreshCw className="w-3 h-3 text-cyan-400 animate-spin" />
                              <span>Testing...</span>
                            </>
                          ) : (
                            <>
                              <Sparkles className="w-3 h-3 text-cyan-400" />
                              <span>Test Connection</span>
                            </>
                          )}
                        </button>
                        <div className="min-w-0">
                          <div className="flex items-center space-x-2.5 flex-wrap gap-y-1">
                            <span className="text-xs font-semibold text-white tracking-tight">
                              {p.label}
                            </span>
                            <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-gray-900 border border-gray-700/80 text-cyan-300">
                              {p.model_name}
                            </span>
                            {/* Local / Offline vs External Cloud Badge */}
                            {p.is_local ? (
                              <span className="text-[10px] font-mono font-medium px-2 py-0.5 rounded-full bg-emerald-950/90 border border-emerald-700/80 text-emerald-400 flex items-center space-x-1">
                                <Shield className="w-2.5 h-2.5" />
                                <span>LOCAL / OFFLINE</span>
                              </span>
                            ) : (
                              <span className="text-[10px] font-mono font-medium px-2 py-0.5 rounded-full bg-sky-950/90 border border-sky-700/80 text-sky-400 flex items-center space-x-1">
                                <Globe className="w-2.5 h-2.5" />
                                <span>EXTERNAL CLOUD</span>
                              </span>
                            )}
                          </div>
                          <p className="text-[11px] text-gray-500 font-mono mt-0.5 truncate">
                            Endpoint: {p.base_url}
                          </p>
                        </div>
                      </div>

                      {/* Right: Inline Test Result Feedback */}
                      {testResult && (
                        <div className="flex items-center space-x-2 shrink-0 self-start md:self-center">
                          {testResult.success ? (
                            <span
                              title={testResult.response_preview ? `Last response: "${testResult.response_preview}"` : "Model connected successfully"}
                              className="px-2.5 py-1 rounded-lg bg-emerald-950/90 border border-emerald-700 text-emerald-300 text-xs font-mono flex items-center space-x-1.5 shadow-sm cursor-help"
                            >
                              <Check className="w-3.5 h-3.5 text-emerald-400" />
                              <span>Connected • {testResult.latency_ms}ms</span>
                            </span>
                          ) : (
                            <span
                              title={testResult.error_detail || "Connection Failed"}
                              className="px-2.5 py-1 rounded-lg bg-rose-950/90 border border-rose-800 text-rose-300 text-xs font-mono flex items-center space-x-1.5 shadow-sm max-w-[280px] truncate"
                            >
                              <AlertCircle className="w-3.5 h-3.5 text-rose-400 shrink-0" />
                              <span className="truncate">
                                {testResult.error_detail || "Connection Failed"}
                              </span>
                            </span>
                          )}
                        </div>
                      )}
                    </div>
                  );
                })
              )}
            </div>
          </div>
        </div>
      )}

      {/* STEP 2: Configure Selected Mode */}
      {step === 2 && (
        <div className="bg-[#111827] border border-gray-800 rounded-2xl p-6 shadow-xl">
          {mode === "offline" && (
            <div className="space-y-5">
              <h3 className="text-sm font-semibold text-white uppercase tracking-wider text-cyan-400 font-mono">
                Configure Offline Evidence Intake
              </h3>

              <div>
                <label className="block text-xs font-medium text-gray-300 mb-1.5 flex items-center justify-between">
                  <span>File Path / Evidence Image Path</span>
                  <span className="text-[11px] font-mono text-cyan-400/80">
                    Supports .evtx, .pcap, .dmp, .raw, .E01, .json, .zip, .log
                  </span>
                </label>

                {/* Hidden File Input for browser selection */}
                <input
                  type="file"
                  ref={fileInputRef}
                  onChange={handleFileChange}
                  className="hidden"
                  accept=".evtx,.pcap,.pcapng,.dmp,.raw,.lime,.vmem,.E01,.vmdk,.dd,.img,.zip,.tar,.gz,.json,.log,.txt"
                />

                {/* Drag-and-Drop Area & Input Row */}
                <div
                  onDragOver={handleDragOver}
                  onDragLeave={handleDragLeave}
                  onDrop={handleDrop}
                  className={`relative flex items-center space-x-2 p-1.5 rounded-xl border transition-all duration-200 ${
                    isDragging
                      ? "border-cyan-400 bg-cyan-950/40 ring-2 ring-cyan-500/30"
                      : "border-gray-700 bg-[#161f30] hover:border-gray-600"
                  }`}
                >
                  <input
                    type="text"
                    value={offlinePath}
                    onChange={(e) => setOfflinePath(e.target.value)}
                    className="flex-1 bg-transparent border-none px-3 py-1.5 text-xs font-mono text-white focus:outline-none"
                    placeholder="e.g. C:\evidence\disk.E01 or drag & drop evidence file here"
                  />

                  {/* Browse / Upload Button */}
                  {isZeroCopy ? (
                    <button
                      type="button"
                      onClick={() => handleOpenLocalBrowser(offlinePath)}
                      className="px-3.5 py-2 bg-gradient-to-r from-cyan-900/80 to-blue-900/80 hover:from-cyan-800 hover:to-blue-800 rounded-lg text-xs font-mono font-medium text-cyan-200 border border-cyan-700/70 flex items-center space-x-1.5 shadow-sm transition-all shrink-0"
                    >
                      <FolderOpen className="w-3.5 h-3.5 text-cyan-300" />
                      <span>Browse Local Disk...</span>
                    </button>
                  ) : (
                    <button
                      type="button"
                      onClick={() => fileInputRef.current?.click()}
                      disabled={uploading}
                      className="px-3.5 py-2 bg-cyan-600 hover:bg-cyan-500 active:bg-cyan-700 disabled:opacity-50 rounded-lg text-xs font-mono font-medium text-white flex items-center space-x-1.5 shadow-md shadow-cyan-950/40 transition-all shrink-0"
                    >
                      {uploading ? (
                        <>
                          <RefreshCw className="w-3.5 h-3.5 text-white animate-spin" />
                          <span>Streaming (1MB chunks)...</span>
                        </>
                      ) : (
                        <>
                          <Upload className="w-3.5 h-3.5 text-white" />
                          <span>Browse File...</span>
                        </>
                      )}
                    </button>
                  )}
                </div>

                {uploadError && (
                  <p className="text-[11px] font-mono text-rose-400 mt-1.5 flex items-center space-x-1">
                    <AlertCircle className="w-3.5 h-3.5 shrink-0" />
                    <span>{uploadError}</span>
                  </p>
                )}

                {/* Drag and Drop Hint */}
                <p className="text-[10px] text-gray-500 font-mono mt-1">
                  Drag & drop your artifact file directly into the input or click Browse.
                </p>

                {/* Quick-Load Sample Attack Scenarios */}
                <div className="mt-3 p-3 rounded-xl bg-[#0f172a] border border-cyan-900/60">
                  <div className="flex items-center space-x-2 mb-2">
                    <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
                    <span className="text-[11px] font-mono text-cyan-300 font-semibold">
                      Load Sample Attack Artifacts (from sample/ folder):
                    </span>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    <button
                      type="button"
                      onClick={() => {
                        setOfflinePath("sample/Credential Access/babyshark_mimikatz_powershell.evtx");
                        setArtifactType("evtx");
                      }}
                      className="px-2.5 py-1.5 rounded-lg bg-cyan-950/70 hover:bg-cyan-900 border border-cyan-700/60 text-xs font-mono text-cyan-200 transition-colors flex items-center space-x-1.5"
                    >
                      <span>🔑 Credential Access (BabyShark Mimikatz LSASS)</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        setOfflinePath("sample/Lateral Movement/LM_wmiexec_impacket_sysmon_whoami.evtx");
                        setArtifactType("evtx");
                      }}
                      className="px-2.5 py-1.5 rounded-lg bg-cyan-950/70 hover:bg-cyan-900 border border-cyan-700/60 text-xs font-mono text-cyan-200 transition-colors flex items-center space-x-1.5"
                    >
                      <span>🚀 Lateral Movement (WMIexec Whoami)</span>
                    </button>
                  </div>
                </div>

                {/* Uploaded Artifact Forensic Verification Card */}
                {uploadedMetadata ? (
                  <div className="mt-3 p-3.5 rounded-xl bg-gray-900/90 border border-cyan-800/60 shadow-lg">
                    <div className="flex items-center justify-between pb-2 border-b border-gray-800">
                      <div className="flex items-center space-x-2">
                        <FileCheck className="w-4 h-4 text-emerald-400" />
                        <span className="text-xs font-mono font-semibold text-white">
                          {uploadedMetadata.filename}
                        </span>
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-gray-800 text-gray-300 border border-gray-700">
                          {(uploadedMetadata.size_bytes / (1024 * 1024)).toFixed(2)} MB
                        </span>
                      </div>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-emerald-950 border border-emerald-700 text-emerald-400 flex items-center space-x-1">
                        <Check className="w-3 h-3" />
                        <span>Streamed & Read-Only (0400)</span>
                      </span>
                    </div>

                    <div className="mt-2.5 space-y-1.5 text-[11px] font-mono">
                      <div className="flex items-center justify-between bg-black/40 px-2.5 py-1 rounded border border-gray-800">
                        <div className="flex items-center space-x-2 truncate">
                          <span className="text-gray-500 shrink-0">SHA-256:</span>
                          <span className="text-cyan-300 truncate select-all">
                            {uploadedMetadata.sha256}
                          </span>
                        </div>
                        <button
                          type="button"
                          onClick={() => copyToClipboard(uploadedMetadata.sha256, "sha256")}
                          className="ml-2 text-gray-400 hover:text-white p-0.5 shrink-0"
                          title="Copy SHA-256"
                        >
                          {copiedHash === "sha256" ? (
                            <CheckCheck className="w-3.5 h-3.5 text-emerald-400" />
                          ) : (
                            <Copy className="w-3.5 h-3.5" />
                          )}
                        </button>
                      </div>

                      <div className="flex items-center justify-between bg-black/40 px-2.5 py-1 rounded border border-gray-800">
                        <div className="flex items-center space-x-2 truncate">
                          <span className="text-gray-500 shrink-0">SHA-512:</span>
                          <span className="text-gray-400 truncate select-all">
                            {uploadedMetadata.sha512}
                          </span>
                        </div>
                        <button
                          type="button"
                          onClick={() => copyToClipboard(uploadedMetadata.sha512, "sha512")}
                          className="ml-2 text-gray-400 hover:text-white p-0.5 shrink-0"
                          title="Copy SHA-512"
                        >
                          {copiedHash === "sha512" ? (
                            <CheckCheck className="w-3.5 h-3.5 text-emerald-400" />
                          ) : (
                            <Copy className="w-3.5 h-3.5" />
                          )}
                        </button>
                      </div>
                    </div>

                    {/* Direct Intake CTA */}
                    <div className="mt-3 pt-2.5 border-t border-gray-800 flex items-center justify-between">
                      <span className="text-[11px] font-mono text-emerald-400 flex items-center gap-1.5">
                        <CheckCircle className="w-3.5 h-3.5" />
                        <span>File uploaded and ready for cryptographic intake</span>
                      </span>
                      <button
                        type="button"
                        onClick={handlePerformIntake}
                        disabled={loading}
                        className="px-4 py-1.5 bg-gradient-to-r from-emerald-600 to-teal-500 hover:from-emerald-500 hover:to-teal-400 text-white font-mono text-xs font-bold rounded-lg shadow-md flex items-center space-x-1.5 disabled:opacity-50"
                      >
                        {loading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5 fill-current" />}
                        <span>Execute Intake Now ➔</span>
                      </button>
                    </div>
                  </div>
                ) : offlinePath.trim() ? (
                  <div className="mt-3 p-3.5 rounded-xl bg-gray-900/90 border border-emerald-800/60 shadow-lg">
                    <div className="flex items-center justify-between pb-2 border-b border-gray-800">
                      <div className="flex items-center space-x-2">
                        <FileCheck className="w-4 h-4 text-emerald-400" />
                        <span className="text-xs font-mono font-semibold text-white">
                          {offlinePath.split(/[\/\\]/).pop()}
                        </span>
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800">
                          {artifactType.toUpperCase()}
                        </span>
                      </div>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-emerald-950 border border-emerald-700 text-emerald-400 flex items-center space-x-1">
                        <Check className="w-3 h-3" />
                        <span>Ready for Intake</span>
                      </span>
                    </div>

                    <div className="mt-2 text-[11px] font-mono text-gray-400 truncate">
                      <span className="text-gray-500">Path: </span>
                      <span className="text-cyan-300">{offlinePath}</span>
                    </div>

                    {/* Direct Intake CTA */}
                    <div className="mt-3 pt-2.5 border-t border-gray-800 flex items-center justify-between">
                      <span className="text-[11px] font-mono text-emerald-400 flex items-center gap-1.5">
                        <CheckCircle className="w-3.5 h-3.5" />
                        <span>Artifact selected and staged for extraction</span>
                      </span>
                      <button
                        type="button"
                        onClick={handlePerformIntake}
                        disabled={loading}
                        className="px-4 py-1.5 bg-gradient-to-r from-emerald-600 to-teal-500 hover:from-emerald-500 hover:to-teal-400 text-white font-mono text-xs font-bold rounded-lg shadow-md flex items-center space-x-1.5 disabled:opacity-50"
                      >
                        {loading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5 fill-current" />}
                        <span>Execute Intake Now ➔</span>
                      </button>
                    </div>
                  </div>
                ) : null}
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-medium text-gray-300 mb-1.5">
                    Artifact Type
                  </label>
                  <select
                    value={artifactType}
                    onChange={(e) => setArtifactType(e.target.value)}
                    className="w-full bg-[#1a2236] border border-gray-700 rounded-lg px-3.5 py-2 text-xs font-mono text-white focus:outline-none focus:border-cyan-500"
                  >
                    <option value="evtx">Windows Event Logs (.evtx)</option>
                    <option value="registry">Windows Registry Hive</option>
                    <option value="memory">Memory Dump (.raw / .lime)</option>
                    <option value="disk_image">Disk Image (.E01 / .vmdk)</option>
                    <option value="capsule">Collector Capsule Archive (.zip)</option>
                  </select>
                </div>

                <div className="flex items-center space-x-6 pt-5">
                  <label className="flex items-center space-x-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={isZeroCopy}
                      onChange={(e) => setIsZeroCopy(e.target.checked)}
                      className="rounded border-gray-700 bg-gray-900 text-cyan-500 focus:ring-0"
                    />
                    <span className="text-xs text-gray-300 font-medium">
                      Zero-Copy Reference (:ro)
                    </span>
                  </label>

                  <label className="flex items-center space-x-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={autoIndex}
                      onChange={(e) => setAutoIndex(e.target.checked)}
                      className="rounded border-gray-700 bg-gray-900 text-cyan-500 focus:ring-0"
                    />
                    <span className="text-xs text-gray-300 font-medium">
                      Auto-Index with Dissect
                    </span>
                  </label>
                </div>
              </div>
            </div>
          )}

          {mode === "siem" && (
            <div className="space-y-5">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-semibold text-white uppercase tracking-wider text-cyan-400 font-mono flex items-center space-x-2">
                  <ShieldCheck className="w-4 h-4 text-cyan-400" />
                  <span>Configure Read-Only SIEM Connector</span>
                </h3>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950 border border-cyan-800 text-cyan-300">
                  SEC-UI-001 Zero-Leakage Credential Store
                </span>
              </div>

              {/* Saved Connection Profile Selector */}
              <div className="p-3.5 rounded-xl bg-[#0f172a] border border-cyan-900/60 space-y-3">
                <div className="flex items-center justify-between">
                  <label className="text-xs font-medium text-cyan-300 font-mono flex items-center space-x-1.5">
                    <Key className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Saved SIEM Connections (Encrypted at Rest)</span>
                  </label>
                  {selectedConnectionId && selectedConnectionId !== "new" && (
                    <button
                      type="button"
                      onClick={handleClearCredentials}
                      className="text-[11px] font-mono text-rose-400 hover:text-rose-300 underline"
                    >
                      Clear Stored Credentials
                    </button>
                  )}
                </div>

                <div className="flex items-center space-x-3">
                  <select
                    value={selectedConnectionId}
                    onChange={(e) => {
                      const cid = e.target.value;
                      setSelectedConnectionId(cid);
                      setTestResult(null);
                      if (cid === "new" || !cid) {
                        updateWizardState({ siemConnectionId: null });
                      } else {
                        const found = siemConnections.find((c) => c.connection_id === cid);
                        if (found) {
                          updateWizardState({
                            siemConnectionId: found.connection_id,
                            siemType: found.siem_type,
                            siemUrl: found.endpoint_url,
                            siemIndex: found.index_pattern || "",
                          });
                        }
                      }
                    }}
                    className="flex-1 bg-[#1a2236] border border-gray-700 rounded-lg px-3 py-2 text-xs font-mono text-white focus:outline-none"
                  >
                    <option value="new">+ Create New Managed SIEM Connection</option>
                    {siemConnections.map((c) => (
                      <option key={c.connection_id} value={c.connection_id}>
                        [{c.siem_type.toUpperCase()}] {c.endpoint_url} {c.has_api_key ? "(API Key)" : c.has_password ? "(Password)" : "(No auth)"}
                      </option>
                    ))}
                  </select>

                  <button
                    type="button"
                    onClick={handleTestConnection}
                    disabled={testingConnection || !selectedConnectionId || selectedConnectionId === "new"}
                    className="px-3.5 py-2 bg-gradient-to-r from-cyan-900/80 to-blue-900/80 hover:from-cyan-800 hover:to-blue-800 disabled:opacity-50 rounded-lg text-xs font-mono font-medium text-cyan-200 border border-cyan-700/70 flex items-center space-x-1.5 transition-all shrink-0"
                  >
                    {testingConnection ? (
                      <RefreshCw className="w-3.5 h-3.5 animate-spin text-cyan-300" />
                    ) : (
                      <CheckCircle className="w-3.5 h-3.5 text-cyan-300" />
                    )}
                    <span>Test Reachability</span>
                  </button>
                </div>

                {/* Connection Status & Credential Presence Badges */}
                {selectedConnectionId && selectedConnectionId !== "new" && (() => {
                  const activeConn = siemConnections.find((c) => c.connection_id === selectedConnectionId);
                  if (!activeConn) return null;
                  return (
                    <div className="flex flex-wrap items-center gap-2 pt-1 text-[11px] font-mono">
                      <span className="text-gray-400">Stored Credentials:</span>
                      {activeConn.has_api_key && (
                        <span className="px-2 py-0.5 rounded bg-emerald-950 border border-emerald-700 text-emerald-300">
                          ✓ API Key Configured (Encrypted)
                        </span>
                      )}
                      {activeConn.has_password && (
                        <span className="px-2 py-0.5 rounded bg-emerald-950 border border-emerald-700 text-emerald-300">
                          ✓ Password Configured (Encrypted)
                        </span>
                      )}
                      {activeConn.has_token && (
                        <span className="px-2 py-0.5 rounded bg-emerald-950 border border-emerald-700 text-emerald-300">
                          ✓ Token Configured (Encrypted)
                        </span>
                      )}
                      {!activeConn.has_api_key && !activeConn.has_password && !activeConn.has_token && (
                        <span className="px-2 py-0.5 rounded bg-gray-800 text-gray-400 border border-gray-700">
                          No credentials stored
                        </span>
                      )}
                    </div>
                  );
                })()}

                {/* Test Connection Result Alert */}
                {testResult && (
                  <div
                    className={`p-2.5 rounded-lg border text-xs font-mono flex items-center space-x-2 ${
                      testResult.status === "success" && testResult.reachable
                        ? "bg-emerald-950/70 border-emerald-700 text-emerald-300"
                        : "bg-rose-950/70 border-rose-700 text-rose-300"
                    }`}
                  >
                    {testResult.status === "success" && testResult.reachable ? (
                      <CheckCircle className="w-4 h-4 text-emerald-400 shrink-0" />
                    ) : (
                      <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
                    )}
                    <span>
                      {testResult.message} ({testResult.latency_ms} ms)
                    </span>
                  </div>
                )}
              </div>

              {/* Endpoint Configuration */}
              <div className="grid grid-cols-3 gap-4">
                <div>
                  <label className="block text-xs font-medium text-gray-300 mb-1.5 font-mono">
                    SIEM Platform
                  </label>
                  <select
                    value={siemType}
                    onChange={(e) => setSiemType(e.target.value as any)}
                    className="w-full bg-[#1a2236] border border-gray-700 rounded-lg px-3 py-2 text-xs font-mono text-white focus:outline-none"
                  >
                    <option value="elasticsearch">Elasticsearch / OpenSearch</option>
                    <option value="wazuh">Wazuh EDR Manager</option>
                    <option value="splunk">Splunk Enterprise</option>
                  </select>
                </div>

                <div className="col-span-2">
                  <label className="block text-xs font-medium text-gray-300 mb-1.5 font-mono">
                    Endpoint URL
                  </label>
                  <input
                    type="text"
                    value={siemUrl}
                    onChange={(e) => setSiemUrl(e.target.value)}
                    placeholder="https://siem.internal:9200"
                    className="w-full bg-[#1a2236] border border-gray-700 rounded-lg px-3 py-2 text-xs font-mono text-white focus:outline-none"
                  />
                </div>
              </div>

              {/* Write-Only Credentials Input Section */}
              <div className="p-3.5 rounded-xl bg-[#141b2d] border border-gray-800 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono font-medium text-gray-300 flex items-center space-x-1.5">
                    <Lock className="w-3.5 h-3.5 text-amber-400" />
                    <span>Set / Update Credentials (Write-Only)</span>
                  </span>
                  <span className="text-[10px] font-mono text-gray-500">
                    Leave blank on update to keep existing stored credentials
                  </span>
                </div>

                <div className="grid grid-cols-3 gap-3">
                  <div>
                    <label className="block text-[11px] font-mono text-gray-400 mb-1">
                      API Key (or Splunk Token)
                    </label>
                    <input
                      type="password"
                      autoComplete="new-password"
                      value={transientApiKey}
                      onChange={(e) => setTransientApiKey(e.target.value)}
                      placeholder={selectedConnectionId && selectedConnectionId !== "new" ? "•••••••• (unchanged)" : "Enter API key"}
                      className="w-full bg-[#1a2236] border border-gray-700 rounded-lg px-3 py-1.5 text-xs font-mono text-white focus:outline-none focus:border-cyan-500"
                    />
                  </div>

                  <div>
                    <label className="block text-[11px] font-mono text-gray-400 mb-1">
                      Username (Optional)
                    </label>
                    <input
                      type="text"
                      value={transientUsername}
                      onChange={(e) => setTransientUsername(e.target.value)}
                      placeholder="e.g. elastic"
                      className="w-full bg-[#1a2236] border border-gray-700 rounded-lg px-3 py-1.5 text-xs font-mono text-white focus:outline-none"
                    />
                  </div>

                  <div>
                    <label className="block text-[11px] font-mono text-gray-400 mb-1">
                      Password (Optional)
                    </label>
                    <input
                      type="password"
                      autoComplete="new-password"
                      value={transientPassword}
                      onChange={(e) => setTransientPassword(e.target.value)}
                      placeholder={selectedConnectionId && selectedConnectionId !== "new" ? "•••••••• (unchanged)" : "Enter password"}
                      className="w-full bg-[#1a2236] border border-gray-700 rounded-lg px-3 py-1.5 text-xs font-mono text-white focus:outline-none focus:border-cyan-500"
                    />
                  </div>
                </div>

                <div className="flex items-center justify-end space-x-2 pt-1">
                  <button
                    type="button"
                    onClick={handleSaveConnection}
                    disabled={savingConnection}
                    className="px-3.5 py-1.5 bg-cyan-700 hover:bg-cyan-600 disabled:opacity-50 text-white rounded-lg text-xs font-mono flex items-center space-x-1.5 transition-colors"
                  >
                    {savingConnection ? (
                      <RefreshCw className="w-3 h-3 animate-spin" />
                    ) : (
                      <Lock className="w-3 h-3" />
                    )}
                    <span>Save / Update Encrypted Credentials</span>
                  </button>
                </div>
              </div>

              {/* Index & Query */}
              <div className="grid grid-cols-3 gap-4">
                <div>
                  <label className="block text-xs font-medium text-gray-300 mb-1.5 font-mono">
                    Index Pattern / Sourcetype
                  </label>
                  <input
                    type="text"
                    value={siemIndex}
                    onChange={(e) => setSiemIndex(e.target.value)}
                    placeholder="winlogbeat-* or index=main"
                    className="w-full bg-[#1a2236] border border-gray-700 rounded-lg px-3 py-2 text-xs font-mono text-white focus:outline-none"
                  />
                </div>

                <div className="col-span-2">
                  <label className="block text-xs font-medium text-gray-300 mb-1.5 font-mono">
                    Read-Only Query / SPL
                  </label>
                  <textarea
                    value={siemQuery}
                    onChange={(e) => setSiemQuery(e.target.value)}
                    rows={2}
                    className="w-full bg-[#1a2236] border border-gray-700 rounded-lg p-2.5 text-xs font-mono text-white focus:outline-none focus:border-cyan-500"
                  />
                  <p className="text-[10px] text-gray-500 mt-0.5 font-mono">
                    * Mutating operators (_delete, delete, outputcsv) are blocked at the AST safety layer.
                  </p>
                </div>
              </div>

              {/* Direct Intake CTA */}
              <div className="pt-2 flex items-center justify-between border-t border-gray-800">
                <span className="text-[11px] font-mono text-cyan-300 flex items-center gap-1.5">
                  <CheckCircle className="w-3.5 h-3.5 text-cyan-400" />
                  <span>SIEM query configured with safe read-only pinning</span>
                </span>
                <button
                  type="button"
                  onClick={handlePerformIntake}
                  disabled={loading}
                  className="px-4 py-1.5 bg-gradient-to-r from-emerald-600 to-teal-500 hover:from-emerald-500 hover:to-teal-400 text-white font-mono text-xs font-bold rounded-lg shadow-md flex items-center space-x-1.5 disabled:opacity-50"
                >
                  {loading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5 fill-current" />}
                  <span>Execute SIEM Intake Now ➔</span>
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* STEP 3: Verification & Chain of Custody */}
      {step === 3 && (
        <div className="space-y-6">
          <div className="bg-[#111827] border border-gray-800 rounded-2xl p-6 shadow-xl">
            <div className="flex items-center justify-between pb-4 border-b border-gray-800">
              <div className="flex items-center space-x-2 text-emerald-400 font-mono text-sm font-semibold">
                <CheckCircle className="w-5 h-5 text-emerald-400" />
                <span>Evidence Successfully Ingested & Verified</span>
              </div>
              <span className="text-xs font-mono bg-emerald-950 text-emerald-300 px-2.5 py-1 rounded-full border border-emerald-800">
                {indexedFindingsCount} Findings Indexed
              </span>
            </div>

            {/* Ingested Artifacts Table */}
            <div className="mt-5 overflow-x-auto">
              <span className="text-xs font-mono text-gray-400 uppercase tracking-wide">
                Dual Cryptographic Hash Verification Table
              </span>
              <table className="w-full mt-2 text-left text-xs font-mono">
                <thead>
                  <tr className="border-b border-gray-800 text-gray-400">
                    <th className="pb-2">Artifact ID</th>
                    <th className="pb-2">Type</th>
                    <th className="pb-2">SHA-256 Hash</th>
                    <th className="pb-2">Vault Location</th>
                    <th className="pb-2">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-800/60 text-gray-300">
                  {ingestedArtifacts.length > 0 ? (
                    ingestedArtifacts.map((art) => (
                      <tr key={art.artifact_id} className="hover:bg-gray-800/30">
                        <td className="py-2.5 text-cyan-400 font-semibold">
                          {art.artifact_id.substring(0, 12)}...
                        </td>
                        <td className="py-2.5">{art.type}</td>
                        <td className="py-2.5 text-gray-300">
                          {art.sha256.substring(0, 16)}...
                        </td>
                        <td className="py-2.5 text-gray-400">{art.blob_path}</td>
                        <td className="py-2.5">
                          <span className="px-2 py-0.5 rounded bg-emerald-950 border border-emerald-800 text-emerald-400 text-[10px]">
                            0400 Read-Only
                          </span>
                        </td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan={5} className="py-4 text-center text-gray-500">
                        SIEM Query Findings snapshot stored directly in DuckDB ledger.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>

            {/* Next Steps actions */}
            <div className="mt-8 pt-5 border-t border-gray-800 flex items-center justify-between">
              <button
                onClick={() => setStep(1)}
                className="px-4 py-2 bg-gray-800 hover:bg-gray-700 text-xs font-mono text-gray-300 rounded-lg"
              >
                Intake Additional Evidence
              </button>

              <div className="flex items-center space-x-3">
                <button
                  onClick={() => setActiveTab("canvas")}
                  className="px-4 py-2 text-xs font-mono text-gray-400 hover:text-white transition-colors"
                >
                  Skip to Workflow Canvas
                </button>
                <button
                  onClick={() => {
                    setStep(4);
                    if (!hypothesisDraft) {
                      handleGenerateHypothesis();
                    }
                  }}
                  className="px-6 py-2.5 bg-gradient-to-r from-cyan-500 to-indigo-600 hover:from-cyan-400 hover:to-indigo-500 text-white font-mono text-xs font-bold rounded-lg shadow-lg shadow-cyan-500/20 flex items-center space-x-2"
                >
                  <Sparkles className="w-4 h-4 text-cyan-200" />
                  <span>Proceed to AI Hypothesis Planner</span>
                  <ArrowRight className="w-4 h-4" />
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Step 4: Investigation Goal & AI Hypothesis Planner */}
      {step === 4 && (
        <div className="space-y-6">
          <div className="bg-[#111827] border border-indigo-900/60 rounded-xl p-6 shadow-2xl relative overflow-hidden">
            <div className="absolute top-0 right-0 w-96 h-96 bg-indigo-600/5 rounded-full blur-3xl pointer-events-none" />

            {/* Step 4 Header */}
            <div className="flex items-center justify-between pb-5 border-b border-gray-800/80">
              <div className="flex items-center space-x-3">
                <div className="w-10 h-10 rounded-lg bg-indigo-950/80 border border-indigo-700/60 flex items-center justify-center text-indigo-400">
                  <Compass className="w-5 h-5" />
                </div>
                <div>
                  <h2 className="text-base font-bold text-white font-mono flex items-center gap-2">
                    <span>Step 4: Investigation Goal & AI Hypothesis Planner</span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-indigo-950 border border-indigo-800 text-indigo-300">
                      Phase 8
                    </span>
                  </h2>
                  <p className="text-xs text-gray-400 mt-0.5">
                    Deterministic evidence facts are fed to LLM with prompt-injection defense to formulate dual hypotheses and a tailored DAG execution plan.
                  </p>
                </div>
              </div>

              <div className="flex items-center space-x-2 text-[11px] font-mono bg-gray-900/90 border border-gray-800 px-3 py-1.5 rounded-lg text-gray-400">
                <Cpu className="w-3.5 h-3.5 text-cyan-400" />
                <span>LLM Engine:</span>
                <span className="text-cyan-300 font-semibold">{activeProviderId}</span>
              </div>
            </div>

            {/* Investigation Goal Formulation */}
            <div className="mt-6 space-y-4">
              <div>
                <label className="block text-xs font-mono font-medium text-gray-300 mb-1.5 flex items-center justify-between">
                  <span className="flex items-center gap-1.5">
                    <Lightbulb className="w-4 h-4 text-amber-400" />
                    <span>Investigation Objective or Hypothesis Query:</span>
                  </span>
                  <span className="text-[10px] text-gray-500 font-normal">
                    Plain-language question or threat hunter hypothesis
                  </span>
                </label>

                <textarea
                  value={investigationGoal}
                  onChange={(e) => setInvestigationGoal(e.target.value)}
                  rows={3}
                  placeholder="e.g., Investigate potential lateral movement and unauthorized PsExec/WMI execution across Windows endpoints..."
                  className="w-full bg-[#161f30] border border-gray-700 rounded-lg p-3 text-xs font-mono text-cyan-200 placeholder-gray-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-colors"
                />
              </div>

              {/* Goal Presets */}
              <div className="space-y-1.5">
                <span className="text-[11px] font-mono text-gray-400">Quick Investigative Presets:</span>
                <div className="flex flex-wrap gap-2">
                  {[
                    {
                      label: "Lateral Movement & WMI",
                      goal: "Investigate potential lateral movement and abnormal PsExec/WMI activity across the network.",
                    },
                    {
                      label: "LSASS Credential Access",
                      goal: "Investigate LSASS memory access, credential dumping, and pass-the-hash indicators.",
                    },
                    {
                      label: "Persistence Mechanisms",
                      goal: "Detect persistence mechanisms via scheduled tasks, registry run keys, or rogue services.",
                    },
                    {
                      label: "C2 & Exfiltration Hunt",
                      goal: "Identify command-and-control beacons, DNS tunneling, and outbound data exfiltration.",
                    },
                  ].map((preset) => (
                    <button
                      key={preset.label}
                      type="button"
                      onClick={() => {
                        setInvestigationGoal(preset.goal);
                        handleGenerateHypothesis(preset.goal);
                      }}
                      className="px-2.5 py-1 text-[11px] font-mono bg-gray-800/80 hover:bg-indigo-950/60 hover:border-indigo-700/60 border border-gray-700 text-gray-300 rounded transition-colors"
                    >
                      {preset.label}
                    </button>
                  ))}
                </div>
              </div>

              {/* Generate Hypothesis Trigger Button */}
              <div className="pt-2 flex items-center justify-between">
                <div className="text-[11px] font-mono text-gray-400">
                  {indexedFindingsCount > 0 ? (
                    <span className="text-emerald-400">
                      ✓ Correlating with {indexedFindingsCount} indexed evidence finding(s)
                    </span>
                  ) : (
                    <span className="text-amber-400">
                      ⚠ No ingested findings detected; planner will evaluate baseline forensic evidence.
                    </span>
                  )}
                </div>

                <button
                  type="button"
                  onClick={() => handleGenerateHypothesis()}
                  disabled={planningHypothesis || !investigationGoal.trim()}
                  className="px-5 py-2 bg-gradient-to-r from-indigo-600 to-cyan-600 hover:from-indigo-500 hover:to-cyan-500 text-white font-mono text-xs font-bold rounded-lg shadow-lg shadow-indigo-600/20 flex items-center space-x-2 disabled:opacity-50"
                >
                  {planningHypothesis ? (
                    <>
                      <RefreshCw className="w-4 h-4 animate-spin text-cyan-200" />
                      <span>Formulating Dual Hypotheses...</span>
                    </>
                  ) : (
                    <>
                      <Sparkles className="w-4 h-4 text-cyan-200" />
                      <span>{hypothesisDraft ? "Re-Generate AI Hypotheses" : "Generate AI Hypotheses & Plan"}</span>
                    </>
                  )}
                </button>
              </div>

              {hypothesisError && (
                <div className="p-3 bg-rose-950/60 border border-rose-800 rounded-lg text-rose-300 text-xs font-mono flex items-center space-x-2">
                  <AlertCircle className="w-4 h-4 shrink-0 text-rose-400" />
                  <span>{hypothesisError}</span>
                </div>
              )}
            </div>

            {/* Generated Hypothesis Results Display */}
            {hypothesisDraft && (
              <div className="mt-8 pt-6 border-t border-gray-800 space-y-6">
                {/* Dual Hypotheses (Threat vs. Benign Alternative) */}
                <div>
                  <h3 className="text-xs font-mono uppercase tracking-wider text-gray-400 mb-3 flex items-center gap-1.5">
                    <ShieldCheck className="w-4 h-4 text-cyan-400" />
                    <span>Dual Hypothesis Evaluation (Anti-Hallucination & Neutral Bias)</span>
                  </h3>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {/* Threat Hypothesis Card */}
                    <div className="bg-gradient-to-b from-rose-950/40 to-slate-900 border border-rose-800/60 rounded-xl p-4 shadow-lg space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="px-2 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-700 text-[10px] font-mono font-bold uppercase tracking-wider flex items-center gap-1">
                          <ShieldAlert className="w-3 h-3 text-rose-400" />
                          <span>Threat Hypothesis</span>
                        </span>
                        <span className="text-[10px] font-mono text-rose-400 bg-rose-950/80 px-2 py-0.5 rounded border border-rose-900">
                          Confidence: {(hypothesisDraft.confidence_score * 100).toFixed(0)}%
                        </span>
                      </div>
                      <p className="text-xs text-rose-100 font-mono leading-relaxed pt-1">
                        {hypothesisDraft.threat_hypothesis}
                      </p>
                    </div>

                    {/* Benign Alternative Hypothesis Card */}
                    <div className="bg-gradient-to-b from-emerald-950/40 to-slate-900 border border-emerald-800/60 rounded-xl p-4 shadow-lg space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-700 text-[10px] font-mono font-bold uppercase tracking-wider flex items-center gap-1">
                          <CheckCircle className="w-3 h-3 text-emerald-400" />
                          <span>Benign Alternative</span>
                        </span>
                        <span className="text-[10px] font-mono text-emerald-400 bg-emerald-950/80 px-2 py-0.5 rounded border border-emerald-900">
                          Administrative Baseline
                        </span>
                      </div>
                      <p className="text-xs text-emerald-100 font-mono leading-relaxed pt-1">
                        {hypothesisDraft.benign_hypothesis}
                      </p>
                    </div>
                  </div>
                </div>

                {/* Recommended Blueprint & Key Questions */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {/* Recommended Blueprint */}
                  <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 space-y-3">
                    <div className="flex items-center space-x-2 text-cyan-400 text-xs font-mono font-semibold">
                      <Layers className="w-4 h-4" />
                      <span>Recommended Workflow Blueprint</span>
                    </div>

                    <div className="p-3 bg-slate-950 rounded-lg border border-cyan-900/40 space-y-1.5">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-mono font-bold text-white">
                          {hypothesisDraft.recommended_blueprint}
                        </span>
                        <span className="text-[10px] font-mono bg-cyan-950 text-cyan-300 px-2 py-0.5 rounded border border-cyan-800">
                          Auto-Selected
                        </span>
                      </div>
                      <p className="text-[11px] font-mono text-gray-400">
                        Configured for automated multi-stage pivot execution with Human Approval Gate enforcement.
                      </p>
                    </div>

                    {hypothesisDraft.plan_steps && hypothesisDraft.plan_steps.length > 0 ? (
                      <div className="space-y-2">
                        <span className="text-[10px] font-mono text-gray-400 uppercase flex items-center justify-between">
                          <span>Deterministic MITRE Playbook Steps:</span>
                          <span className="text-cyan-400">{hypothesisDraft.plan_steps.filter(s => s.status !== "SKIPPED_NO_ARTIFACT").length} Active / {hypothesisDraft.plan_steps.length} Total</span>
                        </span>
                        <div className="space-y-1.5 max-h-56 overflow-y-auto pr-1">
                          {hypothesisDraft.plan_steps.map((step, idx) => (
                            <div
                              key={step.step_id || idx}
                              className={`p-2 rounded border text-xs font-mono flex items-center justify-between gap-2 ${
                                step.status === "SKIPPED_NO_ARTIFACT"
                                  ? "bg-gray-900/60 border-amber-900/50 text-gray-400"
                                  : "bg-slate-950/80 border-cyan-900/50 text-cyan-200"
                              }`}
                            >
                              <div className="flex items-center gap-2 truncate">
                                <span className="px-1.5 py-0.5 rounded text-[9px] font-bold bg-indigo-950 border border-indigo-800 text-indigo-300">
                                  {step.tactic_id}
                                </span>
                                <span className="truncate">{step.name}</span>
                              </div>
                              <span
                                className={`px-2 py-0.5 rounded text-[9px] font-bold shrink-0 ${
                                  step.status === "SKIPPED_NO_ARTIFACT"
                                    ? "bg-amber-950 text-amber-300 border border-amber-800"
                                    : step.status === "EXECUTED"
                                    ? "bg-emerald-950 text-emerald-300 border border-emerald-800"
                                    : "bg-cyan-950 text-cyan-300 border border-cyan-800"
                                }`}
                              >
                                {step.status === "SKIPPED_NO_ARTIFACT" ? "SKIPPED: NO ARTIFACT" : step.status}
                              </span>
                            </div>
                          ))}
                        </div>
                      </div>
                    ) : hypothesisDraft.suggested_steps && hypothesisDraft.suggested_steps.length > 0 && (
                      <div className="space-y-1.5">
                        <span className="text-[10px] font-mono text-gray-400 uppercase">
                          Suggested DAG Analysis Steps:
                        </span>
                        <ul className="space-y-1">
                          {hypothesisDraft.suggested_steps.map((step, idx) => (
                            <li key={idx} className="text-xs font-mono text-gray-300 flex items-start space-x-2">
                              <span className="text-cyan-400 font-bold">•</span>
                              <span>{step}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>

                  {/* Key Questions to Answer */}
                  <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 space-y-3">
                    <div className="flex items-center space-x-2 text-indigo-400 text-xs font-mono font-semibold">
                      <HelpCircle className="w-4 h-4" />
                      <span>Key Questions to Resolve</span>
                    </div>

                    <ul className="space-y-2">
                      {hypothesisDraft.key_questions.map((q, idx) => (
                        <li
                          key={idx}
                          className="p-2.5 bg-slate-950 rounded-lg border border-gray-800 text-xs font-mono text-gray-200 flex items-start space-x-2"
                        >
                          <span className="w-4 h-4 rounded-full bg-indigo-950 border border-indigo-700 text-indigo-300 text-[10px] flex items-center justify-center shrink-0 mt-0.5">
                            {idx + 1}
                          </span>
                          <span>{q}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>

                {/* Cited Evidence Findings Table (RFC 3227 / ISO 27037) */}
                <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2 text-xs font-mono font-semibold text-gray-300">
                      <FileCheck className="w-4 h-4 text-emerald-400" />
                      <span>Verified Evidence Citations (RFC 3227 / ISO 27037)</span>
                    </div>
                    <span className="text-[10px] font-mono text-emerald-400 bg-emerald-950 px-2 py-0.5 rounded border border-emerald-800">
                      Zero LLM Extrapolation Enforced
                    </span>
                  </div>

                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs font-mono">
                      <thead>
                        <tr className="border-b border-gray-800 text-gray-400">
                          <th className="pb-2">Citing Finding ID</th>
                          <th className="pb-2">Claim Type</th>
                          <th className="pb-2">Claim Statement</th>
                          <th className="pb-2">Source Artifact Hash</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-gray-800/60 text-gray-300">
                        {hypothesisDraft.cited_findings.map((claim, idx) => (
                          <tr key={claim.claim_id || idx} className="hover:bg-gray-800/40">
                            <td className="py-2.5 text-cyan-400 font-semibold">
                              {claim.citing_finding_ids && claim.citing_finding_ids.length > 0
                                ? claim.citing_finding_ids.join(", ")
                                : "N/A"}
                            </td>
                            <td className="py-2.5">
                              <span className="px-1.5 py-0.5 rounded bg-cyan-950/80 border border-cyan-800 text-cyan-300 text-[10px]">
                                {claim.claim_type}
                              </span>
                            </td>
                            <td className="py-2.5 text-gray-200">
                              {claim.statement}
                            </td>
                            <td className="py-2.5 text-gray-400 font-mono">
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

                {/* Step 4 Action Buttons */}
                <div className="pt-4 border-t border-gray-800 flex items-center justify-between">
                  <button
                    type="button"
                    onClick={() => setStep(3)}
                    className="flex items-center space-x-2 px-4 py-2 bg-gray-800 hover:bg-gray-700 text-xs font-mono text-gray-300 rounded-lg border border-gray-700"
                  >
                    <ArrowLeft className="w-4 h-4" />
                    <span>Back to Verification & Custody</span>
                  </button>

                  <div className="flex items-center space-x-3">
                    <button
                      type="button"
                      onClick={() => handleGenerateHypothesis()}
                      disabled={planningHypothesis}
                      className="px-4 py-2 text-xs font-mono text-gray-400 hover:text-white transition-colors"
                    >
                      Regenerate
                    </button>

                    {hypothesisDraft.report && (
                      <button
                        type="button"
                        onClick={() => setActiveTab("report")}
                        className="px-5 py-2.5 bg-indigo-900/80 hover:bg-indigo-800 text-indigo-200 border border-indigo-700 font-mono text-xs font-bold rounded-lg shadow-lg flex items-center space-x-2"
                      >
                        <FileCheck className="w-4 h-4 text-indigo-300" />
                        <span>View Cited Report</span>
                      </button>
                    )}

                    <button
                      type="button"
                      onClick={() => {
                        if (hypothesisDraft.recommended_blueprint) {
                          setSelectedBlueprintKey(hypothesisDraft.recommended_blueprint);
                        }
                        setActiveTab("canvas");
                      }}
                      className="px-6 py-2.5 bg-gradient-to-r from-emerald-600 to-cyan-500 hover:from-emerald-500 hover:to-cyan-400 text-white font-mono text-xs font-bold rounded-lg shadow-lg shadow-emerald-500/20 flex items-center space-x-2"
                    >
                      <Sparkles className="w-4 h-4 text-white" />
                      <span>Proceed to Workflow</span>
                      <ArrowRight className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}


      {/* Navigation Buttons for Step 1 & 2 */}
      {step < 3 && (
        <div className="mt-8 flex items-center justify-between">
          {step === 2 ? (
            <button
              onClick={() => setStep(1)}
              className="flex items-center space-x-2 px-4 py-2 bg-gray-800 hover:bg-gray-700 text-xs font-mono text-gray-300 rounded-lg border border-gray-700"
            >
              <ArrowLeft className="w-4 h-4" />
              <span>Back to Modes</span>
            </button>
          ) : (
            <div />
          )}

          {step === 1 ? (
            <button
              onClick={() => setStep(2)}
              className="flex items-center space-x-2 px-6 py-2.5 bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-mono font-semibold rounded-lg shadow-lg shadow-cyan-500/20"
            >
              <span>Configure Selected Mode</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          ) : (
            <button
              onClick={handlePerformIntake}
              disabled={loading}
              className="flex items-center space-x-2 px-6 py-2.5 bg-gradient-to-r from-emerald-600 to-teal-500 hover:from-emerald-500 hover:to-teal-400 text-white text-xs font-mono font-bold rounded-lg shadow-lg shadow-emerald-500/20 disabled:opacity-50"
            >
              {loading ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  <span>Verifying & Intaking...</span>
                </>
              ) : (
                <>
                  <span>Execute Intake & Initialize Chain</span>
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          )}
        </div>
      )}

      {/* Local Host File Browser Modal (Zero-Copy Host Navigation) */}
      {showLocalBrowserModal && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#111827] border border-gray-800 rounded-2xl w-full max-w-2xl max-h-[80vh] flex flex-col shadow-2xl overflow-hidden">
            <div className="flex items-center justify-between px-5 py-3.5 border-b border-gray-800 bg-gray-900/60">
              <div className="flex items-center space-x-2">
                <FolderOpen className="w-4 h-4 text-cyan-400" />
                <h3 className="text-sm font-semibold text-white font-mono">
                  Browse Server Local Filesystem (Zero-Copy :ro)
                </h3>
              </div>
              <button
                type="button"
                onClick={() => setShowLocalBrowserModal(false)}
                className="text-gray-400 hover:text-white p-1 rounded-lg"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Path & Drive Quick Select */}
            <div className="px-5 py-3 border-b border-gray-800 bg-[#161f30] flex items-center justify-between gap-3 text-xs font-mono">
              <div className="flex items-center space-x-2 truncate min-w-0">
                <span className="text-gray-500 shrink-0">Location:</span>
                <span className="text-cyan-300 font-semibold truncate">
                  {localBrowserData?.current_path || "Root"}
                </span>
              </div>
              {localBrowserData?.drives && localBrowserData.drives.length > 0 && (
                <div className="flex items-center space-x-1.5 shrink-0">
                  <span className="text-gray-500 text-[10px]">Drives:</span>
                  {localBrowserData.drives.map((d) => (
                    <button
                      key={d}
                      type="button"
                      onClick={() => handleOpenLocalBrowser(d)}
                      className="px-2 py-0.5 bg-gray-800 hover:bg-gray-700 text-cyan-300 rounded text-[11px] border border-gray-700"
                    >
                      {d}
                    </button>
                  ))}
                </div>
              )}
            </div>

            {/* Item List */}
            <div className="flex-1 overflow-y-auto p-4 space-y-1 divide-y divide-gray-800/40">
              {browsingLoading ? (
                <div className="py-12 text-center text-xs font-mono text-gray-500 flex items-center justify-center space-x-2">
                  <RefreshCw className="w-4 h-4 animate-spin text-cyan-400" />
                  <span>Reading directory...</span>
                </div>
              ) : (
                <>
                  {localBrowserData?.parent_path && (
                    <div
                      onClick={() => handleOpenLocalBrowser(localBrowserData.parent_path!)}
                      className="flex items-center space-x-2 px-3 py-2 rounded-lg hover:bg-gray-800/60 cursor-pointer text-xs font-mono text-cyan-400"
                    >
                      <Folder className="w-4 h-4" />
                      <span>.. (Up one level)</span>
                    </div>
                  )}

                  {localBrowserData?.items.length === 0 ? (
                    <div className="py-8 text-center text-xs font-mono text-gray-500">
                      No matching evidence artifacts found in this directory.
                    </div>
                  ) : (
                    localBrowserData?.items.map((item) => (
                      <div
                        key={item.path}
                        onClick={() => {
                          if (item.is_dir) {
                            handleOpenLocalBrowser(item.path);
                          } else {
                            handleSelectLocalFile(item.path, item.extension);
                          }
                        }}
                        className={`flex items-center justify-between px-3 py-2 rounded-lg cursor-pointer text-xs font-mono transition-colors ${
                          item.is_dir
                            ? "hover:bg-cyan-950/30 text-white"
                            : "hover:bg-gray-800 text-cyan-300"
                        }`}
                      >
                        <div className="flex items-center space-x-2.5 truncate min-w-0">
                          {item.is_dir ? (
                            <Folder className="w-4 h-4 text-amber-400 shrink-0" />
                          ) : (
                            <FileText className="w-4 h-4 text-cyan-400 shrink-0" />
                          )}
                          <span className="truncate">{item.name}</span>
                        </div>
                        {!item.is_dir && (
                          <span className="text-[10px] text-gray-500 shrink-0 ml-2">
                            {(item.size_bytes / (1024 * 1024)).toFixed(1)} MB
                          </span>
                        )}
                      </div>
                    ))
                  )}
                </>
              )}
            </div>

            <div className="px-5 py-3 border-t border-gray-800 bg-gray-900/60 flex items-center justify-end">
              <button
                type="button"
                onClick={() => setShowLocalBrowserModal(false)}
                className="px-4 py-1.5 rounded-lg bg-gray-800 hover:bg-gray-700 text-xs font-mono text-gray-300"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
