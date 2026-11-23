import React, {
  createContext,
  useContext,
  useState,
  useEffect,
  useCallback,
  useRef,
} from "react";
import { Node, Edge } from "@xyflow/react";
import {
  ActiveTab,
  InvestigationSession,
  WizardPersistedState,
  WorkflowCanvasPersistedState,
  WorkflowDefinition,
  WorkflowExecutionState,
  WorkflowNode,
} from "../types";
import { api } from "../services/api";
import { useForensicStore } from "../store/useForensicStore";

const DEFAULT_WIZARD_STATE: WizardPersistedState = {
  mode: "offline",
  offlinePath: "",
  isZeroCopy: false,
  artifactType: "evtx",
  autoIndex: true,
  uploadedMetadata: null,
  approvalTokenId: `tok-session-init`,
  gateApproved: true,
  siemType: "elasticsearch",
  siemUrl: "https://siem.internal:9200",
  siemIndex: "winlogbeat-*",
  siemQuery: 'event.code: "4624" AND winlog.event_data.LogonType: "3"',
  siemConnectionId: null,
  ingestedArtifacts: [],
  indexedFindingsCount: 0,
  recentCustody: [],
  investigationGoal: "Investigate potential unauthorized access, execution anomalies, and persistence.",
  hypothesisDraft: null,
  caseName: "Incident Response - Alpha Hunt",
  organizationName: "CyberCorp Financial",
  caseStatus: "OPEN",
  isSharedToVault: false,
};

interface InvestigationContextValue {
  caseId: string;
  setCaseId: (id: string) => void;
  activeTab: ActiveTab;
  setActiveTab: (tab: ActiveTab) => void;

  // Wizard state
  wizardState: WizardPersistedState;
  updateWizardState: (partial: Partial<WizardPersistedState>) => void;
  resetWizardState: () => void;

  // Workflow state
  selectedBlueprintKey: string;
  setSelectedBlueprintKey: (key: string) => void;
  activeWorkflow: WorkflowDefinition | null;
  setActiveWorkflow: (workflow: WorkflowDefinition | null) => void;
  executionState: WorkflowExecutionState | null;
  setExecutionState: (state: WorkflowExecutionState | null) => void;
  nodes: Node[];
  setNodes: React.Dispatch<React.SetStateAction<Node[]>>;
  edges: Edge[];
  setEdges: React.Dispatch<React.SetStateAction<Edge[]>>;
  streamLogs: Array<{ timestamp: string; event: string; detail: string }>;
  addStreamLog: (event: string, detail: string) => void;
  clearStreamLogs: () => void;
  isStreaming: boolean;
  setIsStreaming: (streaming: boolean) => void;

  // End-to-end execution
  runWorkflow: () => Promise<WorkflowExecutionState | null>;

  // Persistence status & Case Loading
  isSavingSession: boolean;
  lastSavedUtc: string | null;
  saveSessionNow: () => Promise<void>;
  reloadSession: (targetCaseId?: string) => Promise<void>;
  loadCase: (targetCaseId: string) => Promise<void>;
}


const InvestigationContext = createContext<InvestigationContextValue | null>(null);

export function InvestigationProvider({ children }: { children: React.ReactNode }) {
  const forensicStore = useForensicStore();
  const [caseId, setCaseIdState] = useState<string>(() => forensicStore.currentCaseId || "CASE-2026-LIVE-01");
  const [activeTab, setActiveTabState] = useState<ActiveTab>(() => forensicStore.activeTab || "wizard");

  // Wizard persistent state (Scoped to active session via sessionStorage - SA-010)
  // SEC-UI-001: Credentials must NEVER be stored in browser sessionStorage
  const [wizardState, setWizardState] = useState<WizardPersistedState>(() => {
    try {
      const cached = sessionStorage.getItem(`forensicops_wiz_${caseId}`);
      if (cached) {
        const parsed = JSON.parse(cached);
        if (parsed.offlinePath && parsed.offlinePath.includes("triage_case01.zip")) {
          parsed.offlinePath = "";
        }
        delete parsed.siemApiKey;
        delete parsed.password;
        delete parsed.apiKey;
        delete parsed.token;
        return { ...DEFAULT_WIZARD_STATE, ...parsed };
      }
    } catch {}
    return DEFAULT_WIZARD_STATE;
  });

  // Workflow persistent state
  const [selectedBlueprintKey, setSelectedBlueprintKey] = useState<string>("windows_intrusion");
  const [activeWorkflow, setActiveWorkflowState] = useState<WorkflowDefinition | null>(null);
  const [executionState, setExecutionState] = useState<WorkflowExecutionState | null>(null);
  const [nodes, setNodes] = useState<Node[]>([]);
  const [edges, setEdges] = useState<Edge[]>([]);
  const [streamLogs, setStreamLogs] = useState<Array<{ timestamp: string; event: string; detail: string }>>([]);
  const [isStreaming, setIsStreaming] = useState<boolean>(false);

  // Persistence status
  const [isSavingSession, setIsSavingSession] = useState<boolean>(false);
  const [lastSavedUtc, setLastSavedUtc] = useState<string | null>(null);

  const saveTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const isHydratedRef = useRef<boolean>(false);

  // Synchronize caseId with global forensic store
  const setCaseId = useCallback((newCaseId: string) => {
    setCaseIdState(newCaseId);
    forensicStore.setCaseId(newCaseId);
  }, [forensicStore]);

  // Synchronize activeTab with global forensic store
  const setActiveTab = useCallback((tab: ActiveTab) => {
    setActiveTabState(tab);
    forensicStore.setActiveTab(tab);
  }, [forensicStore]);

  // SEC-UI-001: Active hook on initialization to purge any legacy siem_key lingering in browser storage
  useEffect(() => {
    try {
      const legacyKeys = ["siem_key", "siemApiKey", "siem_password", "siem_token", "forensicops_siem_key"];
      for (const k of legacyKeys) {
        localStorage.removeItem(k);
        sessionStorage.removeItem(k);
      }
      for (let i = 0; i < sessionStorage.length; i++) {
        const key = sessionStorage.key(i);
        if (key && (key.startsWith("forensicops_") || key.includes("siem") || key.includes("wiz"))) {
          const raw = sessionStorage.getItem(key);
          if (raw && (raw.includes("siemApiKey") || raw.includes("siem_key") || raw.includes("password"))) {
            try {
              const parsed = JSON.parse(raw);
              delete parsed.siemApiKey;
              delete parsed.siem_key;
              delete parsed.password;
              delete parsed.apiKey;
              delete parsed.token;
              delete parsed.credentials;
              sessionStorage.setItem(key, JSON.stringify(parsed));
            } catch {
              sessionStorage.removeItem(key);
            }
          }
        }
      }
    } catch {}
  }, []);

  const updateWizardState = useCallback((partial: Partial<WizardPersistedState>) => {
    setWizardState((prev) => {
      const next = { ...prev, ...partial };
      try {
        // SEC-UI-001: Strip any sensitive credentials before serializing to sessionStorage
        const safeSessionState: Record<string, any> = { ...next };
        delete safeSessionState.siemApiKey;
        delete safeSessionState.password;
        delete safeSessionState.apiKey;
        delete safeSessionState.token;
        delete safeSessionState.credentials;
        sessionStorage.setItem(`forensicops_wiz_${caseId}`, JSON.stringify(safeSessionState));
      } catch {}
      return next;
    });
  }, [caseId]);

  const resetWizardState = useCallback(() => {
    setWizardState(DEFAULT_WIZARD_STATE);
    try {
      sessionStorage.removeItem(`forensicops_wiz_${caseId}`);
    } catch {}
  }, [caseId]);

  const setActiveWorkflow = useCallback((workflow: WorkflowDefinition | null) => {
    setActiveWorkflowState(workflow);
    forensicStore.setActiveWorkflow(workflow);
  }, [forensicStore]);

  const addStreamLog = useCallback((event: string, detail: string) => {
    const entry = {
      timestamp: new Date().toISOString().substring(11, 19),
      event,
      detail,
    };
    setStreamLogs((prev) => [...prev, entry]);
    forensicStore.addStreamLog(event, detail);
  }, [forensicStore]);

  const clearStreamLogs = useCallback(() => {
    setStreamLogs([]);
    forensicStore.clearStreamLogs();
  }, [forensicStore]);

  // Explicit Save to SQLite Session Store
  const saveSessionNow = useCallback(async () => {
    if (!caseId) return;
    setIsSavingSession(true);
    try {
      const wfStatePayload: WorkflowCanvasPersistedState = {
        selectedBlueprintKey,
        activeWorkflow,
        executionState,
        streamLogs: streamLogs.slice(-50),
        isStreaming: false,
      };

      // SEC-UI-001: Strip credentials prior to persisting session or case records
      const safeWizardState: WizardPersistedState = { ...wizardState };
      delete (safeWizardState as any).siemApiKey;
      delete (safeWizardState as any).password;
      delete (safeWizardState as any).apiKey;
      delete (safeWizardState as any).token;
      delete (safeWizardState as any).credentials;

      await api.saveSession(caseId, {
        wizard_state: safeWizardState,
        workflow_state: wfStatePayload,
        active_tab: activeTab,
      });

      // Synchronize with SQLite Cases Registry
      api.createOrUpdateCase({
        case_id: caseId,
        case_name: wizardState.caseName || `Case ${caseId}`,
        organization_name: wizardState.organizationName || "Default Organization",
        investigation_goal: wizardState.investigationGoal,
        status: wizardState.caseStatus || "OPEN",
        serialized_state: {
          wizard_state: safeWizardState,
          workflow_state: wfStatePayload,
          active_tab: activeTab,
        },
      }).catch((e) => console.warn("Background case sync warning:", e));

      const now = new Date().toISOString();
      setLastSavedUtc(now);
    } catch (err) {
      console.error("Failed to auto-save session to SQLite store:", err);
    } finally {
      setIsSavingSession(false);
    }
  }, [caseId, wizardState, selectedBlueprintKey, activeWorkflow, executionState, streamLogs, activeTab]);

  // Debounced auto-save trigger on state mutations
  useEffect(() => {
    if (!isHydratedRef.current) return;
    if (saveTimerRef.current) clearTimeout(saveTimerRef.current);
    saveTimerRef.current = setTimeout(() => {
      saveSessionNow();
    }, 1200);

    return () => {
      if (saveTimerRef.current) clearTimeout(saveTimerRef.current);
    };
  }, [wizardState, selectedBlueprintKey, executionState, activeTab, saveSessionNow]);

  // Reload session from SQLite store
  const reloadSession = useCallback(async (targetCaseId?: string) => {
    const cid = targetCaseId || caseId;
    if (!cid) return;
    try {
      const session = await api.getSession(cid);
      if (session) {
        if (session.wizard_state && Object.keys(session.wizard_state).length > 0) {
          const wz = { ...session.wizard_state };
          if (wz.offlinePath && wz.offlinePath.includes("triage_case01.zip")) {
            wz.offlinePath = "";
          }
          setWizardState((prev) => ({ ...prev, ...wz }));
        }
        if (session.workflow_state) {
          const wf = session.workflow_state as WorkflowCanvasPersistedState;
          if (wf.selectedBlueprintKey) setSelectedBlueprintKey(wf.selectedBlueprintKey);
          if (wf.activeWorkflow) setActiveWorkflowState(wf.activeWorkflow);
          if (wf.executionState) setExecutionState(wf.executionState);
          if (wf.streamLogs && wf.streamLogs.length > 0) setStreamLogs(wf.streamLogs);
        }
        if (session.active_tab) {
          setActiveTabState(session.active_tab);
        }
        if (session.updated_at_utc) {
          setLastSavedUtc(session.updated_at_utc);
        }
      }
    } catch (err) {
      console.warn("Could not reload session from server SQLite store:", err);
    } finally {
      isHydratedRef.current = true;
    }
  }, [caseId]);

  // Load a complete case from Case Manager
  const loadCase = useCallback(async (targetCaseId: string) => {
    if (!targetCaseId) return;
    setCaseIdState(targetCaseId);
    forensicStore.setCaseId(targetCaseId);
    try {
      const caseRecord = await api.getCase(targetCaseId);
      if (caseRecord && caseRecord.serialized_state) {
        const state = caseRecord.serialized_state;
        if (state.wizard_state) {
          setWizardState((prev) => ({
            ...prev,
            ...state.wizard_state,
            caseName: caseRecord.case_name,
            organizationName: caseRecord.organization_name,
            investigationGoal: caseRecord.investigation_goal || prev.investigationGoal,
            caseStatus: caseRecord.status,
          }));
        }
        if (state.workflow_state) {
          const wf = state.workflow_state;
          if (wf.selectedBlueprintKey) setSelectedBlueprintKey(wf.selectedBlueprintKey);
          if (wf.activeWorkflow) setActiveWorkflowState(wf.activeWorkflow);
          if (wf.executionState) setExecutionState(wf.executionState);
          if (wf.streamLogs && wf.streamLogs.length > 0) setStreamLogs(wf.streamLogs);
        }
        if (state.active_tab) {
          setActiveTabState(state.active_tab);
        }
      } else {
        await reloadSession(targetCaseId);
      }
    } catch {
      await reloadSession(targetCaseId);
    }
  }, [forensicStore, reloadSession]);

  // Initial mount: load session from SQLite store
  useEffect(() => {
    reloadSession(caseId);

  }, [caseId, reloadSession]);

  // End-to-end Workflow Execution connected directly to POST /api/workflow/run
  const runWorkflow = useCallback(async (): Promise<WorkflowExecutionState | null> => {
    if (!activeWorkflow) {
      addStreamLog("error", "No active workflow blueprint selected to run.");
      return null;
    }

    setIsStreaming(true);
    addStreamLog("exec_init", `Dispatching workflow execution to POST /api/workflow/run for Case: ${caseId}`);

    // Set nodes to running visually (reconstructing from activeWorkflow if empty)
    setNodes((prevNodes) => {
      let current = prevNodes;
      if (current.length === 0 && activeWorkflow) {
        current = activeWorkflow.nodes.map((n: WorkflowNode, idx: number) => {
          const col = idx;
          const x = n.position?.x ?? 80 + col * 260;
          const y = n.position?.y ?? 180 + (idx % 2 === 1 ? 60 : -40);
          return {
            id: n.id,
            type: "forensicNode",
            position: { x, y },
            data: {
              label: n.name,
              nodeType: n.type,
              config: n.config,
              status: "running",
            },
          };
        });
        return current;
      }
      return current.map((n) => ({
        ...n,
        data: { ...n.data, status: "running" },
      }));
    });

    try {
      const finalState = await api.runWorkflow({
        case_id: caseId,
        workflow: activeWorkflow,
      });

      setExecutionState(finalState);
      forensicStore.setExecutionState(finalState);

      // Update node states based on results (reconstruct base list if empty)
      setNodes((prevNodes) => {
        let baseNodes = prevNodes;
        if (baseNodes.length === 0 && activeWorkflow) {
          baseNodes = activeWorkflow.nodes.map((n: WorkflowNode, idx: number) => {
            const col = idx;
            const x = n.position?.x ?? 80 + col * 260;
            const y = n.position?.y ?? 180 + (idx % 2 === 1 ? 60 : -40);
            return {
              id: n.id,
              type: "forensicNode",
              position: { x, y },
              data: {
                label: n.name,
                nodeType: n.type,
                config: n.config,
                status: "idle",
              },
            };
          });
        }
        return baseNodes.map((n) => {
          const isCompleted = finalState.completed_nodes.includes(n.id);
          const isPaused = finalState.is_paused && finalState.pause_node_id === n.id;
          const result = finalState.node_results?.[n.id];
          return {
            ...n,
            data: {
              ...n.data,
              status: isPaused ? "paused" : isCompleted ? "completed" : "idle",
              summary: result?.summary,
              claimCount: result?.claims?.length,
            },
          };
        });
      });

      addStreamLog(
        "exec_success",
        `Execution complete via POST /api/workflow/run. Completed ${finalState.completed_nodes.length} nodes.`
      );

      // Persist latest state immediately to SQLite session store
      await api.saveSession(caseId, {
        wizard_state: wizardState,
        workflow_state: {
          selectedBlueprintKey,
          activeWorkflow,
          executionState: finalState,
          streamLogs,
          isStreaming: false,
        },
        active_tab: activeTab,
      });

      // Auto-fetch generated forensic report if workflow completed
      try {
        const rep = await api.getReport(caseId);
        if (rep && rep.report) {
          forensicStore.setReportData(rep.report, rep.markdown);
        }
      } catch {}

      return finalState;
    } catch (err: any) {
      const errorMsg = err.message || String(err);
      addStreamLog("exec_error", `POST /api/workflow/run failed: ${errorMsg}`);
      setNodes((prevNodes) =>
        prevNodes.map((n) => ({
          ...n,
          data: { ...n.data, status: "failed" },
        }))
      );
      return null;
    } finally {
      setIsStreaming(false);
    }
  }, [activeWorkflow, caseId, setNodes, addStreamLog, forensicStore, wizardState, selectedBlueprintKey, streamLogs, activeTab]);

  return (
    <InvestigationContext.Provider
      value={{
        caseId,
        setCaseId,
        activeTab,
        setActiveTab,
        wizardState,
        updateWizardState,
        resetWizardState,
        selectedBlueprintKey,
        setSelectedBlueprintKey,
        activeWorkflow,
        setActiveWorkflow,
        executionState,
        setExecutionState,
        nodes,
        setNodes,
        edges,
        setEdges,
        streamLogs,
        addStreamLog,
        clearStreamLogs,
        isStreaming,
        setIsStreaming,
        runWorkflow,
        isSavingSession,
        lastSavedUtc,
        saveSessionNow,
        reloadSession,
        loadCase,
      }}
    >

      {children}
    </InvestigationContext.Provider>
  );
}

export function useInvestigation() {
  const context = useContext(InvestigationContext);
  if (!context) {
    throw new Error("useInvestigation must be used within an InvestigationProvider");
  }
  return context;
}
