import { create } from "zustand";
import {
  ActiveTab,
  CitedReport,
  CustodyChainEntry,
  ForensicFinding,
  ToolPluginCard,
  WorkflowDefinition,
  WorkflowExecutionState,
} from "../types";

export type { ActiveTab };

interface ForensicState {
  currentCaseId: string;
  activeTab: ActiveTab;
  activeWorkflow: WorkflowDefinition | null;
  executionState: WorkflowExecutionState | null;
  isStreaming: boolean;
  streamLogs: Array<{ timestamp: string; event: string; detail: string }>;
  report: CitedReport | null;
  reportMarkdown: string;
  selectedFinding: ForensicFinding | null;
  isCitationDrawerOpen: boolean;
  custodyEntries: CustodyChainEntry[];
  isChainValid: boolean;
  blueprints: Record<string, WorkflowDefinition>;
  plugins: ToolPluginCard[];

  // Setters
  setCaseId: (caseId: string) => void;
  setActiveTab: (tab: ActiveTab) => void;
  setActiveWorkflow: (workflow: WorkflowDefinition | null) => void;
  setExecutionState: (state: WorkflowExecutionState | null) => void;
  setIsStreaming: (streaming: boolean) => void;
  addStreamLog: (event: string, detail: string) => void;
  clearStreamLogs: () => void;
  setReportData: (report: CitedReport | null, markdown: string) => void;
  openCitationDrawer: (finding: ForensicFinding) => void;
  closeCitationDrawer: () => void;
  setCustodyEntries: (entries: CustodyChainEntry[], isValid: boolean) => void;
  setBlueprints: (blueprints: Record<string, WorkflowDefinition>) => void;
  setPlugins: (plugins: ToolPluginCard[]) => void;
}

export const useForensicStore = create<ForensicState>((set) => ({
  currentCaseId: "CASE-2026-LIVE-01",
  activeTab: "wizard",
  activeWorkflow: null,
  executionState: null,
  isStreaming: false,
  streamLogs: [],
  report: null,
  reportMarkdown: "",
  selectedFinding: null,
  isCitationDrawerOpen: false,
  custodyEntries: [],
  isChainValid: true,
  blueprints: {},
  plugins: [],

  setCaseId: (currentCaseId) => set({ currentCaseId }),
  setActiveTab: (activeTab) => set({ activeTab }),
  setActiveWorkflow: (activeWorkflow) => set({ activeWorkflow }),
  setExecutionState: (executionState) => set({ executionState }),
  setIsStreaming: (isStreaming) => set({ isStreaming }),
  addStreamLog: (event, detail) =>
    set((state) => ({
      streamLogs: [
        ...state.streamLogs,
        {
          timestamp: new Date().toISOString().substring(11, 19),
          event,
          detail,
        },
      ],
    })),
  clearStreamLogs: () => set({ streamLogs: [] }),
  setReportData: (report, reportMarkdown) => set({ report, reportMarkdown }),
  openCitationDrawer: (selectedFinding) =>
    set({ selectedFinding, isCitationDrawerOpen: true }),
  closeCitationDrawer: () =>
    set({ selectedFinding: null, isCitationDrawerOpen: false }),
  setCustodyEntries: (custodyEntries, isChainValid) =>
    set({ custodyEntries, isChainValid }),
  setBlueprints: (blueprints) => set({ blueprints }),
  setPlugins: (plugins) => set({ plugins }),
}));
