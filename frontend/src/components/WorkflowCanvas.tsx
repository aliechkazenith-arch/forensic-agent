import React, { useState, useEffect, useCallback, useMemo } from "react";
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  Node,
  Edge,
  addEdge,
  Connection,
  MarkerType,
  applyNodeChanges,
  applyEdgeChanges,
  OnNodesChange,
  OnEdgesChange,
} from "@xyflow/react";
import {
  Play,
  RotateCcw,
  ShieldAlert,
  Terminal,
  ChevronDown,
  ChevronUp,
  Cpu,
  Layers,
  Sparkles,
  CheckCircle2,
  AlertCircle,
  KeyRound,
  FileText,
  Eye,
  Database,
} from "lucide-react";
import { ForensicNode } from "./ForensicNode";
import { PivotEdge } from "./PivotEdge";
import { ApprovalReviewModal } from "./ApprovalReviewModal";
import { api } from "../services/api";
import { useForensicStore } from "../store/useForensicStore";
import { useAuth } from "../context/AuthContext";
import { useInvestigation } from "../context/InvestigationContext";
import {
  ApprovalRequest,
  HumanApprovalToken,
  WorkflowDefinition,
  WorkflowExecutionState,
  WorkflowNode,
} from "../types";

export const WorkflowCanvas: React.FC = () => {
  const { user } = useAuth();
  const isAuditor = user?.role === "auditor";

  const {
    currentCaseId,
    setReportData,
    blueprints,
    setBlueprints,
    setActiveTab,
  } = useForensicStore();

  const {
    caseId,
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
    runWorkflow,
    isSavingSession,
    saveSessionNow,
    wizardState,
  } = useInvestigation();

  const [isLogsDrawerOpen, setIsLogsDrawerOpen] = useState<boolean>(true);
  const [isApprovalModalOpen, setIsApprovalModalOpen] = useState<boolean>(false);
  const [selectedNode, setSelectedNode] = useState<Node | null>(null);

  const currentApprovalRequest: ApprovalRequest | null = useMemo(() => {
    if (!executionState?.is_paused || !executionState?.pause_node_id) return null;
    const pausedNode = activeWorkflow?.nodes.find((n) => n.id === executionState.pause_node_id);
    return {
      approval_id: `gate-${executionState.pause_node_id}`,
      case_id: caseId || currentCaseId,
      requesting_investigator: "workflow_controller",
      action_type: pausedNode?.type || "sensitive_operation",
      capability_id: pausedNode?.name || executionState.pause_node_id,
      target: caseId || currentCaseId,
      parameters: pausedNode?.config || { node_id: executionState.pause_node_id },
      parameter_digest: "sha256:canonical-node-config",
      risk_level: "high",
      justification:
        executionState.pause_reason ||
        "Sensitive forensic workflow node requires explicit human sign-off before proceeding.",
      policy_version: "1.0.0",
      created_at_utc: new Date().toISOString(),
      expires_at_utc: new Date(Date.now() + 3600 * 1000).toISOString(),
      status: "pending",
    };
  }, [executionState, activeWorkflow, caseId, currentCaseId]);

  // Custom types registration
  const nodeTypes = useMemo(() => ({ forensicNode: ForensicNode }), []);
  const edgeTypes = useMemo(() => ({ pivotEdge: PivotEdge }), []);

  const onNodesChange: OnNodesChange = useCallback(
    (changes) => setNodes((nds) => applyNodeChanges(changes, nds)),
    [setNodes]
  );

  const onEdgesChange: OnEdgesChange = useCallback(
    (changes) => setEdges((eds) => applyEdgeChanges(changes, eds)),
    [setEdges]
  );

  // Convert WorkflowDefinition to React Flow nodes/edges
  const loadBlueprint = useCallback((key: string, bpDict = blueprints) => {
    setSelectedBlueprintKey(key);
    const bp = bpDict[key];
    if (!bp) return;

    setActiveWorkflow(bp);
    if (!executionState || executionState.workflow_id !== bp.workflow_id) {
      setExecutionState(null);
      clearStreamLogs();
    }

    // Layout nodes with horizontal column spacing
    const flowNodes: Node[] = bp.nodes.map((n: WorkflowNode, idx: number) => {
      const col = idx;
      const x = n.position?.x ?? 80 + col * 260;
      const y = n.position?.y ?? 180 + (idx % 2 === 1 ? 60 : -40);

      const isCompleted = executionState?.completed_nodes?.includes(n.id);
      const isPaused = executionState?.is_paused && executionState?.pause_node_id === n.id;
      const result = executionState?.node_results?.[n.id];

      return {
        id: n.id,
        type: "forensicNode",
        position: { x, y },
        data: {
          label: n.name,
          nodeType: n.type,
          config: n.config,
          status: isPaused ? "paused" : isCompleted ? "completed" : "idle",
          summary: result?.summary,
          claimCount: result?.claims?.length,
        },
      };
    });

    const flowEdges: Edge[] = bp.edges.map((e) => ({
      id: e.id,
      source: e.source,
      target: e.target,
      type: "pivotEdge",
      animated: true,
      markerEnd: { type: MarkerType.ArrowClosed, color: "#06b6d4" },
      style: { stroke: "#0891b2", strokeWidth: 2 },
      data: { payload: e.payload },
    }));

    setNodes(flowNodes);
    setEdges(flowEdges);
    addStreamLog("blueprint_loaded", `Loaded blueprint: ${bp.name} (${bp.nodes.length} nodes)`);
  }, [blueprints, setSelectedBlueprintKey, setActiveWorkflow, executionState, setExecutionState, clearStreamLogs, setNodes, setEdges, addStreamLog]);

  // Fetch blueprints on mount if not loaded
  useEffect(() => {
    api
      .getBlueprints()
      .then((data) => {
        setBlueprints(data);
        const targetKey = selectedBlueprintKey || "windows_intrusion";
        if (data[targetKey] && (nodes.length === 0 || !activeWorkflow || activeWorkflow.workflow_id !== data[targetKey].workflow_id)) {
          loadBlueprint(targetKey, data);
        }
      })
      .catch((err) => {
        addStreamLog("error", `Failed to load blueprints: ${err.message}`);
      });
  }, []);

  // Synchronize when selectedBlueprintKey changes externally (e.g. from Step 4 AI Planner)
  useEffect(() => {
    if (!blueprints || Object.keys(blueprints).length === 0) return;
    const targetKey = selectedBlueprintKey || "windows_intrusion";
    const targetBp = blueprints[targetKey];
    if (targetBp && (nodes.length === 0 || !activeWorkflow || activeWorkflow.workflow_id !== targetBp.workflow_id) && !isStreaming) {
      loadBlueprint(targetKey, blueprints);
    }
  }, [selectedBlueprintKey, blueprints, activeWorkflow, isStreaming, loadBlueprint, nodes.length]);

  // Fallback: Reconstruct nodes and edges if activeWorkflow exists but canvas has zero nodes
  useEffect(() => {
    if (activeWorkflow && nodes.length === 0 && blueprints && Object.keys(blueprints).length > 0) {
      const targetKey = selectedBlueprintKey || "windows_intrusion";
      loadBlueprint(targetKey, blueprints);
    }
  }, [activeWorkflow, nodes.length, blueprints, selectedBlueprintKey, loadBlueprint]);


  const onConnect = useCallback(
    (params: Connection) =>
      setEdges((eds) =>
        addEdge(
          {
            ...params,
            type: "pivotEdge",
            animated: true,
            markerEnd: { type: MarkerType.ArrowClosed, color: "#06b6d4" },
            style: { stroke: "#0891b2", strokeWidth: 2 },
            data: { payload: { pivots: {} } },
          },
          eds
        )
      ),
    [setEdges]
  );

  // Sync execution status with nodes
  useEffect(() => {
    if (!executionState) return;

    setNodes((nds) =>
      nds.map((n) => {
        const isCompleted = executionState.completed_nodes.includes(n.id);
        const isPaused = executionState.is_paused && executionState.pause_node_id === n.id;
        const result = executionState.node_results[n.id];

        let status = n.data.status;
        let summary = n.data.summary;
        let claimCount = n.data.claimCount;

        if (isCompleted) {
          status = "completed";
          summary = result?.summary;
          claimCount = result?.claims?.length;
        } else if (isPaused) {
          status = "paused";
        }

        return {
          ...n,
          data: {
            ...n.data,
            status,
            summary,
            claimCount,
          },
        };
      })
    );

    if (executionState.is_paused) {
      setIsApprovalModalOpen(true);
    }
  }, [executionState, setNodes]);

  // Execute Workflow End-to-End with POST /api/workflow/run
  const handleRunWorkflow = async () => {
    if (!activeWorkflow) return;
    await runWorkflow();
  };

  // Resume paused approval gate
  const handleApproveGate = async () => {
    if (!executionState || !activeWorkflow || !executionState.pause_node_id) return;

    addStreamLog("gate_approval", `Authorizing approval token for node ${executionState.pause_node_id}...`);
    setIsApprovalModalOpen(false);

    try {
      const token = await api.createApprovalToken({
        case_id: caseId || currentCaseId,
        node_id: executionState.pause_node_id,
        reason: `Gate continuation authorized by ${user?.username || "analyst"}`,
      });

      const nextState = await api.resumeWorkflow({
        case_id: caseId || currentCaseId,
        workflow: activeWorkflow,
        state: executionState,
        approval_token: token,
      });
      setExecutionState(nextState);
      addStreamLog("gate_resumed", "Workflow resumed successfully after gate verification.");
      
      // Auto-save session
      await saveSessionNow();

      // Auto-fetch report if completed
      if (nextState.completed_nodes.length === activeWorkflow.nodes.length) {
        const rep = await api.getReport(caseId || currentCaseId);
        setReportData(rep.report, rep.markdown);
      }
    } catch (err: any) {
      addStreamLog("error", `Failed to resume workflow: ${err.message}`);
    }
  };

  const handleReset = () => {
    if (activeWorkflow) {
      loadBlueprint(selectedBlueprintKey);
    }
  };

  return (
    <div className="relative h-[calc(100vh-68px)] w-full flex flex-col bg-slate-950 overflow-hidden">
      {/* Top Workflow Control Bar */}
      <div className="h-14 border-b border-slate-800 bg-slate-900/90 backdrop-blur-md px-6 flex items-center justify-between z-10">
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2 text-cyan-400 font-semibold text-sm">
            <Layers className="w-4 h-4" />
            <span>Workflow Engine</span>
          </div>

          <div className="h-4 w-px bg-slate-700" />

          {/* Blueprint Selector */}
          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-400">Blueprint:</span>
            <select
              value={selectedBlueprintKey}
              onChange={(e) => loadBlueprint(e.target.value)}
              disabled={isStreaming}
              className="bg-slate-950 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-200 font-medium focus:ring-1 focus:ring-cyan-500 focus:outline-none"
            >
              <option value="windows_intrusion">Windows Intrusion Hunt</option>
              <option value="full_windows_triage">Full Windows Triage (Dissect)</option>
              <option value="linux_ssh_compromise">Linux SSH Compromise Investigation</option>
              <option value="memory_pcap_hunt">Memory + PCAP Hunt</option>
            </select>
          </div>

          {/* Persistent SQLite Session Status Indicator */}
          <div className="flex items-center gap-1.5 text-[11px] font-mono text-slate-400 bg-slate-950/80 px-2.5 py-1 rounded-lg border border-slate-800">
            <Database className="w-3.5 h-3.5 text-cyan-400" />
            <span>Session:</span>
            <span className={isSavingSession ? "text-amber-400 animate-pulse font-semibold" : "text-emerald-400 font-semibold"}>
              {isSavingSession ? "Syncing SQLite..." : "Persistent in SQLite"}
            </span>
          </div>

          {/* Active AI Hypothesis Badge */}
          {wizardState.hypothesisDraft && (
            <div
              className="hidden xl:flex items-center gap-1.5 text-[11px] font-mono text-slate-300 bg-indigo-950/60 border border-indigo-800/60 px-2.5 py-1 rounded-lg max-w-sm truncate"
              title={wizardState.hypothesisDraft.threat_hypothesis}
            >
              <Sparkles className="w-3.5 h-3.5 text-indigo-400 shrink-0" />
              <span className="text-indigo-400 font-semibold shrink-0">Hypothesis:</span>
              <span className="truncate">{wizardState.hypothesisDraft.threat_hypothesis}</span>
            </div>
          )}
        </div>


        {/* Action Buttons */}
        <div className="flex items-center gap-3">
          {executionState?.is_paused && (
            <button
              onClick={() => setIsApprovalModalOpen(true)}
              className="flex items-center gap-2 bg-rose-600 hover:bg-rose-500 text-white text-xs font-semibold px-3 py-1.5 rounded-lg shadow-lg shadow-rose-900/30 transition-all animate-bounce"
            >
              <ShieldAlert className="w-3.5 h-3.5" />
              <span>Gate Action Required</span>
            </button>
          )}

          {isAuditor ? (
            <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-semibold bg-amber-950/60 border border-amber-800/60 text-amber-300">
              <Eye className="w-3.5 h-3.5" />
              <span>Auditor Mode (Read-Only)</span>
            </div>
          ) : (
            <button
              onClick={handleRunWorkflow}
              disabled={isStreaming || !activeWorkflow}
              className={`flex items-center gap-2 px-4 py-1.5 rounded-lg text-xs font-semibold tracking-wide transition-all shadow-md ${
                isStreaming
                  ? "bg-cyan-900/50 text-cyan-300 border border-cyan-500/30 cursor-not-allowed"
                  : "bg-cyan-500 hover:bg-cyan-400 text-slate-950 shadow-cyan-500/20 active:scale-95"
              }`}
            >
              <Play className={`w-3.5 h-3.5 fill-current ${isStreaming ? "animate-pulse" : ""}`} />
              <span>{isStreaming ? "Executing POST /api/workflow/run..." : "Run Workflow"}</span>
            </button>
          )}

          <button
            onClick={handleReset}
            disabled={isStreaming}
            className="flex items-center gap-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs px-3 py-1.5 rounded-lg border border-slate-700 transition-colors"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span>Reset</span>
          </button>

          {executionState?.completed_nodes.length === activeWorkflow?.nodes.length && (
            <button
              onClick={() => setActiveTab("report")}
              className="flex items-center gap-1.5 bg-purple-600 hover:bg-purple-500 text-white text-xs font-semibold px-3 py-1.5 rounded-lg shadow transition-colors"
            >
              <FileText className="w-3.5 h-3.5" />
              <span>View Report</span>
            </button>
          )}
        </div>
      </div>

      {/* Main Flow Canvas */}
      <div className="flex-1 relative">
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={isAuditor ? undefined : onNodesChange}
          onEdgesChange={isAuditor ? undefined : onEdgesChange}
          onConnect={isAuditor ? undefined : onConnect}
          nodesDraggable={!isAuditor}
          nodesConnectable={!isAuditor}
          elementsSelectable={true}
          nodeTypes={nodeTypes}
          edgeTypes={edgeTypes}
          onNodeClick={(_, node) => setSelectedNode(node)}
          fitView
          className="bg-slate-950"
        >
          <Background color="#1e293b" gap={20} size={1} />
          <Controls className="!bg-slate-900 !border !border-slate-800 !text-slate-300 rounded-lg overflow-hidden shadow-xl" />
          <MiniMap
            nodeStrokeColor="#06b6d4"
            nodeColor="#0f172a"
            maskColor="rgba(11, 15, 25, 0.7)"
            className="!bg-slate-950 !border !border-slate-800 !rounded-lg"
          />
        </ReactFlow>

        {/* Selected Node Inspector Drawer (Right Side) */}
        {selectedNode && (
          <div className="absolute top-4 right-4 w-80 bg-slate-900/95 border border-slate-800 rounded-xl shadow-2xl p-4 backdrop-blur-md z-20 text-xs space-y-3">
            <div className="flex items-center justify-between pb-2 border-b border-slate-800">
              <span className="font-semibold text-slate-200">Node Inspector</span>
              <button
                onClick={() => setSelectedNode(null)}
                className="text-slate-400 hover:text-slate-200 text-sm font-bold"
              >
                &times;
              </button>
            </div>
            <div>
              <span className="text-[10px] text-slate-400 uppercase font-mono">Node ID</span>
              <p className="font-mono text-cyan-400 text-xs">{selectedNode.id}</p>
            </div>
            <div>
              <span className="text-[10px] text-slate-400 uppercase font-mono">Type</span>
              <p className="font-semibold text-slate-200">{selectedNode.data.nodeType as string}</p>
            </div>
            <div>
              <span className="text-[10px] text-slate-400 uppercase font-mono">Label / Task</span>
              <p className="text-slate-300">{selectedNode.data.label as string}</p>
            </div>
            {Boolean(selectedNode.data.summary) && (
              <div className="pt-2 border-t border-slate-800">
                <span className="text-[10px] text-emerald-400 uppercase font-mono font-semibold">
                  Execution Finding Summary
                </span>
                <p className="text-slate-300 mt-1 bg-slate-950/60 p-2 rounded border border-slate-800 font-mono text-[11px] leading-relaxed">
                  {String(selectedNode.data.summary)}
                </p>
              </div>
            )}
            {selectedNode.data.claimCount !== undefined && (
              <div className="flex items-center justify-between bg-slate-950/40 p-2 rounded border border-slate-800">
                <span className="text-slate-400">Cryptographic Claims:</span>
                <span className="font-mono text-cyan-300 font-bold">
                  {String(selectedNode.data.claimCount)}
                </span>
              </div>
            )}
          </div>
        )}

        {/* Collapsible Execution Stream Logs Drawer (Bottom) */}
        <div
          className={`absolute bottom-0 left-0 right-0 bg-slate-900/95 border-t border-slate-800 backdrop-blur-md z-20 transition-all duration-300 ${
            isLogsDrawerOpen ? "h-48" : "h-10"
          }`}
        >
          {/* Drawer Header */}
          <div
            onClick={() => setIsLogsDrawerOpen(!isLogsDrawerOpen)}
            className="h-10 px-6 flex items-center justify-between cursor-pointer hover:bg-slate-800/50 border-b border-slate-800/60"
          >
            <div className="flex items-center gap-2">
              <Terminal className="w-4 h-4 text-cyan-400" />
              <span className="text-xs font-semibold text-slate-200">Execution Logs & Pivot Ledger</span>
              <span className="bg-slate-800 text-slate-400 text-[10px] font-mono px-2 py-0.5 rounded-full">
                {streamLogs.length} events
              </span>
            </div>
            <div className="flex items-center gap-3">
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  clearStreamLogs();
                }}
                className="text-[11px] text-slate-400 hover:text-slate-200 px-2 py-0.5 rounded bg-slate-800/80 border border-slate-700/60"
              >
                Clear Logs
              </button>
              {isLogsDrawerOpen ? (
                <ChevronDown className="w-4 h-4 text-slate-400" />
              ) : (
                <ChevronUp className="w-4 h-4 text-slate-400" />
              )}
            </div>
          </div>

          {/* Drawer Content */}
          {isLogsDrawerOpen && (
            <div className="h-[calc(100%-40px)] p-4 overflow-y-auto font-mono text-[11px] space-y-1.5 scrollbar-thin scrollbar-thumb-slate-700">
              {streamLogs.length === 0 ? (
                <div className="h-full flex items-center justify-center text-slate-500">
                  <span>No execution events yet. Click "Run Workflow" to execute nodes via POST /api/workflow/run.</span>
                </div>
              ) : (
                streamLogs.map((log, idx) => (
                  <div key={idx} className="flex items-start gap-3 text-slate-300">
                    <span className="text-slate-500 shrink-0 select-none">[{log.timestamp}]</span>
                    <span
                      className={`font-semibold shrink-0 uppercase text-[10px] px-1.5 py-0.2 rounded border ${
                        log.event === "error" || log.event === "exec_error"
                          ? "bg-rose-950/60 border-rose-800/60 text-rose-300"
                          : log.event === "exec_success" || log.event === "workflow_complete"
                          ? "bg-emerald-950/60 border-emerald-800/60 text-emerald-300"
                          : log.event === "exec_init"
                          ? "bg-cyan-950/60 border-cyan-800/60 text-cyan-300"
                          : log.event.includes("pause")
                          ? "bg-amber-950/60 border-amber-800/60 text-amber-300"
                          : "bg-slate-800/60 border-slate-700/60 text-slate-300"
                      }`}
                    >
                      {log.event}
                    </span>
                    <span className="text-slate-300 break-all select-text">{log.detail}</span>
                  </div>
                ))
              )}
            </div>
          )}
        </div>
      </div>

      {/* Human Approval Review Modal */}
      <ApprovalReviewModal
        isOpen={isApprovalModalOpen}
        request={currentApprovalRequest}
        onClose={() => setIsApprovalModalOpen(false)}
        onDecisionComplete={async () => {
          await handleApproveGate();
        }}
      />
    </div>
  );
};
