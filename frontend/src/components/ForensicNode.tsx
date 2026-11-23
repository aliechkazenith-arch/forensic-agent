import React from "react";
import { Handle, Position, NodeProps } from "@xyflow/react";
import {
  Database,
  Cpu,
  Terminal,
  Sparkles,
  ShieldAlert,
  FileText,
  CheckCircle2,
  Clock,
  AlertTriangle,
  Loader2,
} from "lucide-react";
import { NodeType } from "../types";

export interface ForensicNodeData {
  label: string;
  nodeType: NodeType;
  config: Record<string, any>;
  status?: "idle" | "running" | "completed" | "paused" | "failed" | "skipped_no_artifact";
  summary?: string;
  claimCount?: number;
  outputCount?: number;
  [key: string]: any;
}

export const ForensicNode: React.FC<NodeProps> = ({ id, data, selected }) => {
  const nodeData = data as unknown as ForensicNodeData;
  const status = nodeData.status || "idle";
  const nodeType = nodeData.nodeType || "tool_runner";

  const getTypeTheme = () => {
    switch (nodeType) {
      case "evidence_input":
        return {
          border: "border-cyan-500/60",
          glow: "shadow-cyan-950/40",
          headerBg: "bg-cyan-950/60 text-cyan-400",
          badge: "bg-cyan-900/60 text-cyan-300 border-cyan-700/50",
          icon: Database,
        };
      case "dissect_parser":
        return {
          border: "border-emerald-500/60",
          glow: "shadow-emerald-950/40",
          headerBg: "bg-emerald-950/60 text-emerald-400",
          badge: "bg-emerald-900/60 text-emerald-300 border-emerald-700/50",
          icon: Cpu,
        };
      case "tool_runner":
        return {
          border: "border-amber-500/60",
          glow: "shadow-amber-950/40",
          headerBg: "bg-amber-950/60 text-amber-400",
          badge: "bg-amber-900/60 text-amber-300 border-amber-700/50",
          icon: Terminal,
        };
      case "ai_goal_step":
        return {
          border: "border-purple-500/60",
          glow: "shadow-purple-950/40",
          headerBg: "bg-purple-950/60 text-purple-300",
          badge: "bg-purple-900/60 text-purple-200 border-purple-700/50",
          icon: Sparkles,
        };
      case "human_approval_gate":
        return {
          border: "border-rose-500/70",
          glow: "shadow-rose-950/50",
          headerBg: "bg-rose-950/60 text-rose-300",
          badge: "bg-rose-900/60 text-rose-200 border-rose-700/50",
          icon: ShieldAlert,
        };
      case "report_compiler":
        return {
          border: "border-blue-500/60",
          glow: "shadow-blue-950/40",
          headerBg: "bg-blue-950/60 text-blue-300",
          badge: "bg-blue-900/60 text-blue-200 border-blue-700/50",
          icon: FileText,
        };
      default:
        return {
          border: "border-gray-500/60",
          glow: "shadow-gray-950/40",
          headerBg: "bg-gray-800 text-gray-300",
          badge: "bg-gray-800 text-gray-300 border-gray-600",
          icon: Terminal,
        };
    }
  };

  const theme = getTypeTheme();
  const IconComponent = theme.icon;

  const renderStatusBadge = () => {
    if (nodeData.config?.status === "SKIPPED_NO_ARTIFACT" || status === "skipped_no_artifact") {
      return (
        <span className="flex items-center gap-1 text-[10px] uppercase font-semibold tracking-wider text-amber-300 bg-amber-950/80 px-2 py-0.5 rounded-full border border-amber-600/50">
          <AlertTriangle className="w-2.5 h-2.5 text-amber-400" /> SKIPPED (NO ARTIFACT)
        </span>
      );
    }
    switch (status) {
      case "running":
        return (
          <span className="flex items-center gap-1 text-[10px] uppercase font-semibold tracking-wider text-cyan-400 bg-cyan-950/80 px-2 py-0.5 rounded-full border border-cyan-500/40 animate-pulse">
            <Loader2 className="w-2.5 h-2.5 animate-spin" /> RUNNING
          </span>
        );
      case "completed":
        return (
          <span className="flex items-center gap-1 text-[10px] uppercase font-semibold tracking-wider text-emerald-400 bg-emerald-950/80 px-2 py-0.5 rounded-full border border-emerald-500/40">
            <CheckCircle2 className="w-2.5 h-2.5" /> DONE
          </span>
        );
      case "paused":
        return (
          <span className="flex items-center gap-1 text-[10px] uppercase font-semibold tracking-wider text-amber-400 bg-amber-950/80 px-2 py-0.5 rounded-full border border-amber-500/40">
            <Clock className="w-2.5 h-2.5" /> GATE PAUSE
          </span>
        );
      case "failed":
        return (
          <span className="flex items-center gap-1 text-[10px] uppercase font-semibold tracking-wider text-rose-400 bg-rose-950/80 px-2 py-0.5 rounded-full border border-rose-500/40">
            <AlertTriangle className="w-2.5 h-2.5" /> FAILED
          </span>
        );
      default:
        return (
          <span className="text-[10px] uppercase font-semibold tracking-wider text-slate-500 bg-slate-800/80 px-2 py-0.5 rounded-full border border-slate-700">
            IDLE
          </span>
        );
    }
  };

  return (
    <div
      className={`relative rounded-xl border bg-slate-900/95 backdrop-blur-md shadow-2xl transition-all duration-200 min-w-[270px] max-w-[340px] text-slate-200 ${
        theme.border
      } ${theme.glow} ${selected ? "ring-2 ring-cyan-400 scale-[1.02]" : ""}`}
    >
      {/* Handles */}
      <Handle
        type="target"
        position={Position.Left}
        className="!w-3 !h-3 !-left-1.5 !bg-cyan-400 !border-2 !border-slate-950"
      />
      <Handle
        type="source"
        position={Position.Right}
        className="!w-3 !h-3 !-right-1.5 !bg-cyan-400 !border-2 !border-slate-950"
      />

      {/* Header */}
      <div className={`flex items-center justify-between px-3.5 py-2.5 border-b border-slate-800/80 rounded-t-xl ${theme.headerBg}`}>
        <div className="flex items-center gap-2">
          <IconComponent className="w-4 h-4 shrink-0" />
          <div className="font-semibold text-xs tracking-wide truncate max-w-[150px]">
            {nodeData.label || id}
          </div>
        </div>
        <div>{renderStatusBadge()}</div>
      </div>

      {/* Body */}
      <div className="p-3 text-xs space-y-2">
        <div className="flex items-center justify-between text-[11px] text-slate-400">
          <span className="font-mono text-slate-500 uppercase">{nodeType.replace("_", " ")}</span>
          {nodeData.claimCount !== undefined && nodeData.claimCount > 0 && (
            <span className="text-purple-300 bg-purple-950/70 border border-purple-800/50 px-1.5 py-0.5 rounded text-[10px] font-mono">
              ★ {nodeData.claimCount} Claims
            </span>
          )}
        </div>

        {/* Configuration summary / AI prompt */}
        {nodeData.config && Object.keys(nodeData.config).length > 0 && (
          <div className="bg-slate-950/70 rounded-md p-2 border border-slate-800 font-mono text-[11px] space-y-1">
            {nodeData.config.tool_id && (
              <div className="flex justify-between">
                <span className="text-slate-500">Tool:</span>
                <span className="text-amber-300 font-semibold">{nodeData.config.tool_id}</span>
              </div>
            )}
            {nodeData.config.target_artifact && (
              <div className="flex justify-between">
                <span className="text-slate-500">Artifact:</span>
                <span className="text-cyan-300 truncate max-w-[150px]">{nodeData.config.target_artifact}</span>
              </div>
            )}
            {nodeData.config.goal_description && (
              <div className="space-y-0.5 pt-1 border-t border-slate-800/60">
                <span className="text-purple-400 font-sans font-medium flex items-center gap-1">
                  <Sparkles className="w-3 h-3" /> AI Goal:
                </span>
                <p className="text-slate-300 text-[10px] font-sans line-clamp-2 leading-relaxed">
                  {nodeData.config.goal_description}
                </p>
              </div>
            )}
            {nodeData.config.required_actor && (
              <div className="flex justify-between text-rose-300">
                <span className="text-slate-500">Gate Actor:</span>
                <span>{nodeData.config.required_actor}</span>
              </div>
            )}
          </div>
        )}

        {/* Execution Summary / Result */}
        {nodeData.summary && (
          <div className="bg-emerald-950/30 border border-emerald-900/40 rounded p-2 text-[10px] text-emerald-300 line-clamp-2">
            ✓ {nodeData.summary}
          </div>
        )}
      </div>
    </div>
  );
};
