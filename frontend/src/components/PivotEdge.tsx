import React from "react";
import { BaseEdge, EdgeLabelRenderer, EdgeProps, getBezierPath } from "@xyflow/react";
import { WorkflowEdgePayload } from "../types";

export const PivotEdge: React.FC<EdgeProps> = ({
  id,
  sourceX,
  sourceY,
  targetX,
  targetY,
  sourcePosition,
  targetPosition,
  style = {},
  markerEnd,
  data,
}) => {
  const [edgePath, labelX, labelY] = getBezierPath({
    sourceX,
    sourceY,
    sourcePosition,
    targetX,
    targetY,
    targetPosition,
  });

  const edgePayload = data?.payload as WorkflowEdgePayload | undefined;
  const pivots = edgePayload?.pivots || {};

  const totalPivots = Object.values(pivots).reduce((acc, curr) => acc + (Array.isArray(curr) ? curr.length : 0), 0);

  return (
    <>
      <BaseEdge path={edgePath} markerEnd={markerEnd} style={style} />
      {totalPivots > 0 && (
        <EdgeLabelRenderer>
          <div
            style={{
              position: "absolute",
              transform: `translate(-50%, -50%) translate(${labelX}px,${labelY}px)`,
              pointerEvents: "all",
            }}
            className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-slate-900/90 border border-cyan-500/50 backdrop-blur-md shadow-lg text-[10px] text-cyan-300 font-mono transition-transform hover:scale-110"
          >
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-ping inline-block" />
            <span className="font-semibold text-slate-200">{totalPivots} Pivots</span>
            {pivots.ips && pivots.ips.length > 0 && (
              <span className="text-emerald-400 bg-emerald-950/60 px-1 rounded">
                🌐 {pivots.ips.length}
              </span>
            )}
            {pivots.users && pivots.users.length > 0 && (
              <span className="text-amber-400 bg-amber-950/60 px-1 rounded">
                👤 {pivots.users.length}
              </span>
            )}
            {pivots.file_paths && pivots.file_paths.length > 0 && (
              <span className="text-purple-400 bg-purple-950/60 px-1 rounded">
                📁 {pivots.file_paths.length}
              </span>
            )}
          </div>
        </EdgeLabelRenderer>
      )}
    </>
  );
};
