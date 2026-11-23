import React, { useEffect, useState } from "react";
import {
  ShieldCheck,
  ShieldAlert,
  X,
  RefreshCw,
  Hash,
  Clock,
  User,
  Terminal,
  Lock,
  Download,
  FileCode,
} from "lucide-react";
import { useForensicStore } from "../store/useForensicStore";
import { api, triggerBrowserDownload } from "../services/api";

interface CustodyLedgerModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const CustodyLedgerModal: React.FC<CustodyLedgerModalProps> = ({
  isOpen,
  onClose,
}) => {
  const {
    currentCaseId,
    custodyEntries,
    isChainValid,
    setCustodyEntries,
  } = useForensicStore();
  const [isVerifying, setIsVerifying] = useState<boolean>(false);
  const [isExporting, setIsExporting] = useState<boolean>(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const fetchAndVerifyCustody = async () => {
    setIsVerifying(true);
    setErrorMsg(null);
    try {
      const data = await api.getCustodyLedger(currentCaseId);
      setCustodyEntries(data.entries, data.is_tamper_free);
    } catch (err: any) {
      setErrorMsg(`Failed to query custody ledger: ${err.message}`);
    } finally {
      setIsVerifying(false);
    }
  };

  const handleExportCustody = async (format: "jsonl" | "json") => {
    setIsExporting(true);
    setErrorMsg(null);
    try {
      const { blob, filename } = await api.exportCustodyLedger(currentCaseId, format);
      triggerBrowserDownload(blob, filename);
    } catch (err: any) {
      setErrorMsg(`Custody export failed: ${err.message}`);
    } finally {
      setIsExporting(false);
    }
  };

  useEffect(() => {
    if (isOpen) {
      fetchAndVerifyCustody();
    }
  }, [isOpen, currentCaseId]);

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-slate-950/85 backdrop-blur-md flex items-center justify-center z-50 p-6 animate-in fade-in duration-200">
      <div className="bg-slate-900 border border-slate-700/80 rounded-2xl w-full max-w-4xl shadow-2xl overflow-hidden flex flex-col max-h-[85vh]">
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-800 bg-slate-950/70 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-emerald-950/70 border border-emerald-500/50 rounded-lg text-emerald-400">
              <Lock className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-base font-bold text-slate-100">
                  Append-Only Chain of Custody Audit
                </h2>
                <span className="text-xs text-slate-400 font-mono">[{currentCaseId}]</span>
              </div>
              <p className="text-xs text-slate-400">
                RFC 3227, ISO 27037 & NIST SP 800-86 Cryptographic Audit Ledger
              </p>
            </div>
          </div>
          <button onClick={onClose} className="text-slate-400 hover:text-slate-200 transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Verification Status Banner */}
        <div className="px-6 py-3.5 bg-slate-950/50 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-3">
            {isChainValid ? (
              <div className="flex items-center gap-2 text-emerald-400 bg-emerald-950/80 border border-emerald-500/50 px-3 py-1.5 rounded-full text-xs font-semibold tracking-wide">
                <ShieldCheck className="w-4 h-4" />
                <span>IMMUTABLE HASH CHAIN VALID — ZERO TAMPER DETECTED</span>
              </div>
            ) : (
              <div className="flex items-center gap-2 text-rose-400 bg-rose-950/80 border border-rose-500/50 px-3 py-1.5 rounded-full text-xs font-semibold tracking-wide animate-pulse">
                <ShieldAlert className="w-4 h-4" />
                <span>INTEGRITY WARNING: HASH CHAIN DISCREPANCY DETECTED</span>
              </div>
            )}
            <span className="text-xs text-slate-400 font-mono">
              {custodyEntries.length} chained entries
            </span>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => handleExportCustody("jsonl")}
              disabled={isExporting}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-950/70 hover:bg-emerald-900/80 text-emerald-300 text-xs font-medium border border-emerald-700/60 transition-colors disabled:opacity-50"
              title="Export append-only chain of custody as JSONL"
            >
              <Download className="w-3.5 h-3.5" />
              <span>{isExporting ? "Exporting..." : "Export .JSONL"}</span>
            </button>

            <button
              onClick={() => handleExportCustody("json")}
              disabled={isExporting}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium border border-slate-700 transition-colors disabled:opacity-50"
              title="Export append-only chain of custody as JSON"
            >
              <FileCode className="w-3.5 h-3.5" />
              <span>Export .JSON</span>
            </button>

            <button
              onClick={fetchAndVerifyCustody}
              disabled={isVerifying}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium border border-slate-700 transition-colors"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isVerifying ? "animate-spin text-cyan-400" : ""}`} />
              <span>Re-verify Chain</span>
            </button>
          </div>
        </div>

        {errorMsg && (
          <div className="mx-6 mt-4 p-3 bg-rose-950/80 border border-rose-800 rounded-lg text-xs text-rose-300">
            {errorMsg}
          </div>
        )}

        {/* Chronological Table */}
        <div className="p-6 overflow-y-auto flex-1">
          {custodyEntries.length === 0 ? (
            <div className="text-center py-12 text-slate-500 text-xs italic">
              No custody records logged yet for case {currentCaseId}. Ingest evidence or run workflows to initialize the chain.
            </div>
          ) : (
            <div className="border border-slate-800 rounded-xl overflow-hidden shadow-sm">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="bg-slate-950 border-b border-slate-800 text-slate-400 text-[11px] font-mono uppercase">
                    <th className="p-3">Seq</th>
                    <th className="p-3">UTC Timestamp</th>
                    <th className="p-3">Actor</th>
                    <th className="p-3">Action</th>
                    <th className="p-3">Artifact SHA-256</th>
                    <th className="p-3">Prev Hash</th>
                    <th className="p-3">Entry Hash</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono text-[11px] text-slate-300">
                  {custodyEntries.map((e) => (
                    <tr key={e.seq_id} className="hover:bg-slate-800/40 transition-colors">
                      <td className="p-3 text-cyan-400 font-bold">#{e.seq_id}</td>
                      <td className="p-3 text-slate-400 whitespace-nowrap">
                        {e.timestamp_utc?.substring(0, 19).replace("T", " ")}
                      </td>
                      <td className="p-3 text-slate-200">
                        <span className="bg-slate-800 px-1.5 py-0.5 rounded text-[10px]">
                          {e.actor}
                        </span>
                      </td>
                      <td className="p-3 text-emerald-400 font-semibold">{e.action}</td>
                      <td className="p-3 text-slate-400 truncate max-w-[130px]" title={e.artifact_sha256 || ""}>
                        {e.artifact_sha256 ? `${e.artifact_sha256.substring(0, 12)}...` : "-"}
                      </td>
                      <td className="p-3 text-slate-500 truncate max-w-[110px]" title={e.prev_hash}>
                        {e.prev_hash ? `${e.prev_hash.substring(0, 10)}...` : "-"}
                      </td>
                      <td className="p-3 text-cyan-300 font-semibold truncate max-w-[110px]" title={e.entry_hash}>
                        {e.entry_hash ? `${e.entry_hash.substring(0, 10)}...` : "-"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-3 bg-slate-950/80 border-t border-slate-800 flex items-center justify-between text-xs text-slate-500">
          <span>SHA-256 Hash Chaining: entry_hash = SHA256(prev_hash + actor + action + sha256 + timestamp)</span>
          <button
            onClick={onClose}
            className="px-4 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
