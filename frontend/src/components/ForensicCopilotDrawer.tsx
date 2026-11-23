import React, { useState, useRef, useEffect } from "react";
import {
  Bot,
  X,
  Send,
  Sparkles,
  RefreshCw,
  Cpu,
  ToggleLeft,
  ToggleRight,
  Shield,
  Layers,
  HelpCircle,
  Minimize2,
} from "lucide-react";
import { api } from "../services/api";
import { useInvestigation } from "../context/InvestigationContext";
import { CopilotMessage } from "../types";

interface ForensicCopilotDrawerProps {
  isOpen: boolean;
  onClose: () => void;
}

export const ForensicCopilotDrawer: React.FC<ForensicCopilotDrawerProps> = ({
  isOpen,
  onClose,
}) => {
  const { caseId, wizardState, reloadSession } = useInvestigation();
  const [messages, setMessages] = useState<CopilotMessage[]>([
    {
      id: "msg-welcome",
      role: "assistant",
      content:
        "👋 Welcome, Lead Investigator. I am your ForensicOps DFIR Incident Commander.\n\n" +
        "I can actively orchestrate forensic playbooks against case vault evidence, correlate findings across Windows & Linux triage archives, evaluate competing hypotheses, and recommend next investigative actions.\n\n" +
        "What objective or artifact would you like to investigate first?",
      timestamp_utc: new Date().toISOString(),
      provider_id: "dfir_lead_commander",
      suggested_actions: [
        "🔍 Investigate Persistence",
        "📜 Check Suspicious PowerShell",
        "🌐 Sweep PCAP Network Traffic",
        "🛡️ Check Lateral Movement",
      ],
    },
  ]);
  const [inputMessage, setInputMessage] = useState<string>("");
  const [loading, setLoading] = useState<boolean>(false);
  const [sendSystemPrompt, setSendSystemPrompt] = useState<boolean>(true);
  const messagesEndRef = useRef<HTMLDivElement | null>(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    if (isOpen) {
      scrollToBottom();
    }
  }, [messages, isOpen]);

  const handleSendMessage = async (textToSend?: string) => {
    const text = (textToSend || inputMessage).trim();
    if (!text || loading) return;

    const userMsg: CopilotMessage = {
      id: `msg-${Date.now()}-user`,
      role: "user",
      content: text,
      timestamp_utc: new Date().toISOString(),
    };

    setMessages((prev) => [...prev, userMsg]);
    setInputMessage("");
    setLoading(true);

    try {
      if (text.startsWith("/goal ") || text.startsWith("/playbook ")) {
        const goalText = text.replace(/^(\/goal|\/playbook)\s+/, "");
        const draft = await api.planHypothesis({
          case_id: caseId,
          investigation_goal: goalText,
          auto_approve: true,
        });
        const executedCount = draft.plan_steps?.filter((s) => s.status === "EXECUTED").length || 0;
        const skippedCount = draft.plan_steps?.filter((s) => s.status === "SKIPPED_NO_ARTIFACT").length || 0;
        const findingsCited = draft.cited_findings?.length || 0;
        const replyText =
          `🎯 **Playbook Goal Engine Executed (Scope 3B Auto-Approve)**\n\n` +
          `**Investigative Goal:** ${draft.investigation_goal}\n` +
          `**Threat Hypothesis:** ${draft.threat_hypothesis}\n\n` +
          `**Playbook Execution Status:** ${executedCount} Executed, ${skippedCount} Skipped (No Artifact in Vault)\n` +
          `**Verified Findings Cited:** ${findingsCited} fact(s) cited strictly from DuckDB without LLM extrapolation.\n` +
          (draft.report ? `\n📄 Cited forensic report generated and ready in the Report Viewer.` : "");

        const assistantMsg: CopilotMessage = {
          id: `msg-${Date.now()}-ai`,
          role: "assistant",
          content: replyText,
          timestamp_utc: new Date().toISOString(),
          provider_id: "deterministic_goal_engine",
        };
        setMessages((prev) => [...prev, assistantMsg]);
        return;
      }

      const historyPayload = messages.map((m) => ({
        role: m.role,
        content: m.content,
      }));

      const res = await api.copilotChat({
        case_id: caseId,
        message: text,
        history: historyPayload,
        send_system_prompt: sendSystemPrompt,
      });

      const assistantMsg: CopilotMessage = {
        id: `msg-${Date.now()}-ai`,
        role: "assistant",
        content: res.reply,
        timestamp_utc: res.timestamp_utc,
        provider_id: res.provider_id,
        suggested_actions: res.suggested_actions,
        executed_playbooks: res.executed_playbooks,
        findings_count: res.findings_count,
      };

      setMessages((prev) => [...prev, assistantMsg]);
      if (reloadSession) {
        reloadSession(caseId);
      }
    } catch (err: any) {
      const errorMsg: CopilotMessage = {
        id: `msg-${Date.now()}-err`,
        role: "assistant",
        content: `Error: Failed to contact AI provider: ${err.message || err}`,
        timestamp_utc: new Date().toISOString(),
      };
      setMessages((prev) => [...prev, errorMsg]);
    } finally {
      setLoading(false);
    }
  };

  if (!isOpen) return null;

  return (
    <aside className="fixed inset-y-0 right-0 z-50 w-full sm:w-96 md:w-[420px] bg-[#0d131f] border-l border-cyan-800/60 shadow-2xl flex flex-col font-mono text-xs select-none">
      {/* Top Header */}
      <div className="p-4 border-b border-gray-800 bg-[#111827] flex items-center justify-between">
        <div className="flex items-center space-x-2.5">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-tr from-cyan-600 to-indigo-600 flex items-center justify-center text-white shadow-md shadow-cyan-500/20">
            <Bot className="w-4 h-4" />
          </div>
          <div>
            <h3 className="font-bold text-white flex items-center gap-1.5">
              <span>DFIR Technical Co-Pilot</span>
              <span className="text-[10px] px-1.5 py-0.2 rounded bg-cyan-950 border border-cyan-800 text-cyan-300">
                AI
              </span>
            </h3>
            <span className="text-[10px] text-gray-400">Case: {caseId}</span>
          </div>
        </div>

        <button
          onClick={onClose}
          className="p-1.5 text-gray-400 hover:text-white hover:bg-gray-800 rounded-lg transition-colors"
          title="Close Co-Pilot Drawer"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      {/* Settings Bar: Send System Prompt toggle */}
      <div className="px-4 py-2 border-b border-gray-800 bg-[#161f30] flex items-center justify-between text-[11px] text-gray-400">
        <div className="flex items-center space-x-1.5">
          <Shield className="w-3.5 h-3.5 text-cyan-400" />
          <span>ForensicOps Persona:</span>
        </div>
        <button
          type="button"
          onClick={() => setSendSystemPrompt(!sendSystemPrompt)}
          className="flex items-center space-x-1 text-cyan-300 hover:text-cyan-200"
          title="Toggle sending the standard DFIR system prompt vs. relying on LM Studio model preset"
        >
          {sendSystemPrompt ? (
            <span className="text-emerald-400 font-semibold">Active</span>
          ) : (
            <span className="text-amber-400 font-semibold">Model Preset</span>
          )}
          {sendSystemPrompt ? (
            <ToggleRight className="w-4 h-4 text-emerald-400" />
          ) : (
            <ToggleLeft className="w-4 h-4 text-amber-400" />
          )}
        </button>
      </div>

      {/* Chat Messages Scrollable Body */}
      <div className="flex-1 overflow-y-auto p-4 space-y-3">
        {messages.map((m) => {
          const isUser = m.role === "user";
          return (
            <div
              key={m.id}
              className={`flex flex-col ${isUser ? "items-end" : "items-start"}`}
            >
              <div
                className={`max-w-[88%] p-3 rounded-xl leading-relaxed text-xs ${
                  isUser
                    ? "bg-cyan-600 text-white rounded-br-none shadow-md shadow-cyan-950/40"
                    : "bg-[#182338] text-gray-200 border border-gray-800 rounded-bl-none shadow-md"
                }`}
              >
                {!isUser && (
                  <div className="flex items-center space-x-1.5 mb-1 pb-1 border-b border-gray-700/60 text-[10px] text-cyan-400 font-bold">
                    <Sparkles className="w-3 h-3" />
                    <span>Technical Co-Pilot</span>
                    {m.provider_id && m.provider_id !== "system" && (
                      <span className="text-gray-500 font-normal">({m.provider_id})</span>
                    )}
                  </div>
                )}
                <div className="whitespace-pre-wrap">{m.content}</div>

                {/* Interactive Action Chips for Incident Responder */}
                {!isUser && m.suggested_actions && m.suggested_actions.length > 0 && (
                  <div className="mt-3 pt-2.5 border-t border-gray-700/60">
                    <div className="text-[10px] text-cyan-300 font-bold mb-1.5 flex items-center gap-1">
                      <Sparkles className="w-3 h-3 text-cyan-400" />
                      <span>Recommended Forensic Actions (Click to Dispatch):</span>
                    </div>
                    <div className="flex flex-wrap gap-1.5">
                      {m.suggested_actions.map((act) => (
                        <button
                          key={act}
                          type="button"
                          onClick={() => handleSendMessage(act)}
                          disabled={loading}
                          className="text-left text-[11px] px-2.5 py-1 bg-cyan-950/80 hover:bg-cyan-900 border border-cyan-700/70 hover:border-cyan-400 text-cyan-200 hover:text-white rounded-lg transition-all shadow-sm active:scale-95 disabled:opacity-50"
                        >
                          {act}
                        </button>
                      ))}
                    </div>
                  </div>
                )}
              </div>
              <span className="text-[9px] text-gray-500 mt-1 px-1">
                {new Date(m.timestamp_utc).toLocaleTimeString()}
              </span>
            </div>
          );
        })}
        {loading && (
          <div className="flex items-center space-x-2 text-cyan-400 text-xs p-3 bg-[#182338] border border-gray-800 rounded-xl max-w-[70%]">
            <RefreshCw className="w-3.5 h-3.5 animate-spin" />
            <span>Analyzing case telemetry & executing playbooks...</span>
          </div>
        )}
        <div ref={messagesEndRef} />
      </div>

      {/* Quick Prompt Presets */}
      <div className="px-4 py-2 bg-[#121927] border-t border-gray-800 flex items-center gap-1.5 overflow-x-auto text-[10px]">
        {[
          "🔍 Investigate Persistence",
          "📜 Check PowerShell 4104",
          "🌐 Correlate PCAP C2",
          "🛡️ Check Lateral Movement",
          "🎯 Executive Incident Briefing",
        ].map((promptText) => (
          <button
            key={promptText}
            onClick={() => handleSendMessage(promptText)}
            disabled={loading}
            className="px-2.5 py-1 bg-gray-800/90 hover:bg-cyan-950 border border-gray-700 text-gray-300 hover:text-cyan-300 rounded-md shrink-0 transition-colors"
          >
            {promptText}
          </button>
        ))}
      </div>

      {/* Input Area */}
      <div className="p-3 bg-[#111827] border-t border-gray-800">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleSendMessage();
          }}
          className="flex items-center space-x-2"
        >
          <input
            type="text"
            value={inputMessage}
            onChange={(e) => setInputMessage(e.target.value)}
            placeholder="Ask Co-Pilot about findings, MITRE, or pivots..."
            className="flex-1 bg-[#161f30] border border-gray-700 rounded-xl px-3.5 py-2 text-xs text-white placeholder-gray-500 focus:outline-none focus:border-cyan-500"
          />
          <button
            type="submit"
            disabled={loading || !inputMessage.trim()}
            className="p-2 bg-cyan-600 hover:bg-cyan-500 active:bg-cyan-700 disabled:opacity-50 text-white rounded-xl shadow-md shadow-cyan-950/40 transition-colors"
          >
            <Send className="w-4 h-4" />
          </button>
        </form>
      </div>
    </aside>
  );
};
