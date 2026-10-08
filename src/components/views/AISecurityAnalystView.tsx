/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { Incident, SecurityEvent, AIAnalysisResult } from '../../types/security';
import { SeverityBadge, DetectionMethodBadge } from '../common/SeverityBadge';
import {
  Sparkles,
  Send,
  ShieldAlert,
  CheckCircle2,
  AlertTriangle,
  HelpCircle,
  Cpu,
  Terminal,
  Activity,
  Layers,
  Search,
} from 'lucide-react';
import { analyzeEventWithAI, queryAIAnalyst } from '../../services/aiAnalystClient';

interface AISecurityAnalystViewProps {
  events: SecurityEvent[];
  incidents: Incident[];
  onUpdateEvent: (updated: SecurityEvent) => void;
  onSelectEvent: (event: SecurityEvent) => void;
}

export const AISecurityAnalystView: React.FC<AISecurityAnalystViewProps> = ({
  events,
  incidents,
  onUpdateEvent,
  onSelectEvent,
}) => {
  const [selectedEventId, setSelectedEventId] = useState<string>(
    events.find((e) => e.severity === 'CRITICAL' || e.severity === 'HIGH')?.event_id || events[0]?.event_id || ''
  );
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [activeAnalysis, setActiveAnalysis] = useState<AIAnalysisResult | null>(null);

  // Copilot Query State
  const [userQuery, setUserQuery] = useState('');
  const [queryLoading, setQueryLoading] = useState(false);
  const [chatHistory, setChatHistory] = useState<Array<{ sender: 'user' | 'ai'; text: string; timestamp: string }>>([
    {
      sender: 'ai',
      text: 'Greetings, SOC Analyst. I am SentinelAI Security Analyst (Gemini 3.8 Flash). All findings and timelines are strictly grounded in your active telemetry logs. How can I assist with threat triage or incident response today?',
      timestamp: new Date().toLocaleTimeString(),
    },
  ]);

  const selectedEvent = events.find((e) => e.event_id === selectedEventId) || events[0];

  const handleRunEventAnalysis = async () => {
    if (!selectedEvent) return;
    setIsAnalyzing(true);
    try {
      const result = await analyzeEventWithAI(selectedEvent);
      setActiveAnalysis(result);
      const updated: SecurityEvent = {
        ...selectedEvent,
        ai_analysis: result,
        detection_method: selectedEvent.detection_method === 'RULE' ? 'RULE_AND_AI' : 'AI',
        severity: result.severity,
        risk_score: Math.max(selectedEvent.risk_score, result.risk_score),
      };
      onUpdateEvent(updated);
    } catch (err) {
      console.error(err);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleSendQuery = async (queryText?: string) => {
    const text = queryText || userQuery;
    if (!text.trim()) return;

    const userMsg = {
      sender: 'user' as const,
      text: text.trim(),
      timestamp: new Date().toLocaleTimeString(),
    };

    setChatHistory((prev) => [...prev, userMsg]);
    if (!queryText) setUserQuery('');
    setQueryLoading(true);

    try {
      const answer = await queryAIAnalyst(text, events, incidents);
      setChatHistory((prev) => [
        ...prev,
        {
          sender: 'ai' as const,
          text: answer,
          timestamp: new Date().toLocaleTimeString(),
        },
      ]);
    } catch (err) {
      setChatHistory((prev) => [
        ...prev,
        {
          sender: 'ai' as const,
          text: 'Error contacting AI Analyst. Please check server connection.',
          timestamp: new Date().toLocaleTimeString(),
        },
      ]);
    } finally {
      setQueryLoading(false);
    }
  };

  const currentDisplayAnalysis = activeAnalysis || selectedEvent?.ai_analysis;

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 shadow-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="p-1.5 rounded-lg bg-slate-800 text-purple-300">
              <Sparkles className="w-5 h-5" />
            </span>
            <h2 className="text-base font-semibold text-white">
              AI Security Analyst & Forensic Investigator
            </h2>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-slate-300 border border-slate-700">
              MODEL: GEMINI 3.8 FLASH
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Grounded forensic corroboration, structured risk scoring, evidence attribution, and SOC playbooks
          </p>
        </div>

        <div className="flex items-center gap-2 text-xs font-mono text-slate-400 bg-slate-950 px-3 py-2 rounded-lg border border-slate-800">
          <span className="w-2 h-2 rounded-full bg-emerald-400" />
          <span>Strict Zero-Hallucination Guardrail: Active</span>
        </div>
      </div>

      {/* Main Grid: Left = Deep Event Analysis; Right = Interactive Copilot Chat */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Deep Event Structured Analysis */}
        <div className="lg:col-span-7 space-y-4">
          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 shadow-sm space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div>
                <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 text-purple-400" />
                  Target Event Deep Investigation
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">Select any ingested event to analyze with Gemini</p>
              </div>

              {/* Event Dropdown Selector */}
              <div className="w-full sm:w-60">
                <select
                  value={selectedEventId}
                  onChange={(e) => {
                    setSelectedEventId(e.target.value);
                    setActiveAnalysis(null);
                  }}
                  className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-purple-500 font-mono"
                >
                  {events.map((ev) => (
                    <option key={ev.event_id} value={ev.event_id}>
                      [{ev.event_id}] {ev.severity} - {ev.asset} ({ev.threat_category})
                    </option>
                  ))}
                </select>
              </div>
            </div>

            {/* Selected Event Card Preview */}
            {selectedEvent && (
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800/90 text-xs space-y-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-cyan-400 font-bold">{selectedEvent.event_id}</span>
                    <SeverityBadge severity={selectedEvent.severity} />
                    <DetectionMethodBadge method={selectedEvent.detection_method} />
                    <span className="text-slate-400 font-mono text-[11px]">{selectedEvent.threat_category}</span>
                  </div>
                  <span className="font-mono text-slate-400 text-[11px]">
                    {new Date(selectedEvent.timestamp).toLocaleTimeString()}
                  </span>
                </div>

                <p className="text-slate-200 font-medium">{selectedEvent.message}</p>

                <div className="flex flex-wrap items-center justify-between gap-2 pt-1 border-t border-slate-900 font-mono text-[11px] text-slate-400">
                  <span>
                    SRC: {selectedEvent.source_ip}:{selectedEvent.source_port} &rarr; DST:{' '}
                    {selectedEvent.destination_ip}:{selectedEvent.destination_port}
                  </span>
                  <span>Asset: {selectedEvent.asset}</span>
                </div>
              </div>
            )}

            {/* Analyze Action Button */}
            <div>
              <button
                onClick={handleRunEventAnalysis}
                disabled={isAnalyzing || !selectedEvent}
                className="w-full py-2.5 px-4 rounded-lg bg-purple-600 hover:bg-purple-500 disabled:opacity-50 text-white font-semibold text-xs flex items-center justify-center gap-2 transition shadow-lg shadow-purple-950/40"
              >
                <Sparkles className="w-4 h-4" />
                {isAnalyzing ? 'Executing Gemini 3.8 Flash Analysis...' : 'Run Grounded AI Security Analysis'}
              </button>
            </div>

            {/* Structured Results Display */}
            {currentDisplayAnalysis ? (
              <div className="p-4 rounded-xl bg-purple-950/20 border border-purple-800/60 space-y-4 text-xs">
                {/* Metrics Header */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                  <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
                    <span className="text-[11px] text-slate-400 block mb-0.5">Assessed Threat</span>
                    <span className="font-semibold text-purple-300">
                      {currentDisplayAnalysis.threat_category}
                    </span>
                  </div>
                  <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
                    <span className="text-[11px] text-slate-400 block mb-0.5">Severity Tier</span>
                    <SeverityBadge severity={currentDisplayAnalysis.severity} />
                  </div>
                  <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
                    <span className="text-[11px] text-slate-400 block mb-0.5">Risk Score</span>
                    <span className="font-mono font-bold text-red-400 text-sm">
                      {currentDisplayAnalysis.risk_score}/100
                    </span>
                  </div>
                  <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
                    <span className="text-[11px] text-slate-400 block mb-0.5">Analyst Confidence</span>
                    <span className="font-mono font-bold text-emerald-400 text-sm">
                      {currentDisplayAnalysis.confidence}%
                    </span>
                  </div>
                </div>

                {/* Assessment Verdict Banner */}
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs space-y-1">
                  <span className="text-[10px] uppercase font-mono tracking-wider text-purple-300 font-bold block">
                    Analytical Assessment Verdict:
                  </span>
                  <p className="text-slate-100 font-medium leading-relaxed">
                    {currentDisplayAnalysis.assessment}
                  </p>
                </div>

                {/* Reasoning Summary & Severity Justification */}
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs space-y-1">
                  <h4 className="font-semibold uppercase tracking-wider text-slate-400 text-[11px] font-mono">
                    Severity Justification & Inference Breakdown:
                  </h4>
                  <p className="text-slate-300 leading-relaxed font-sans text-xs">
                    {currentDisplayAnalysis.reasoning_summary}
                  </p>
                </div>

                {/* Grounded Evidence List */}
                <div>
                  <h4 className="font-semibold uppercase tracking-wider text-slate-400 text-[11px] mb-1 font-mono">
                    Grounded Log Evidence (No Invented Data):
                  </h4>
                  <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
                    {currentDisplayAnalysis.evidence.map((ev, i) => (
                      <div key={i} className="flex items-start gap-2 font-mono text-[11px] text-cyan-300/90">
                        <span className="text-slate-500">&bull;</span>
                        <span>{ev}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Recommended Defensive Actions */}
                <div>
                  <h4 className="font-semibold uppercase tracking-wider text-slate-400 text-[11px] mb-1 font-mono">
                    Recommended Defensive Actions (No Offensive Commands):
                  </h4>
                  <div className="space-y-1.5">
                    {currentDisplayAnalysis.recommended_actions.map((act, i) => (
                      <div key={i} className="flex items-start gap-2 p-2 rounded bg-slate-950 border border-slate-800 text-slate-200">
                        <CheckCircle2 className="w-3.5 h-3.5 text-purple-400 shrink-0 mt-0.5" />
                        <span className="text-xs">{act}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Additional Information Needed */}
                <div>
                  <h4 className="font-semibold uppercase tracking-wider text-slate-400 text-[11px] mb-1 font-mono">
                    Additional Information Needed (Evidence Gaps):
                  </h4>
                  <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 space-y-1 text-slate-300 text-[11px]">
                    {(currentDisplayAnalysis.additional_information_needed || []).map((info, i) => (
                      <div key={i} className="flex items-start gap-1.5">
                        <span className="text-cyan-400 font-mono shrink-0">&bull;</span>
                        <span>{info}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* False Positive Rating */}
                <div className="flex items-center justify-between pt-2 border-t border-purple-900/60 text-xs">
                  <span className="text-slate-400">False Positive Possibility:</span>
                  <span
                    className={`font-semibold px-2 py-0.5 rounded font-mono ${
                      currentDisplayAnalysis.false_positive_possibility === 'LOW'
                        ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                        : 'bg-amber-950 text-amber-300 border border-amber-800'
                    }`}
                  >
                    {currentDisplayAnalysis.false_positive_possibility}
                  </span>
                </div>
              </div>
            ) : (
              <div className="p-8 text-center text-slate-500 text-xs bg-slate-950 rounded-lg border border-slate-800">
                Click &quot;Run Grounded AI Security Analysis&quot; above to inspect event telemetry with Gemini.
              </div>
            )}
          </div>
        </div>

        {/* Right Column: Interactive SOC Copilot Workbench */}
        <div className="lg:col-span-5 flex flex-col h-[700px] p-5 rounded-xl bg-slate-900 border border-slate-800 shadow-sm">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <div className="flex items-center gap-2">
              <Terminal className="w-4 h-4 text-cyan-400" />
              <h3 className="text-sm font-semibold text-white">Analyst Copilot Workbench</h3>
            </div>
            <span className="text-[11px] font-mono text-slate-400">Interactive Triage</span>
          </div>

          {/* Quick Prompt Pills */}
          <div className="py-3 space-y-1.5 border-b border-slate-800/80">
            <span className="text-[10px] uppercase font-mono text-slate-500 font-semibold block">
              Quick Forensic Queries:
            </span>
            <div className="flex flex-wrap gap-1.5">
              {[
                'Investigate IP 203.0.113.88 attack progression',
                'Assess root cause of jump-bastion-01 privilege escalation',
                'Check logs for data exfiltration indicators',
                'List immediate containment steps for critical alerts',
              ].map((p, idx) => (
                <button
                  key={idx}
                  onClick={() => handleSendQuery(p)}
                  className="px-2 py-1 rounded bg-slate-950 hover:bg-slate-800 border border-slate-800 text-[11px] text-slate-300 transition text-left"
                >
                  {p}
                </button>
              ))}
            </div>
          </div>

          {/* Message Thread */}
          <div className="flex-1 overflow-y-auto py-3 space-y-3 text-xs">
            {chatHistory.map((msg, i) => (
              <div
                key={i}
                className={`p-3 rounded-lg leading-relaxed ${
                  msg.sender === 'user'
                    ? 'bg-cyan-950/60 border border-cyan-800/70 text-cyan-100 ml-4'
                    : 'bg-slate-950 border border-slate-800 text-slate-200 mr-4 whitespace-pre-wrap'
                }`}
              >
                <div className="flex items-center justify-between text-[10px] text-slate-400 mb-1 font-mono">
                  <span>{msg.sender === 'user' ? 'SOC Analyst' : 'SentinelAI Copilot'}</span>
                  <span>{msg.timestamp}</span>
                </div>
                <div>{msg.text}</div>
              </div>
            ))}
            {queryLoading && (
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-slate-400 text-xs flex items-center gap-2">
                <Sparkles className="w-3.5 h-3.5 text-purple-400 animate-spin" />
                <span>Correlating telemetry across all events...</span>
              </div>
            )}
          </div>

          {/* Input Box */}
          <form
            onSubmit={(e) => {
              e.preventDefault();
              handleSendQuery();
            }}
            className="pt-3 border-t border-slate-800 flex gap-2"
          >
            <input
              type="text"
              placeholder="Ask analyst copilot about any IP, asset, or pattern..."
              value={userQuery}
              onChange={(e) => setUserQuery(e.target.value)}
              className="flex-1 px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
            />
            <button
              type="submit"
              disabled={queryLoading || !userQuery.trim()}
              className="px-3.5 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white text-xs font-semibold flex items-center gap-1.5 transition"
            >
              <Send className="w-3.5 h-3.5" />
            </button>
          </form>
        </div>
      </div>
    </div>
  );
};
