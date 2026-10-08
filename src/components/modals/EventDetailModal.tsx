/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { EventStatus, SecurityEvent } from '../../types/security';
import { SeverityBadge, DetectionMethodBadge } from '../common/SeverityBadge';
import {
  X,
  Sparkles,
  ShieldAlert,
  Terminal,
  Clock,
  HardDrive,
  Cpu,
  Layers,
  ArrowRight,
  CheckCircle,
  Copy,
  PlusCircle,
  AlertTriangle,
  RotateCcw,
  Check,
} from 'lucide-react';
import { analyzeEventWithAI } from '../../services/aiAnalystClient';

interface EventDetailModalProps {
  event: SecurityEvent | null;
  onClose: () => void;
  onUpdateEvent: (updated: SecurityEvent) => void;
  onCreateIncidentFromEvent: (event: SecurityEvent) => void;
}

export const EventDetailModal: React.FC<EventDetailModalProps> = ({
  event,
  onClose,
  onUpdateEvent,
  onCreateIncidentFromEvent,
}) => {
  const [analyzing, setAnalyzing] = useState(false);
  const [analysisError, setAnalysisError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  if (!event) return null;

  const handleRunAI = async () => {
    setAnalyzing(true);
    setAnalysisError(null);
    try {
      const result = await analyzeEventWithAI(event);
      const updated: SecurityEvent = {
        ...event,
        ai_analysis: result,
        detection_method: event.detection_method === 'RULE' ? 'RULE_AND_AI' : 'AI',
        severity: result.severity,
        risk_score: Math.max(event.risk_score, result.risk_score),
      };
      onUpdateEvent(updated);
    } catch (err: any) {
      console.error(err);
      setAnalysisError(err?.message || 'Failed to communicate with AI analyst model. Click to retry.');
    } finally {
      setAnalyzing(false);
    }
  };

  const handleStatusChange = (newStatus: EventStatus) => {
    const updated: SecurityEvent = {
      ...event,
      status: newStatus,
    };
    onUpdateEvent(updated);
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(JSON.stringify(event, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4 overflow-y-auto">
      <div className="relative w-full max-w-4xl max-h-[92vh] flex flex-col bg-slate-900 border border-slate-800 rounded-xl shadow-2xl text-slate-100 overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-slate-950/70">
          <div className="flex items-center gap-3">
            <span className="p-2 rounded-lg bg-slate-800/80 text-cyan-400">
              <ShieldAlert className="w-5 h-5" />
            </span>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-mono text-sm text-cyan-400 font-bold">{event.event_id}</span>
                <SeverityBadge severity={event.severity} />
                <DetectionMethodBadge method={event.detection_method} />
                <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono">
                  {event.status}
                </span>
              </div>
              <h3 className="text-base font-semibold text-white mt-0.5">{event.message}</h3>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={handleCopy}
              className="px-2.5 py-1.5 text-xs text-slate-300 bg-slate-800 hover:bg-slate-700 rounded flex items-center gap-1.5 transition"
              title="Copy event JSON"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              {copied ? 'Copied' : 'JSON'}
            </button>
            <button
              onClick={onClose}
              className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6 text-sm">
          {/* Key Metrics Strip */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800/90">
              <span className="text-xs text-slate-400 flex items-center gap-1 mb-1">
                <Clock className="w-3.5 h-3.5 text-slate-500" /> Timestamp
              </span>
              <p className="font-mono text-xs text-slate-200">{new Date(event.timestamp).toLocaleString()}</p>
            </div>
            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800/90">
              <span className="text-xs text-slate-400 flex items-center gap-1 mb-1">
                <HardDrive className="w-3.5 h-3.5 text-slate-500" /> Target Asset
              </span>
              <p className="font-semibold text-slate-200">{event.asset}</p>
            </div>
            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800/90">
              <span className="text-xs text-slate-400 flex items-center gap-1 mb-1">
                <Layers className="w-3.5 h-3.5 text-slate-500" /> Threat Category
              </span>
              <p className="font-medium text-amber-300">{event.threat_category}</p>
            </div>
            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800/90">
              <span className="text-xs text-slate-400 flex items-center gap-1 mb-1">
                <Cpu className="w-3.5 h-3.5 text-slate-500" /> Risk Score
              </span>
              <div className="flex items-center gap-2">
                <span className="font-mono text-base font-bold text-red-400">{event.risk_score}/100</span>
                <div className="flex-1 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-gradient-to-r from-yellow-500 to-red-500 rounded-full"
                    style={{ width: `${Math.min(100, event.risk_score)}%` }}
                  />
                </div>
              </div>
            </div>
          </div>

          {/* Network Telemetry Flow */}
          <div className="p-4 rounded-lg bg-slate-950 border border-slate-800">
            <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-3">
              Network Flow & Endpoint Metadata
            </h4>
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 py-2 px-3 bg-slate-900/80 rounded border border-slate-800/80 font-mono text-xs">
              <div className="flex items-center gap-2">
                <span className="text-slate-400">SOURCE:</span>
                <span className="font-bold text-cyan-300">{event.source_ip}</span>
                <span className="text-slate-500">:{event.source_port}</span>
              </div>
              <div className="flex items-center gap-2 text-slate-500">
                <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-sans font-medium text-[11px]">
                  {event.protocol}
                </span>
                <ArrowRight className="w-4 h-4 text-cyan-500" />
              </div>
              <div className="flex items-center gap-2">
                <span className="text-slate-400">DEST:</span>
                <span className="font-bold text-cyan-300">{event.destination_ip}</span>
                <span className="text-slate-500">:{event.destination_port}</span>
              </div>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mt-3 text-xs">
              <div>
                <span className="text-slate-500 block">Device</span>
                <span className="font-medium text-slate-300">{event.device} ({event.device_type})</span>
              </div>
              <div>
                <span className="text-slate-500 block">Action</span>
                <span className={`font-mono font-bold ${event.action === 'ALLOW' || event.action === 'SUCCESS' ? 'text-emerald-400' : 'text-red-400'}`}>
                  {event.action}
                </span>
              </div>
              <div>
                <span className="text-slate-500 block">User Context</span>
                <span className="font-mono text-slate-300">{event.username || 'N/A'}</span>
              </div>
              <div>
                <span className="text-slate-500 block">Payload / Volume</span>
                <span className="text-slate-300">
                  {event.bytes_transferred ? `${(event.bytes_transferred / 1024).toFixed(1)} KB` : 'N/A'} (
                  {event.packets || 0} pkts)
                </span>
              </div>
            </div>
          </div>

          {/* Detection Analysis: Deterministic Rule vs AI */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Deterministic Rule Engine Box */}
            <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-2">
              <div className="flex items-center justify-between">
                <h4 className="text-xs font-semibold uppercase tracking-wider text-emerald-400 flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-emerald-500" />
                  Deterministic Rule Match
                </h4>
                {event.rule_id && (
                  <span className="text-[11px] font-mono text-slate-400 bg-slate-900 px-1.5 py-0.5 rounded border border-slate-800">
                    {event.rule_id}
                  </span>
                )}
              </div>
              <p className="text-xs text-slate-300 leading-relaxed font-sans">
                {event.detection_reason || 'Standard operational log telemetry (No deterministic rule triggered).'}
              </p>
              {event.mitre_attack && (
                <div className="pt-2 border-t border-slate-800/80 text-[11px]">
                  <span className="text-slate-500">MITRE ATT&CK: </span>
                  <span className="text-cyan-400 font-mono">{event.mitre_attack.technique_id}</span> -{' '}
                  <span className="text-slate-300">{event.mitre_attack.technique_name}</span> (
                  <span className="text-slate-400">{event.mitre_attack.tactic}</span>)
                </div>
              )}
            </div>

            {/* AI Security Analyst Assessment Box */}
            <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-3 flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between mb-2">
                  <h4 className="text-xs font-semibold uppercase tracking-wider text-purple-400 flex items-center gap-1.5">
                    <Sparkles className="w-3.5 h-3.5 text-purple-400" />
                    Gemini AI Security Analyst
                  </h4>
                  {event.ai_analysis && (
                    <span className="text-[11px] font-mono text-purple-300 bg-purple-950/60 px-1.5 py-0.5 rounded border border-purple-800/60">
                      {event.ai_analysis.confidence}% Confidence
                    </span>
                  )}
                </div>

                {/* Loading State */}
                {analyzing ? (
                  <div className="py-6 px-3 text-center space-y-2">
                    <div className="w-6 h-6 border-2 border-purple-500 border-t-transparent rounded-full animate-spin mx-auto" />
                    <p className="text-xs text-purple-300 font-mono">
                      Querying Gemini 3.8 Flash model with grounded log telemetry...
                    </p>
                  </div>
                ) : analysisError ? (
                  /* Error State */
                  <div className="p-3 rounded bg-red-950/40 border border-red-800/60 text-xs text-red-300 space-y-2">
                    <div className="flex items-center gap-1.5 font-semibold">
                      <AlertTriangle className="w-3.5 h-3.5 text-red-400" />
                      Analysis Error
                    </div>
                    <p>{analysisError}</p>
                    <button
                      onClick={handleRunAI}
                      className="px-2.5 py-1 rounded bg-red-900/60 hover:bg-red-800 text-white font-medium inline-flex items-center gap-1 transition"
                    >
                      <RotateCcw className="w-3 h-3" /> Retry Analysis
                    </button>
                  </div>
                ) : event.ai_analysis ? (
                  /* Success State */
                  <div className="space-y-2 text-xs">
                    <div className="p-2.5 rounded bg-purple-950/30 border border-purple-900/50 text-slate-200">
                      <span className="text-[10px] font-mono uppercase tracking-wider text-purple-300 block mb-0.5 font-bold">
                        Analyst Assessment:
                      </span>
                      {event.ai_analysis.assessment}
                    </div>
                    <div className="text-[11px] text-slate-300">
                      <span className="text-slate-400 font-semibold block mb-0.5">Reasoning & Severity Justification:</span>
                      <p className="text-slate-300 leading-relaxed font-sans">{event.ai_analysis.reasoning_summary}</p>
                    </div>
                    <div className="text-[11px] text-slate-400 flex items-center justify-between pt-1 border-t border-slate-900">
                      <span>False Positive Likelihood:</span>
                      <span className={`font-semibold font-mono ${event.ai_analysis.false_positive_possibility === 'LOW' ? 'text-emerald-400' : 'text-amber-400'}`}>
                        {event.ai_analysis.false_positive_possibility}
                      </span>
                    </div>
                  </div>
                ) : (
                  /* Empty / Idle State */
                  <p className="text-xs text-slate-400 italic">
                    AI evaluation has not been executed for this specific event yet. Click below to trigger deep Gemini analysis based strictly on the provided log evidence.
                  </p>
                )}
              </div>

              <div className="pt-2">
                <button
                  onClick={handleRunAI}
                  disabled={analyzing}
                  className="w-full py-2 px-3 rounded-lg text-xs font-semibold bg-purple-600 hover:bg-purple-500 disabled:opacity-50 text-white flex items-center justify-center gap-2 transition shadow shadow-purple-950"
                >
                  <Sparkles className="w-3.5 h-3.5" />
                  {analyzing ? 'Analyzing with Gemini AI...' : event.ai_analysis ? 'Re-Analyze with Gemini AI' : 'Run Deep AI Security Analysis'}
                </button>
              </div>
            </div>
          </div>

          {/* AI Grounded Evidence, Defensive Actions & Additional Information Panel */}
          {event.ai_analysis && (
            <div className="p-4 rounded-lg bg-purple-950/20 border border-purple-900/50 space-y-4">
              <h4 className="text-xs font-semibold uppercase tracking-wider text-purple-300 flex items-center gap-2">
                <CheckCircle className="w-4 h-4 text-purple-400" />
                AI Analysis: Grounded Telemetry, Defensive Actions & Evidence Gaps
              </h4>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
                {/* Evidence */}
                <div>
                  <span className="text-slate-400 font-semibold block mb-1.5 font-mono text-[11px]">
                    1. Grounded Log Evidence:
                  </span>
                  <ul className="list-disc list-inside space-y-1 text-slate-300">
                    {event.ai_analysis.evidence.map((ev, i) => (
                      <li key={i} className="font-mono text-[11px] leading-relaxed">{ev}</li>
                    ))}
                  </ul>
                </div>

                {/* Recommended Defensive Actions */}
                <div>
                  <span className="text-slate-400 font-semibold block mb-1.5 font-mono text-[11px]">
                    2. Recommended Defensive Actions:
                  </span>
                  <ul className="space-y-1.5">
                    {event.ai_analysis.recommended_actions.map((act, i) => (
                      <li key={i} className="flex items-start gap-1.5 text-slate-200">
                        <span className="w-4 h-4 rounded bg-purple-900/80 text-purple-300 flex items-center justify-center text-[10px] shrink-0 mt-0.5 font-bold">
                          {i + 1}
                        </span>
                        <span>{act}</span>
                      </li>
                    ))}
                  </ul>
                </div>

                {/* Additional Information Needed */}
                <div>
                  <span className="text-slate-400 font-semibold block mb-1.5 font-mono text-[11px]">
                    3. Additional Information Needed:
                  </span>
                  <ul className="space-y-1 text-slate-300">
                    {(event.ai_analysis.additional_information_needed || []).map((info, i) => (
                      <li key={i} className="flex items-start gap-1.5 text-slate-300 text-[11px]">
                        <span className="text-cyan-400 font-mono shrink-0">&bull;</span>
                        <span>{info}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            </div>
          )}

          {/* Raw Payload Log Console */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                Raw Telemetry Payload
              </h4>
              <span className="text-[11px] text-slate-500 font-mono">Format: Syslog / CEF / JSON</span>
            </div>
            <pre className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-cyan-300/90 font-mono text-xs overflow-x-auto whitespace-pre-wrap leading-relaxed select-all">
              {event.raw_payload || event.message}
            </pre>
          </div>
        </div>

        {/* Footer Actions & Status Triage */}
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between px-6 py-3 border-t border-slate-800 bg-slate-950/70 gap-3">
          <div className="flex items-center gap-2 text-xs">
            <span className="text-slate-500">Triage Status:</span>
            <div className="flex items-center rounded-lg bg-slate-900 border border-slate-800 p-0.5">
              {(['OPEN', 'INVESTIGATING', 'RESOLVED', 'DISMISSED'] as EventStatus[]).map((st) => (
                <button
                  key={st}
                  onClick={() => handleStatusChange(st)}
                  className={`px-2 py-0.5 rounded text-[11px] font-mono transition ${
                    event.status === st
                      ? 'bg-slate-800 text-cyan-300 font-bold'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {st}
                </button>
              ))}
            </div>
          </div>

          <div className="flex items-center gap-2 justify-end">
            <button
              onClick={() => {
                onCreateIncidentFromEvent(event);
                onClose();
              }}
              className="px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-red-600 hover:bg-red-500 text-white flex items-center gap-1.5 transition shadow shadow-red-950"
            >
              <PlusCircle className="w-3.5 h-3.5" />
              Promote to Incident
            </button>
            <button
              onClick={onClose}
              className="px-4 py-1.5 rounded-lg text-xs font-medium text-slate-300 bg-slate-800 hover:bg-slate-700 transition"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
