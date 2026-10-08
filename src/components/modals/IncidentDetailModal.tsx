/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { Incident, IncidentStatus, SecurityEvent, SeverityLevel } from '../../types/security';
import { SeverityBadge, IncidentStatusBadge, DetectionMethodBadge } from '../common/SeverityBadge';
import {
  X,
  Sparkles,
  AlertOctagon,
  Clock,
  Shield,
  User,
  CheckSquare,
  Square,
  MessageSquare,
  List,
  Activity,
  Send,
  Layers,
  CheckCircle2,
} from 'lucide-react';
import { analyzeIncidentWithAI } from '../../services/aiAnalystClient';
import { AttackTimeline } from '../common/AttackTimeline';
import { getIncidentAttackTimeline } from '../../services/incidentTimelineHelper';

interface IncidentDetailModalProps {
  incident: Incident | null;
  allEvents: SecurityEvent[];
  onClose: () => void;
  onUpdateIncident: (updated: Incident) => void;
  onSelectEvent: (event: SecurityEvent) => void;
}

export const IncidentDetailModal: React.FC<IncidentDetailModalProps> = ({
  incident,
  allEvents,
  onClose,
  onUpdateIncident,
  onSelectEvent,
}) => {
  const [newNote, setNewNote] = useState('');
  const [noteAuthor, setNoteAuthor] = useState('Analyst (Tier 2)');
  const [analyzing, setAnalyzing] = useState(false);

  if (!incident) return null;

  const linkedEvents = allEvents.filter((e) => incident.event_ids.includes(e.event_id));
  const attackTimelineItems = getIncidentAttackTimeline(incident, allEvents);

  const handleStatusChange = (newStatus: IncidentStatus) => {
    const updated: Incident = {
      ...incident,
      status: newStatus,
      updated_at: new Date().toISOString(),
      analyst_notes: [
        ...incident.analyst_notes,
        {
          id: `note-${Date.now()}`,
          author: 'System Audit',
          timestamp: new Date().toISOString(),
          note: `Incident status transitioned from '${incident.status}' to '${newStatus}'.`,
        },
      ],
    };
    onUpdateIncident(updated);
  };

  const handleSeverityChange = (newSev: SeverityLevel) => {
    const updated: Incident = {
      ...incident,
      severity: newSev,
      updated_at: new Date().toISOString(),
    };
    onUpdateIncident(updated);
  };

  const handleToggleChecklist = (id: string) => {
    const updatedChecklist = incident.containment_checklist.map((item) => {
      if (item.id === id) {
        const nextState = !item.completed;
        return {
          ...item,
          completed: nextState,
          completed_by: nextState ? 'Analyst' : undefined,
          completed_at: nextState ? new Date().toISOString() : undefined,
        };
      }
      return item;
    });

    const updated: Incident = {
      ...incident,
      containment_checklist: updatedChecklist,
      updated_at: new Date().toISOString(),
    };
    onUpdateIncident(updated);
  };

  const handleAddNote = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newNote.trim()) return;

    const noteItem = {
      id: `n-${Date.now()}`,
      author: noteAuthor.trim() || 'Analyst',
      timestamp: new Date().toISOString(),
      note: newNote.trim(),
    };

    const updated: Incident = {
      ...incident,
      analyst_notes: [noteItem, ...incident.analyst_notes],
      updated_at: new Date().toISOString(),
    };
    onUpdateIncident(updated);
    setNewNote('');
  };

  const handleRunAICorrelation = async () => {
    setAnalyzing(true);
    try {
      const result = await analyzeIncidentWithAI(incident, linkedEvents);
      const updated: Incident = {
        ...incident,
        ai_analysis: result,
        updated_at: new Date().toISOString(),
        detection_origin: 'RULE_AND_AI',
      };
      onUpdateIncident(updated);
    } catch (err) {
      console.error(err);
    } finally {
      setAnalyzing(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4 overflow-y-auto">
      <div className="relative w-full max-w-5xl max-h-[92vh] flex flex-col bg-slate-900 border border-slate-800 rounded-xl shadow-2xl text-slate-100 overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-slate-950/80">
          <div className="flex items-center gap-3">
            <span className="p-2 rounded-lg bg-red-950/80 text-red-400 border border-red-900/50">
              <AlertOctagon className="w-5 h-5" />
            </span>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-mono text-sm text-red-400 font-bold">{incident.incident_id}</span>
                <SeverityBadge severity={incident.severity} />
                <IncidentStatusBadge status={incident.status} />
                <DetectionMethodBadge method={incident.detection_origin} />
              </div>
              <h3 className="text-base font-semibold text-white mt-1">{incident.title}</h3>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Action & Status Bar */}
        <div className="flex flex-wrap items-center justify-between gap-3 px-6 py-3 bg-slate-950 border-b border-slate-800 text-xs">
          <div className="flex items-center gap-2">
            <span className="text-slate-400 font-medium">Status:</span>
            {(['New', 'Investigating', 'Contained', 'Resolved', 'False Positive'] as IncidentStatus[]).map((st) => (
              <button
                key={st}
                onClick={() => handleStatusChange(st)}
                className={`px-2.5 py-1 rounded transition font-medium ${
                  incident.status === st
                    ? 'bg-cyan-600 text-white shadow-sm'
                    : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
                }`}
              >
                {st}
              </button>
            ))}
          </div>

          <div className="flex items-center gap-2">
            <span className="text-slate-400 font-medium">Severity:</span>
            <select
              value={incident.severity}
              onChange={(e) => handleSeverityChange(e.target.value as SeverityLevel)}
              className="bg-slate-800 border border-slate-700 rounded px-2 py-1 text-slate-200 text-xs focus:outline-none"
            >
              <option value="CRITICAL">CRITICAL</option>
              <option value="HIGH">HIGH</option>
              <option value="MEDIUM">MEDIUM</option>
              <option value="LOW">LOW</option>
            </select>

            <button
              onClick={handleRunAICorrelation}
              disabled={analyzing}
              className="px-3 py-1 rounded bg-purple-600 hover:bg-purple-500 disabled:opacity-50 text-white flex items-center gap-1.5 font-semibold transition"
            >
              <Sparkles className="w-3.5 h-3.5" />
              {analyzing ? 'Analyzing...' : 'AI Multi-Stage Correlation'}
            </button>
          </div>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6 text-sm">
          {/* Metadata Cards */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
              <span className="text-xs text-slate-400 flex items-center gap-1 mb-1">
                <Clock className="w-3.5 h-3.5 text-slate-500" /> Opened At
              </span>
              <p className="font-mono text-xs text-slate-300">{new Date(incident.created_at).toLocaleString()}</p>
            </div>
            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
              <span className="text-xs text-slate-400 flex items-center gap-1 mb-1">
                <User className="w-3.5 h-3.5 text-slate-500" /> Assigned Lead
              </span>
              <p className="font-medium text-slate-200">{incident.assigned_to || 'Unassigned'}</p>
            </div>
            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
              <span className="text-xs text-slate-400 flex items-center gap-1 mb-1">
                <Shield className="w-3.5 h-3.5 text-slate-500" /> Targeted Assets
              </span>
              <p className="font-semibold text-cyan-300">{incident.target_assets.join(', ')}</p>
            </div>
            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
              <span className="text-xs text-slate-400 flex items-center gap-1 mb-1">
                <Layers className="w-3.5 h-3.5 text-slate-500" /> Suspected Threat IPs
              </span>
              <p className="font-mono text-xs text-red-400">{incident.threat_actors_ips.join(', ')}</p>
            </div>
          </div>

          {/* Executive Incident Summary */}
          <div className="p-4 rounded-lg bg-slate-950 border border-slate-800">
            <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">
              Incident Case Summary
            </h4>
            <p className="text-slate-300 leading-relaxed text-sm font-sans">{incident.summary}</p>

            {incident.mitre_tactics && incident.mitre_tactics.length > 0 && (
              <div className="mt-3 pt-3 border-t border-slate-800/80 flex flex-wrap items-center gap-2">
                <span className="text-xs text-slate-400 font-medium">MITRE ATT&CK Tactics:</span>
                {incident.mitre_tactics.map((tac, i) => (
                  <span
                    key={i}
                    className="px-2 py-0.5 rounded text-[11px] font-mono bg-cyan-950/60 text-cyan-300 border border-cyan-800/60"
                  >
                    {tac}
                  </span>
                ))}
              </div>
            )}
          </div>

          {/* AI Multi-Stage Incident Analysis Panel */}
          {incident.ai_analysis && (
            <div className="p-4 rounded-lg bg-purple-950/20 border border-purple-900/50 space-y-4">
              <div className="flex items-center justify-between">
                <h4 className="text-xs font-semibold uppercase tracking-wider text-purple-300 flex items-center gap-2">
                  <Sparkles className="w-4 h-4 text-purple-400" />
                  Gemini AI Incident Root Cause & Multi-Stage Attack Analysis
                </h4>
                <div className="flex items-center gap-2">
                  <span className="text-xs px-2 py-0.5 rounded bg-purple-900/70 text-purple-200 font-mono">
                    Confidence: {incident.ai_analysis.confidence}%
                  </span>
                  <span className="text-xs px-2 py-0.5 rounded bg-red-950/70 text-red-300 font-mono">
                    Risk: {incident.ai_analysis.risk_score}/100
                  </span>
                  <span className="text-xs px-2 py-0.5 rounded bg-slate-900 text-slate-300 font-mono border border-slate-800">
                    FP Likelihood: {incident.ai_analysis.false_positive_possibility}
                  </span>
                </div>
              </div>

              {/* Assessment summary */}
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs space-y-2">
                <div className="text-purple-300 font-semibold font-mono text-[11px]">
                  ASSESSMENT VERDICT:
                </div>
                <p className="text-slate-100 leading-relaxed font-sans">{incident.ai_analysis.assessment}</p>
              </div>

              {/* Reasoning & Severity justification */}
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs space-y-1">
                <span className="text-slate-400 font-semibold font-mono text-[11px] block">
                  REASONING SUMMARY & SEVERITY JUSTIFICATION:
                </span>
                <p className="text-slate-300 leading-relaxed">{incident.ai_analysis.reasoning_summary}</p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs pt-1">
                {/* Evidence */}
                <div>
                  <span className="text-slate-400 font-semibold block mb-1.5 font-mono text-[11px]">
                    1. Grounded Log Evidence:
                  </span>
                  <ul className="list-disc list-inside space-y-1 text-slate-300 font-mono text-[11px]">
                    {incident.ai_analysis.evidence.map((ev, i) => (
                      <li key={i}>{ev}</li>
                    ))}
                  </ul>
                </div>

                {/* Recommended Defensive Actions */}
                <div>
                  <span className="text-slate-400 font-semibold block mb-1.5 font-mono text-[11px]">
                    2. Recommended Defensive Playbook:
                  </span>
                  <ul className="space-y-1.5 text-slate-200">
                    {incident.ai_analysis.recommended_actions.map((act, i) => (
                      <li key={i} className="flex items-start gap-1.5">
                        <CheckCircle2 className="w-3.5 h-3.5 text-purple-400 shrink-0 mt-0.5" />
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
                    {(incident.ai_analysis.additional_information_needed || []).map((info, i) => (
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

          {/* Attack Progression Timeline */}
          <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-3">
            <div className="flex items-center justify-between">
              <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-300 flex items-center gap-2">
                <Clock className="w-4 h-4 text-cyan-400" />
                Attack Progression Timeline ({attackTimelineItems.length} Key Events)
              </h4>
              <span className="text-[11px] font-mono text-slate-500">
                Chronological sequence
              </span>
            </div>
            <AttackTimeline
              items={attackTimelineItems}
              onSelectEventId={(id) => {
                const found = allEvents.find((e) => e.event_id === id);
                if (found) onSelectEvent(found);
              }}
            />
          </div>

          {/* Containment Checklist */}
          <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-3">
            <div className="flex items-center justify-between">
              <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-2">
                <CheckSquare className="w-4 h-4 text-cyan-400" />
                SOC Containment & Remediation Checklist
              </h4>
              <span className="text-xs text-slate-400 font-mono">
                {incident.containment_checklist.filter((i) => i.completed).length} /{' '}
                {incident.containment_checklist.length} Complete
              </span>
            </div>

            <div className="space-y-2">
              {incident.containment_checklist.map((item) => (
                <div
                  key={item.id}
                  onClick={() => handleToggleChecklist(item.id)}
                  className={`flex items-start gap-3 p-2.5 rounded-lg border cursor-pointer transition select-none ${
                    item.completed
                      ? 'bg-emerald-950/20 border-emerald-900/50 text-slate-300'
                      : 'bg-slate-900/60 border-slate-800 hover:border-slate-700 text-slate-200'
                  }`}
                >
                  <button className="mt-0.5 text-cyan-400 focus:outline-none">
                    {item.completed ? (
                      <CheckSquare className="w-4 h-4 text-emerald-400" />
                    ) : (
                      <Square className="w-4 h-4 text-slate-500" />
                    )}
                  </button>
                  <div className="flex-1 text-xs">
                    <span className={item.completed ? 'line-through text-slate-400' : 'font-medium'}>
                      {item.title}
                    </span>
                    {item.completed && item.completed_by && (
                      <span className="block text-[10px] text-emerald-400/80 mt-0.5 font-mono">
                        Completed by {item.completed_by}
                      </span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Linked Security Events Timeline */}
          <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-3">
            <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-2">
              <Activity className="w-4 h-4 text-cyan-400" />
              Correlated Security Events Timeline ({linkedEvents.length})
            </h4>

            <div className="space-y-2">
              {linkedEvents.map((ev) => (
                <div
                  key={ev.event_id}
                  onClick={() => onSelectEvent(ev)}
                  className="flex items-center justify-between p-2.5 rounded-lg bg-slate-900/80 border border-slate-800 hover:border-cyan-700/60 cursor-pointer transition text-xs"
                >
                  <div className="flex items-center gap-3">
                    <SeverityBadge severity={ev.severity} />
                    <span className="font-mono text-cyan-400 font-semibold">{ev.event_id}</span>
                    <span className="text-slate-400 font-mono text-[11px]">{new Date(ev.timestamp).toLocaleTimeString()}</span>
                    <span className="text-slate-200 font-medium">{ev.message}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-slate-400 text-[11px]">
                      {ev.source_ip} &rarr; {ev.destination_ip}
                    </span>
                    <span className="text-cyan-400 hover:underline text-[11px]">Details &rarr;</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Analyst Notes Log */}
          <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-3">
            <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-2">
              <MessageSquare className="w-4 h-4 text-cyan-400" />
              Analyst Case Notes & Audit History
            </h4>

            {/* Note Input */}
            <form onSubmit={handleAddNote} className="flex gap-2">
              <input
                type="text"
                placeholder="Add incident investigation note..."
                value={newNote}
                onChange={(e) => setNewNote(e.target.value)}
                className="flex-1 px-3 py-2 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
              />
              <input
                type="text"
                placeholder="Author"
                value={noteAuthor}
                onChange={(e) => setNoteAuthor(e.target.value)}
                className="w-32 px-3 py-2 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
              />
              <button
                type="submit"
                className="px-3 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-medium flex items-center gap-1.5 transition"
              >
                <Send className="w-3.5 h-3.5" />
                Add Note
              </button>
            </form>

            {/* Notes List */}
            <div className="space-y-2 mt-3">
              {incident.analyst_notes.map((note) => (
                <div key={note.id} className="p-2.5 rounded-lg bg-slate-900/60 border border-slate-800/80 text-xs">
                  <div className="flex items-center justify-between text-slate-400 mb-1">
                    <span className="font-semibold text-slate-300">{note.author}</span>
                    <span className="font-mono text-[11px]">{new Date(note.timestamp).toLocaleString()}</span>
                  </div>
                  <p className="text-slate-200">{note.note}</p>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between px-6 py-3 border-t border-slate-800 bg-slate-950/70">
          <div className="text-xs text-slate-400">
            Last Updated: <span className="font-mono text-slate-300">{new Date(incident.updated_at).toLocaleString()}</span>
          </div>
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg text-xs font-medium text-slate-300 bg-slate-800 hover:bg-slate-700 transition"
          >
            Close Incident View
          </button>
        </div>
      </div>
    </div>
  );
};
