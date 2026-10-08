/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { Incident, SecurityEvent, SeverityLevel, ThreatCategory } from '../../types/security';
import { X, AlertOctagon, Plus, Check } from 'lucide-react';
import { getIncidentAttackTimeline } from '../../services/incidentTimelineHelper';

interface CreateIncidentModalProps {
  initialEvents: SecurityEvent[];
  allEvents: SecurityEvent[];
  onClose: () => void;
  onCreate: (newIncident: Incident) => void;
}

export const CreateIncidentModal: React.FC<CreateIncidentModalProps> = ({
  initialEvents,
  allEvents,
  onClose,
  onCreate,
}) => {
  const [title, setTitle] = useState(
    initialEvents.length > 0
      ? `Investigate ${initialEvents[0].threat_category} on ${initialEvents[0].asset}`
      : 'Suspicious Security Activity Incident'
  );
  const [severity, setSeverity] = useState<SeverityLevel>(
    initialEvents.length > 0 ? initialEvents[0].severity : 'HIGH'
  );
  const [threatCategory, setThreatCategory] = useState<ThreatCategory>(
    initialEvents.length > 0 ? initialEvents[0].threat_category : 'Brute Force'
  );
  const [assignedTo, setAssignedTo] = useState('Alex Morgan (Tier 3)');
  const [summary, setSummary] = useState(
    initialEvents.length > 0
      ? `Elevated security event ${initialEvents.map((e) => e.event_id).join(', ')} flagged for active triage and containment.`
      : ''
  );
  const [selectedEventIds, setSelectedEventIds] = useState<string[]>(
    initialEvents.map((e) => e.event_id)
  );

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!title.trim()) return;

    const linked = allEvents.filter((e) => selectedEventIds.includes(e.event_id));
    const targetAssets = Array.from(new Set(linked.map((e) => e.asset).filter((a) => a && a !== '-')));
    const threatIps = Array.from(new Set(linked.map((e) => e.source_ip).filter((ip) => ip && ip !== '-')));

    const newInc: Incident = {
      incident_id: `INC-${Math.floor(1000 + Math.random() * 9000)}`,
      title: title.trim(),
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      severity,
      status: 'New',
      threat_category: threatCategory,
      assigned_to: assignedTo.trim() || 'Unassigned',
      detection_origin: 'RULE',
      event_ids: selectedEventIds,
      target_assets: targetAssets.length > 0 ? targetAssets : ['Internal Network'],
      threat_actors_ips: threatIps.length > 0 ? threatIps : ['Unknown'],
      summary: summary.trim(),
      mitre_tactics: ['Initial Access', 'Execution'],
      containment_checklist: [
        { id: `c-${Date.now()}-1`, title: 'Verify firewall drop on suspected threat IP', completed: false },
        { id: `c-${Date.now()}-2`, title: 'Isolate affected host or segment traffic', completed: false },
        { id: `c-${Date.now()}-3`, title: 'Capture forensic artifacts and log exports', completed: false },
      ],
      analyst_notes: [
        {
          id: `note-${Date.now()}`,
          author: assignedTo || 'SOC Analyst',
          timestamp: new Date().toISOString(),
          note: `Incident opened from security events: ${selectedEventIds.join(', ')}.`,
        },
      ],
    };

    newInc.attack_timeline = getIncidentAttackTimeline(newInc, allEvents);

    onCreate(newInc);
    onClose();
  };

  const toggleEvent = (id: string) => {
    if (selectedEventIds.includes(id)) {
      setSelectedEventIds(selectedEventIds.filter((x) => x !== id));
    } else {
      setSelectedEventIds([...selectedEventIds, id]);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4 overflow-y-auto">
      <div className="relative w-full max-w-2xl bg-slate-900 border border-slate-800 rounded-xl shadow-2xl text-slate-100 overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-slate-950/80">
          <div className="flex items-center gap-3">
            <span className="p-2 rounded-lg bg-red-950/80 text-red-400">
              <AlertOctagon className="w-5 h-5" />
            </span>
            <div>
              <h3 className="text-base font-semibold text-white">Create New SOC Incident</h3>
              <p className="text-xs text-slate-400">Escalate security telemetry into an actionable investigation</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="p-6 space-y-4 text-xs">
          <div>
            <label className="block text-slate-300 font-semibold mb-1">Incident Title</label>
            <input
              type="text"
              required
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-100 text-xs focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-slate-300 font-semibold mb-1">Severity</label>
              <select
                value={severity}
                onChange={(e) => setSeverity(e.target.value as SeverityLevel)}
                className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-100 text-xs focus:outline-none focus:border-cyan-500"
              >
                <option value="CRITICAL">CRITICAL</option>
                <option value="HIGH">HIGH</option>
                <option value="MEDIUM">MEDIUM</option>
                <option value="LOW">LOW</option>
              </select>
            </div>
            <div>
              <label className="block text-slate-300 font-semibold mb-1">Threat Category</label>
              <select
                value={threatCategory}
                onChange={(e) => setThreatCategory(e.target.value as ThreatCategory)}
                className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-100 text-xs focus:outline-none focus:border-cyan-500"
              >
                <option value="Brute Force">Brute Force</option>
                <option value="Port Scanning">Port Scanning</option>
                <option value="Suspicious Authentication">Suspicious Authentication</option>
                <option value="Malware Indicator">Malware Indicator</option>
                <option value="Command-and-Control Indicator">Command-and-Control Indicator</option>
                <option value="DDoS/Traffic Anomaly">DDoS/Traffic Anomaly</option>
                <option value="SQL Injection Attempt">SQL Injection Attempt</option>
                <option value="Privilege Escalation">Privilege Escalation</option>
                <option value="Suspicious Outbound Traffic">Suspicious Outbound Traffic</option>
                <option value="Data Exfiltration Indicator">Data Exfiltration Indicator</option>
              </select>
            </div>
          </div>

          <div>
            <label className="block text-slate-300 font-semibold mb-1">Assigned Analyst Lead</label>
            <input
              type="text"
              value={assignedTo}
              onChange={(e) => setAssignedTo(e.target.value)}
              className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-100 text-xs focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div>
            <label className="block text-slate-300 font-semibold mb-1">Incident Summary & Hypotheses</label>
            <textarea
              rows={3}
              required
              value={summary}
              onChange={(e) => setSummary(e.target.value)}
              className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-100 text-xs focus:outline-none focus:border-cyan-500"
              placeholder="Describe what was observed, impacted assets, and initial indicators..."
            />
          </div>

          {/* Linked Events Selector */}
          <div>
            <label className="block text-slate-300 font-semibold mb-1">
              Correlated Events ({selectedEventIds.length} Selected)
            </label>
            <div className="max-h-40 overflow-y-auto space-y-1.5 p-2 bg-slate-950 rounded-lg border border-slate-800">
              {allEvents.slice(0, 15).map((ev) => {
                const isSelected = selectedEventIds.includes(ev.event_id);
                return (
                  <div
                    key={ev.event_id}
                    onClick={() => toggleEvent(ev.event_id)}
                    className={`flex items-center justify-between p-2 rounded cursor-pointer transition select-none ${
                      isSelected
                        ? 'bg-cyan-950/60 border border-cyan-800/80 text-white'
                        : 'bg-slate-900/60 border border-slate-800/60 text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    <div className="flex items-center gap-2">
                      <span
                        className={`w-4 h-4 rounded flex items-center justify-center text-[10px] ${
                          isSelected ? 'bg-cyan-500 text-slate-950 font-bold' : 'border border-slate-600'
                        }`}
                      >
                        {isSelected && <Check className="w-3 h-3" />}
                      </span>
                      <span className="font-mono text-cyan-400">{ev.event_id}</span>
                      <span className="text-slate-300 truncate max-w-xs">{ev.message}</span>
                    </div>
                    <span className="text-[11px] font-mono text-slate-500">{ev.device_type}</span>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Buttons */}
          <div className="flex items-center justify-end gap-3 pt-3 border-t border-slate-800">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition"
            >
              Cancel
            </button>
            <button
              type="submit"
              className="px-4 py-2 rounded-lg bg-red-600 hover:bg-red-500 text-white font-semibold flex items-center gap-1.5 transition shadow"
            >
              <Plus className="w-4 h-4" />
              Open Incident
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
