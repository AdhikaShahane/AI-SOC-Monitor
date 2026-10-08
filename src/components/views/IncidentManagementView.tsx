/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { Incident, IncidentStatus, SecurityEvent, SeverityLevel } from '../../types/security';
import { SeverityBadge, IncidentStatusBadge, DetectionMethodBadge } from '../common/SeverityBadge';
import { AttackTimeline } from '../common/AttackTimeline';
import { getIncidentAttackTimeline } from '../../services/incidentTimelineHelper';
import {
  AlertOctagon,
  Plus,
  Search,
  Filter,
  CheckCircle,
  Clock,
  User,
  Shield,
  Layers,
  ChevronRight,
  Sparkles,
  ChevronDown,
  ChevronUp,
  RotateCcw,
  AlertTriangle,
} from 'lucide-react';

interface IncidentManagementViewProps {
  incidents: Incident[];
  allEvents: SecurityEvent[];
  onSelectIncident: (incident: Incident) => void;
  onOpenCreateIncidentModal: () => void;
  onSelectEvent?: (event: SecurityEvent) => void;
  onUpdateIncident?: (incident: Incident) => void;
}

export const IncidentManagementView: React.FC<IncidentManagementViewProps> = ({
  incidents,
  allEvents,
  onSelectIncident,
  onOpenCreateIncidentModal,
  onSelectEvent,
  onUpdateIncident,
}) => {
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedTimelines, setExpandedTimelines] = useState<Record<string, boolean>>({
    'INC-8021': true,
    'INC-8022': true,
  });

  const toggleTimeline = (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setExpandedTimelines((prev) => ({
      ...prev,
      [id]: !prev[id],
    }));
  };

  const handleQuickStatusChange = (
    inc: Incident,
    newStatus: IncidentStatus,
    e: React.MouseEvent
  ) => {
    e.stopPropagation();
    if (onUpdateIncident) {
      onUpdateIncident({
        ...inc,
        status: newStatus,
        updated_at: new Date().toISOString(),
      });
    }
  };

  const filtered = incidents.filter((inc) => {
    if (statusFilter !== 'ALL' && inc.status !== statusFilter) return false;
    if (severityFilter !== 'ALL' && inc.severity !== severityFilter) return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      const match =
        inc.incident_id.toLowerCase().includes(q) ||
        inc.title.toLowerCase().includes(q) ||
        inc.summary.toLowerCase().includes(q) ||
        inc.threat_category.toLowerCase().includes(q) ||
        inc.target_assets.some((a) => a.toLowerCase().includes(q)) ||
        inc.threat_actors_ips.some((ip) => ip.toLowerCase().includes(q));
      if (!match) return false;
    }
    return true;
  });

  const handleTimelineEventClick = (eventId: string) => {
    if (onSelectEvent) {
      const found = allEvents.find((e) => e.event_id === eventId);
      if (found) onSelectEvent(found);
    }
  };

  return (
    <div className="space-y-5">
      {/* Top Banner & Control Bar */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-4 p-4 rounded-xl bg-slate-900 border border-slate-800 shadow-sm">
        <div>
          <h2 className="text-base font-semibold text-white flex items-center gap-2">
            <AlertOctagon className="w-5 h-5 text-red-400" />
            SOC Incident Management & Attack Timelines
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Active threat triage cases, multi-stage attack progression timelines, and containment tracking
          </p>
        </div>

        <button
          onClick={onOpenCreateIncidentModal}
          className="px-3.5 py-2 rounded-lg bg-red-600 hover:bg-red-500 text-white font-semibold text-xs flex items-center gap-1.5 transition shadow"
        >
          <Plus className="w-4 h-4" />
          Create Incident Case
        </button>
      </div>

      {/* Filter and Search Bar */}
      <div className="p-3.5 rounded-xl bg-slate-900/90 border border-slate-800 flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3 text-xs">
        <div className="flex flex-wrap items-center gap-2">
          {/* Status Tabs */}
          <div className="flex items-center rounded-lg bg-slate-950 border border-slate-800 p-0.5">
            {['ALL', 'New', 'Investigating', 'Contained', 'Resolved'].map((st) => (
              <button
                key={st}
                onClick={() => setStatusFilter(st)}
                className={`px-2.5 py-1 rounded text-xs font-medium transition ${
                  statusFilter === st
                    ? 'bg-slate-800 text-cyan-300 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {st}
              </button>
            ))}
          </div>

          {/* Severity Dropdown */}
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1 text-slate-200 text-xs focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical Only</option>
            <option value="HIGH">High Only</option>
            <option value="MEDIUM">Medium Only</option>
          </select>

          {(statusFilter !== 'ALL' || severityFilter !== 'ALL' || searchQuery) && (
            <button
              onClick={() => {
                setStatusFilter('ALL');
                setSeverityFilter('ALL');
                setSearchQuery('');
              }}
              className="text-xs text-slate-400 hover:text-slate-200 flex items-center gap-1 ml-1"
            >
              <RotateCcw className="w-3 h-3" /> Reset
            </button>
          )}
        </div>

        {/* Search */}
        <div className="relative w-full md:w-64">
          <Search className="absolute left-3 top-2.5 w-3.5 h-3.5 text-slate-500" />
          <input
            type="text"
            placeholder="Search incident ID, IP, asset, summary..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-8 pr-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 placeholder-slate-500 text-xs focus:outline-none focus:border-cyan-500"
          />
        </div>
      </div>

      {/* Incidents List Cards */}
      <div className="grid grid-cols-1 gap-4">
        {filtered.length === 0 ? (
          <div className="p-12 text-center text-slate-400 text-xs bg-slate-900 rounded-xl border border-slate-800 space-y-2">
            <AlertTriangle className="w-6 h-6 text-slate-500 mx-auto" />
            <p className="font-semibold text-slate-300">No incident cases match the active filter criteria.</p>
            <p className="text-slate-500">Try loosening your status or severity filters, or create a new incident.</p>
          </div>
        ) : (
          filtered.map((inc) => {
            const completedChecklist = inc.containment_checklist.filter((c) => c.completed).length;
            const totalChecklist = inc.containment_checklist.length;
            const pct = totalChecklist > 0 ? Math.round((completedChecklist / totalChecklist) * 100) : 0;
            const timelineItems = getIncidentAttackTimeline(inc, allEvents);
            const isTimelineOpen = expandedTimelines[inc.incident_id] !== false; // default open

            return (
              <div
                key={inc.incident_id}
                onClick={() => onSelectIncident(inc)}
                className="p-5 rounded-xl bg-slate-900/90 border border-slate-800 hover:border-slate-700 transition shadow-sm cursor-pointer space-y-4"
              >
                {/* Header Row */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-red-400 font-bold text-sm tracking-tight">
                      {inc.incident_id}
                    </span>
                    <SeverityBadge severity={inc.severity} />
                    <IncidentStatusBadge status={inc.status} />
                    <DetectionMethodBadge method={inc.detection_origin} />
                    <span className="text-slate-300 font-medium text-xs font-mono ml-1">
                      {inc.threat_category}
                    </span>
                  </div>

                  <div className="flex items-center gap-3 text-slate-400 text-xs font-mono">
                    <span className="flex items-center gap-1 tabular-nums">
                      <Clock className="w-3.5 h-3.5 text-slate-500" />
                      {new Date(inc.created_at).toLocaleTimeString()}
                    </span>
                    <span className="flex items-center gap-1">
                      <User className="w-3.5 h-3.5 text-slate-500" />
                      {inc.assigned_to}
                    </span>
                  </div>
                </div>

                {/* Title & Summary */}
                <div>
                  <h3 className="text-base font-semibold text-slate-100 hover:text-cyan-300 transition">
                    {inc.title}
                  </h3>
                  <p className="text-xs text-slate-300 mt-1 leading-relaxed">{inc.summary}</p>
                </div>

                {/* Metadata Details Row */}
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 py-2 px-3 bg-slate-950/60 rounded-lg border border-slate-800/80 text-xs">
                  <div>
                    <span className="text-slate-500 block text-[11px]">Impacted Assets</span>
                    <span className="font-semibold text-cyan-300 font-mono">
                      {inc.target_assets.join(', ') || 'N/A'}
                    </span>
                  </div>

                  <div>
                    <span className="text-slate-500 block text-[11px]">Threat Origin IPs</span>
                    <span className="font-mono text-red-400">
                      {inc.threat_actors_ips.join(', ') || 'Internal asset'}
                    </span>
                  </div>

                  <div>
                    <span className="text-slate-500 block text-[11px]">
                      Containment Status ({completedChecklist}/{totalChecklist} Tasks)
                    </span>
                    <div className="flex items-center gap-2 mt-1">
                      <div className="flex-1 h-1.5 bg-slate-900 rounded-full overflow-hidden border border-slate-800">
                        <div
                          className="h-full bg-cyan-500 rounded-full transition-all"
                          style={{ width: `${pct}%` }}
                        />
                      </div>
                      <span className="font-mono text-[11px] text-slate-300">{pct}%</span>
                    </div>
                  </div>
                </div>

                {/* Attack Timeline Accordion Section */}
                <div className="space-y-2 pt-1 border-t border-slate-800/80">
                  <div className="flex items-center justify-between">
                    <button
                      onClick={(e) => toggleTimeline(inc.incident_id, e)}
                      className="text-xs font-semibold text-slate-300 hover:text-cyan-300 flex items-center gap-1.5 transition"
                    >
                      {isTimelineOpen ? (
                        <ChevronUp className="w-3.5 h-3.5 text-slate-400" />
                      ) : (
                        <ChevronDown className="w-3.5 h-3.5 text-slate-400" />
                      )}
                      <span>Attack Timeline ({timelineItems.length} Events)</span>
                    </button>

                    <div className="flex items-center gap-2">
                      {/* Quick status progression buttons */}
                      {inc.status === 'New' && (
                        <button
                          onClick={(e) => handleQuickStatusChange(inc, 'Investigating', e)}
                          className="px-2 py-0.5 rounded text-[11px] bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 font-medium transition"
                        >
                          Mark Investigating
                        </button>
                      )}
                      {inc.status === 'Investigating' && (
                        <button
                          onClick={(e) => handleQuickStatusChange(inc, 'Contained', e)}
                          className="px-2 py-0.5 rounded text-[11px] bg-blue-950/80 hover:bg-blue-900 text-blue-300 border border-blue-800 font-medium transition"
                        >
                          Mark Contained
                        </button>
                      )}
                    </div>
                  </div>

                  {/* Chronological Attack Sequence */}
                  {isTimelineOpen && (
                    <div
                      className="p-3 rounded-lg bg-slate-950 border border-slate-800/90 text-xs"
                      onClick={(e) => e.stopPropagation()}
                    >
                      <AttackTimeline
                        items={timelineItems}
                        compact={false}
                        onSelectEventId={handleTimelineEventClick}
                      />
                    </div>
                  )}
                </div>

                {/* Card Action Footer */}
                <div className="flex items-center justify-between pt-1 text-xs text-slate-400 font-mono">
                  <span>
                    {inc.event_ids.length} Correlated Log Records &bull; {inc.analyst_notes.length} Analyst Notes
                  </span>
                  <span className="text-cyan-400 inline-flex items-center gap-1 font-semibold hover:underline">
                    Open Forensic Investigation &rarr;
                  </span>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
