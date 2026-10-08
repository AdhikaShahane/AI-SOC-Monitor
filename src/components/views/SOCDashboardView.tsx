/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { Incident, SecurityEvent, SOCMetrics } from '../../types/security';
import { SeverityBadge, DetectionMethodBadge } from '../common/SeverityBadge';
import { AttackTimeline } from '../common/AttackTimeline';
import { getIncidentAttackTimeline } from '../../services/incidentTimelineHelper';
import {
  AlertTriangle,
  ShieldAlert,
  Flame,
  Radio,
  Clock,
  ArrowUpRight,
  TrendingUp,
  Server,
  Globe,
  Activity,
  Layers,
  ChevronRight,
  Sparkles,
  RefreshCw,
  Cpu,
  BarChart2,
  CheckCircle,
  ExternalLink,
} from 'lucide-react';

interface SOCDashboardViewProps {
  metrics: SOCMetrics;
  events: SecurityEvent[];
  incidents: Incident[];
  onSelectEvent: (event: SecurityEvent) => void;
  onSelectIncident: (incident: Incident) => void;
  onNavigateToModule: (module: any) => void;
  onGenerateDemoDataset?: () => void;
}

export const SOCDashboardView: React.FC<SOCDashboardViewProps> = ({
  metrics,
  events,
  incidents,
  onSelectEvent,
  onSelectIncident,
  onNavigateToModule,
  onGenerateDemoDataset,
}) => {
  const [selectedIncidentForTimeline, setSelectedIncidentForTimeline] = useState<string>(
    incidents[0]?.incident_id || ''
  );

  const recentCritical = events
    .filter((e) => e.severity === 'CRITICAL' || e.severity === 'HIGH')
    .slice(0, 7);

  const activeIncident = incidents.find((i) => i.incident_id === selectedIncidentForTimeline) || incidents[0];
  const activeTimeline = activeIncident ? getIncidentAttackTimeline(activeIncident, events) : [];

  // Compute fleet mean risk score
  const meanRiskScore = events.length > 0
    ? Math.round(events.reduce((sum, e) => sum + (e.risk_score || 0), 0) / events.length)
    : 0;

  // Empty State: if no events exist in buffer
  if (events.length === 0) {
    return (
      <div className="py-20 px-4 text-center max-w-lg mx-auto space-y-4">
        <div className="p-4 rounded-full bg-slate-900 border border-slate-800 w-16 h-16 mx-auto flex items-center justify-center text-slate-400">
          <Activity className="w-8 h-8" />
        </div>
        <div>
          <h3 className="text-base font-semibold text-slate-100">SOC Telemetry Buffer Empty</h3>
          <p className="text-xs text-slate-400 mt-1 leading-relaxed">
            No live or synthetic security telemetry is currently loaded in memory. Generate the full 500+ event synthetic multi-stage dataset to populate SOC detection rules and attack timelines.
          </p>
        </div>
        {onGenerateDemoDataset && (
          <button
            onClick={onGenerateDemoDataset}
            className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-semibold text-xs inline-flex items-center gap-2 transition shadow shadow-cyan-950"
          >
            <RefreshCw className="w-4 h-4" />
            Generate Demo Dataset (500+ Events)
          </button>
        )}
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Hierarchy Level 1: Executive SOC Operational KPIs */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        {/* Total Ingested Events */}
        <div className="p-3.5 rounded-xl bg-slate-900/90 border border-slate-800 shadow-sm">
          <div className="flex items-center justify-between text-slate-400 mb-1.5">
            <span className="text-[11px] font-medium uppercase tracking-wider">Total Events</span>
            <Activity className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-white tracking-tight tabular-nums">
            {metrics.total_events.toLocaleString()}
          </div>
          <div className="text-[11px] text-slate-400 mt-1 flex items-center gap-1 font-mono">
            <TrendingUp className="w-3 h-3 text-cyan-400" />
            <span>Today: {metrics.events_today}</span>
          </div>
        </div>

        {/* Critical Alerts */}
        <div className="p-3.5 rounded-xl bg-red-950/20 border border-red-900/60 shadow-sm">
          <div className="flex items-center justify-between text-red-300 mb-1.5">
            <span className="text-[11px] font-medium uppercase tracking-wider">Critical</span>
            <ShieldAlert className="w-4 h-4 text-red-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-red-400 tracking-tight tabular-nums">
            {metrics.critical_events}
          </div>
          <div className="text-[11px] text-red-400/80 mt-1 font-mono">Immediate Triage</div>
        </div>

        {/* High Risk Alerts */}
        <div className="p-3.5 rounded-xl bg-amber-950/20 border border-amber-900/60 shadow-sm">
          <div className="flex items-center justify-between text-amber-300 mb-1.5">
            <span className="text-[11px] font-medium uppercase tracking-wider">High Risk</span>
            <AlertTriangle className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-amber-400 tracking-tight tabular-nums">
            {metrics.high_events}
          </div>
          <div className="text-[11px] text-amber-400/80 mt-1 font-mono">Action Required</div>
        </div>

        {/* Medium Risk */}
        <div className="p-3.5 rounded-xl bg-slate-900/90 border border-slate-800 shadow-sm">
          <div className="flex items-center justify-between text-slate-400 mb-1.5">
            <span className="text-[11px] font-medium uppercase tracking-wider">Medium Risk</span>
            <span className="w-2 h-2 rounded-full bg-yellow-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-yellow-300 tracking-tight tabular-nums">
            {metrics.medium_events}
          </div>
          <div className="text-[11px] text-slate-500 mt-1 font-mono">Heuristic Monitored</div>
        </div>

        {/* Mean Risk Score */}
        <div className="p-3.5 rounded-xl bg-slate-900/90 border border-slate-800 shadow-sm">
          <div className="flex items-center justify-between text-slate-400 mb-1.5">
            <span className="text-[11px] font-medium uppercase tracking-wider">Mean Risk</span>
            <Cpu className="w-4 h-4 text-purple-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-purple-300 tracking-tight tabular-nums">
            {meanRiskScore}<span className="text-xs text-slate-500 font-normal">/100</span>
          </div>
          <div className="text-[11px] text-slate-400 mt-1 font-mono">Fleet composite</div>
        </div>

        {/* Open Incidents */}
        <div
          onClick={() => onNavigateToModule('incidents')}
          className="p-3.5 rounded-xl bg-slate-900/90 border border-red-800/60 shadow-sm cursor-pointer hover:border-red-600 transition group"
        >
          <div className="flex items-center justify-between text-slate-300 mb-1.5">
            <span className="text-[11px] font-medium uppercase tracking-wider">Open Cases</span>
            <ArrowUpRight className="w-4 h-4 text-red-400 group-hover:translate-x-0.5 transition" />
          </div>
          <div className="text-2xl font-bold font-mono text-red-400 tracking-tight tabular-nums">
            {metrics.open_incidents}
          </div>
          <div className="text-[11px] text-slate-400 mt-1 font-mono">View Incident Cases &rarr;</div>
        </div>
      </div>

      {/* Hierarchy Level 2: Threat Visualizations (Histogram + Severity Breakdown) */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Telemetry Ingestion Histogram with Critical Spikes */}
        <div className="lg:col-span-2 p-5 rounded-xl bg-slate-900/90 border border-slate-800 shadow-sm space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                <BarChart2 className="w-4 h-4 text-cyan-400" />
                Security Ingestion Rate & Critical Spikes Over Time
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Real-time chronological telemetry volume bucketed in 10-minute bins
              </p>
            </div>
            <span className="text-xs font-mono text-cyan-300 bg-cyan-950/70 border border-cyan-800/60 px-2 py-0.5 rounded">
              Active Correlated Feed
            </span>
          </div>

          {/* Histogram Bar Display */}
          <div className="h-44 flex items-end gap-2.5 pt-6 pb-2 px-2 border-b border-slate-800">
            {metrics.events_over_time.length === 0 ? (
              <div className="w-full text-center text-xs text-slate-500 my-auto">
                No timeline bins available
              </div>
            ) : (
              metrics.events_over_time.map((bin, idx) => {
                const maxCount = Math.max(...metrics.events_over_time.map((b) => b.count), 1);
                const heightPct = Math.max(14, Math.round((bin.count / maxCount) * 100));
                const criticalHeightPct =
                  bin.critical > 0 ? Math.min(100, Math.round((bin.critical / bin.count) * 100)) : 0;

                return (
                  <div key={idx} className="flex-1 flex flex-col items-center gap-1 h-full justify-end group">
                    <span className="text-[10px] font-mono text-slate-400 opacity-0 group-hover:opacity-100 transition tabular-nums">
                      {bin.count}
                    </span>
                    <div
                      className="w-full max-w-[40px] rounded-t flex flex-col justify-end overflow-hidden transition-all bg-slate-800 group-hover:bg-slate-700"
                      style={{ height: `${heightPct}%` }}
                    >
                      {bin.critical > 0 && (
                        <div
                          className="w-full bg-red-500"
                          style={{ height: `${criticalHeightPct}%` }}
                          title={`${bin.critical} Critical / High Alerts`}
                        />
                      )}
                      <div className="w-full flex-1 bg-cyan-700/80 group-hover:bg-cyan-600 transition" />
                    </div>
                    <span className="text-[10px] font-mono text-slate-400 shrink-0 tabular-nums">
                      {bin.time}
                    </span>
                  </div>
                );
              })
            )}
          </div>

          <div className="flex items-center justify-between text-xs font-mono text-slate-400 pt-1">
            <span className="text-slate-500 text-[11px]">Hover bars to inspect bin counts</span>
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded bg-cyan-600" />
                <span>Baseline Telemetry</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded bg-red-500" />
                <span>Critical Spikes</span>
              </div>
            </div>
          </div>
        </div>

        {/* Severity Distribution Card */}
        <div className="p-5 rounded-xl bg-slate-900/90 border border-slate-800 shadow-sm space-y-4 flex flex-col justify-between">
          <div>
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-cyan-400" />
              Severity Breakdown
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">Distribution across enterprise risk tiers</p>
          </div>

          <div className="space-y-3">
            {metrics.severity_distribution.map((sev) => {
              const pct = metrics.total_events > 0 ? Math.round((sev.count / metrics.total_events) * 100) : 0;
              return (
                <div key={sev.name} className="space-y-1">
                  <div className="flex items-center justify-between text-xs font-mono">
                    <span className="font-semibold text-slate-300">{sev.name}</span>
                    <span className="text-slate-400 tabular-nums">
                      {sev.count} <span className="text-slate-500">({pct}%)</span>
                    </span>
                  </div>
                  <div className="h-2 bg-slate-950 rounded-full overflow-hidden border border-slate-800/80">
                    <div
                      className="h-full rounded-full transition-all duration-300"
                      style={{ width: `${pct}%`, backgroundColor: sev.color }}
                    />
                  </div>
                </div>
              );
            })}
          </div>

          <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-400 flex items-center justify-between">
            <span>SLA Response Window:</span>
            <span className="font-mono text-cyan-300 font-semibold">&le; 15 mins for Critical</span>
          </div>
        </div>
      </div>

      {/* Hierarchy Level 3: Threat Categories & Top Talkers */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Threat Categories Breakdown */}
        <div className="p-5 rounded-xl bg-slate-900/90 border border-slate-800 shadow-sm space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <Layers className="w-4 h-4 text-cyan-400" />
              Attack & Threat Categories
            </h3>
            <span className="text-xs text-slate-500 font-mono">Ranked</span>
          </div>

          <div className="space-y-2">
            {metrics.top_threat_categories.slice(0, 5).map((item, i) => {
              const maxCatCount = metrics.top_threat_categories[0]?.count || 1;
              const barPct = Math.round((item.count / maxCatCount) * 100);

              return (
                <div key={item.category} className="p-2 rounded-lg bg-slate-950 border border-slate-800/90 text-xs space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="font-medium text-slate-200 truncate">{item.category}</span>
                    <span className="font-mono text-amber-300 font-bold tabular-nums ml-2">
                      {item.count} hits
                    </span>
                  </div>
                  <div className="h-1 bg-slate-900 rounded-full overflow-hidden">
                    <div
                      className="h-full bg-amber-500/80 rounded-full"
                      style={{ width: `${barPct}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Top Attacking Source IPs */}
        <div className="p-5 rounded-xl bg-slate-900/90 border border-slate-800 shadow-sm space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <Globe className="w-4 h-4 text-cyan-400" />
              Top Source IPs (External / Suspicious)
            </h3>
            <span className="text-xs text-slate-500 font-mono">Origin</span>
          </div>

          <div className="space-y-2">
            {metrics.top_source_ips.slice(0, 5).map((src) => (
              <div
                key={src.ip}
                className="flex items-center justify-between p-2 rounded-lg bg-slate-950 border border-slate-800/90 text-xs"
              >
                <span className="font-mono text-cyan-300 font-semibold">{src.ip}</span>
                <span className="font-mono text-slate-400 tabular-nums">
                  {src.count} events
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Top Targeted Assets */}
        <div className="p-5 rounded-xl bg-slate-900/90 border border-slate-800 shadow-sm space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <Server className="w-4 h-4 text-cyan-400" />
              Top Targeted Internal Assets
            </h3>
            <span className="text-xs text-slate-500 font-mono">Target</span>
          </div>

          <div className="space-y-2">
            {metrics.top_target_assets.slice(0, 5).map((target) => (
              <div
                key={target.asset}
                className="flex items-center justify-between p-2 rounded-lg bg-slate-950 border border-slate-800/90 text-xs"
              >
                <span className="font-semibold text-slate-200">{target.asset}</span>
                <span className="font-mono text-slate-400 tabular-nums">
                  {target.count} hits
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Hierarchy Level 4: Live Attack Timeline & Active Incident Investigations */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* Active Incident Attack Timeline Viewer */}
        <div className="p-5 rounded-xl bg-slate-900/90 border border-slate-800 shadow-sm space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <div>
              <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                <Clock className="w-4 h-4 text-cyan-400" />
                Incident Attack Progression Timeline
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Multi-stage chronological sequence for selected incident case
              </p>
            </div>

            {/* Case selector */}
            <select
              value={selectedIncidentForTimeline}
              onChange={(e) => setSelectedIncidentForTimeline(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
            >
              {incidents.map((inc) => (
                <option key={inc.incident_id} value={inc.incident_id}>
                  {inc.incident_id}: {inc.title.slice(0, 32)}...
                </option>
              ))}
            </select>
          </div>

          {activeIncident ? (
            <div className="space-y-3">
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800/90 text-xs flex items-center justify-between">
                <div>
                  <span className="font-mono font-bold text-red-400 mr-2">{activeIncident.incident_id}</span>
                  <span className="font-semibold text-slate-200">{activeIncident.title}</span>
                </div>
                <button
                  onClick={() => onSelectIncident(activeIncident)}
                  className="text-cyan-400 hover:text-cyan-300 font-mono text-[11px] inline-flex items-center gap-1 shrink-0 ml-2"
                >
                  Manage <ChevronRight className="w-3.5 h-3.5" />
                </button>
              </div>

              {/* Render the dedicated Attack Timeline */}
              <div className="max-h-72 overflow-y-auto pr-1">
                <AttackTimeline
                  items={activeTimeline}
                  compact={false}
                  onSelectEventId={(id) => {
                    const found = events.find((e) => e.event_id === id);
                    if (found) onSelectEvent(found);
                  }}
                />
              </div>
            </div>
          ) : (
            <div className="p-8 text-center text-xs text-slate-500">
              No active incidents to display timeline.
            </div>
          )}
        </div>

        {/* Priority Security Triage Queue (Critical / High Alerts) */}
        <div className="p-5 rounded-xl bg-slate-900/90 border border-slate-800 shadow-sm space-y-3">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-red-400" />
                Priority Alert Triage Queue ({recentCritical.length})
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">High & Critical security alerts pending review</p>
            </div>
            <button
              onClick={() => onNavigateToModule('events')}
              className="text-xs text-cyan-400 hover:underline flex items-center gap-1"
            >
              All Events ({events.length}) <ChevronRight className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="space-y-2 max-h-80 overflow-y-auto pr-1">
            {recentCritical.length === 0 ? (
              <div className="p-6 text-center text-xs text-slate-500 bg-slate-950 rounded-lg border border-slate-800">
                <CheckCircle className="w-5 h-5 text-emerald-400 mx-auto mb-1.5" />
                All high and critical risk alerts have been cleared from the queue.
              </div>
            ) : (
              recentCritical.map((ev) => (
                <div
                  key={ev.event_id}
                  onClick={() => onSelectEvent(ev)}
                  className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 hover:border-slate-700 cursor-pointer transition text-xs space-y-1"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <SeverityBadge severity={ev.severity} />
                      <span className="font-mono text-cyan-400 font-semibold">{ev.event_id}</span>
                      <span className="text-slate-500 font-mono text-[11px] tabular-nums">
                        {new Date(ev.timestamp).toLocaleTimeString()}
                      </span>
                    </div>
                    <span className="text-slate-400 font-mono text-[11px] truncate max-w-[120px]">
                      {ev.asset}
                    </span>
                  </div>

                  <p className="text-slate-200 font-medium truncate">{ev.message}</p>

                  <div className="flex items-center justify-between text-[11px] text-slate-500 font-mono pt-1 border-t border-slate-900">
                    <span className="tabular-nums">
                      {ev.source_ip}:{ev.source_port} &rarr; {ev.destination_ip}:{ev.destination_port}
                    </span>
                    <span className="text-cyan-400 hover:underline">Triage &rarr;</span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
