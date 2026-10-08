/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { SecurityEvent } from '../../types/security';
import { SeverityBadge, DetectionMethodBadge } from '../common/SeverityBadge';
import { Radio, AlertOctagon, ShieldAlert, Terminal, ChevronRight } from 'lucide-react';

interface IdsIpsMonitoringViewProps {
  events: SecurityEvent[];
  onSelectEvent: (event: SecurityEvent) => void;
}

export const IdsIpsMonitoringView: React.FC<IdsIpsMonitoringViewProps> = ({
  events,
  onSelectEvent,
}) => {
  const idsEvents = events.filter((e) => e.device_type === 'IDS/IPS');

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 shadow-sm">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium">Suricata / Snort Alerts</span>
            <Radio className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-white">{idsEvents.length}</div>
          <span className="text-[11px] text-slate-500 font-mono">Sensors: ids-core-01, ids-dmz-02</span>
        </div>

        <div className="p-4 rounded-xl bg-red-950/20 border border-red-900/60 shadow-sm">
          <div className="flex items-center justify-between text-red-300 mb-2">
            <span className="text-xs font-medium">High Severity Signatures</span>
            <ShieldAlert className="w-4 h-4 text-red-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-red-400">
            {idsEvents.filter((e) => e.severity === 'CRITICAL' || e.severity === 'HIGH').length}
          </div>
          <span className="text-[11px] text-red-400/80 font-mono">Signature rules matched</span>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 shadow-sm">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium">Active Signature Rulebase</span>
            <span className="text-xs font-mono text-emerald-400">ET Open + Custom</span>
          </div>
          <div className="text-2xl font-bold font-mono text-slate-200">28,490 SIDs</div>
          <span className="text-[11px] text-slate-500 font-mono">MITRE ATT&CK Tagged</span>
        </div>
      </div>

      {/* Signature Alert Cards */}
      <div className="rounded-xl bg-slate-900 border border-slate-800 shadow-sm overflow-hidden">
        <div className="px-4 py-3 border-b border-slate-800 bg-slate-950/60 text-xs font-semibold text-slate-200 flex items-center justify-between">
          <span>Intrusion Detection Alert Stream ({idsEvents.length} Signatures Fired)</span>
          <span className="text-slate-500 font-mono text-[11px]">Engine: Suricata 7.0 IPS/IDS</span>
        </div>

        <div className="divide-y divide-slate-800/60">
          {idsEvents.length === 0 ? (
            <div className="p-8 text-center text-slate-500 text-xs">
              No IDS/IPS alerts detected in current telemetry.
            </div>
          ) : (
            idsEvents.map((ev) => (
              <div
                key={ev.event_id}
                onClick={() => onSelectEvent(ev)}
                className="p-4 hover:bg-slate-800/30 cursor-pointer transition space-y-2 text-xs"
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <SeverityBadge severity={ev.severity} />
                    <DetectionMethodBadge method={ev.detection_method} />
                    <span className="font-mono text-cyan-400 font-bold">{ev.event_id}</span>
                    <span className="font-mono text-slate-400 text-[11px]">
                      {new Date(ev.timestamp).toLocaleTimeString()}
                    </span>
                  </div>
                  <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-slate-950 border border-slate-800 text-slate-300">
                    Target: {ev.asset}
                  </span>
                </div>

                <div className="flex items-start justify-between gap-4">
                  <div>
                    <h4 className="font-semibold text-slate-100 text-sm">{ev.message}</h4>
                    {ev.detection_reason && (
                      <p className="text-xs text-slate-400 mt-1 font-sans">{ev.detection_reason}</p>
                    )}
                  </div>
                  <button className="text-cyan-400 hover:text-cyan-300 font-mono text-xs inline-flex items-center gap-1 shrink-0">
                    Inspect Signature &rarr;
                  </button>
                </div>

                {/* Network & Signature Detail */}
                <div className="flex flex-wrap items-center justify-between gap-2 pt-2 border-t border-slate-950 text-[11px] text-slate-400 font-mono">
                  <div>
                    <span>SRC: </span>
                    <span className="text-cyan-300">{ev.source_ip}:{ev.source_port}</span>
                    <span> &rarr; DST: </span>
                    <span className="text-slate-300">{ev.destination_ip}:{ev.destination_port}</span>
                  </div>
                  {ev.mitre_attack && (
                    <div className="text-purple-300">
                      MITRE ATT&CK: {ev.mitre_attack.technique_id} ({ev.mitre_attack.technique_name})
                    </div>
                  )}
                </div>

                {ev.raw_payload && (
                  <div className="p-2 rounded bg-slate-950 border border-slate-800/90 font-mono text-[11px] text-cyan-300/80 truncate">
                    {ev.raw_payload}
                  </div>
                )}
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};
