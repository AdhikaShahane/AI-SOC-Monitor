/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { SecurityEvent } from '../../types/security';
import { SeverityBadge, DetectionMethodBadge } from '../common/SeverityBadge';
import { BarChart2, Zap, ArrowUpRight, Cpu, ChevronRight, AlertOctagon } from 'lucide-react';

interface NetworkAnomalyViewProps {
  events: SecurityEvent[];
  onSelectEvent: (event: SecurityEvent) => void;
}

export const NetworkAnomalyView: React.FC<NetworkAnomalyViewProps> = ({
  events,
  onSelectEvent,
}) => {
  const flowEvents = events.filter(
    (e) =>
      e.device_type === 'Network Flow' ||
      e.threat_category === 'DDoS/Traffic Anomaly' ||
      e.threat_category === 'Data Exfiltration Indicator' ||
      e.threat_category === 'Command-and-Control Indicator' ||
      e.threat_category === 'Port Scanning'
  );

  const exfilEvents = events.filter((e) => e.threat_category === 'Data Exfiltration Indicator');
  const c2Events = events.filter((e) => e.threat_category === 'Command-and-Control Indicator');
  const ddosEvents = events.filter((e) => e.threat_category === 'DDoS/Traffic Anomaly');

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 shadow-sm">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium">Network Flow Anomalies</span>
            <BarChart2 className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-white">{flowEvents.length}</div>
          <span className="text-[11px] text-slate-500 font-mono">Sensors: Zeek, NetFlow v9</span>
        </div>

        <div className="p-4 rounded-xl bg-red-950/20 border border-red-900/60 shadow-sm">
          <div className="flex items-center justify-between text-red-300 mb-2">
            <span className="text-xs font-medium">Data Exfiltration Alerts</span>
            <ArrowUpRight className="w-4 h-4 text-red-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-red-400">{exfilEvents.length}</div>
          <span className="text-[11px] text-red-400/80 font-mono">Volume threshold &gt; 10MB</span>
        </div>

        <div className="p-4 rounded-xl bg-amber-950/20 border border-amber-900/60 shadow-sm">
          <div className="flex items-center justify-between text-amber-300 mb-2">
            <span className="text-xs font-medium">C2 Beaconing Indicators</span>
            <Zap className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-amber-400">{c2Events.length}</div>
          <span className="text-[11px] text-amber-400/80 font-mono">Periodic persistent egress</span>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 shadow-sm">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium">DDoS / SYN Floods</span>
            <Cpu className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-slate-200">{ddosEvents.length}</div>
          <span className="text-[11px] text-slate-500 font-mono">Rate threshold &gt; 20k pkts</span>
        </div>
      </div>

      {/* Exfiltration & Beaconing Spotlight */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2 text-xs">
          <h4 className="font-semibold text-slate-200 flex items-center gap-2">
            <ArrowUpRight className="w-4 h-4 text-red-400" />
            High Volume Egress Detector (Rule RULE-EXFIL-008)
          </h4>
          <p className="text-slate-400 leading-relaxed">
            Correlates byte transfers between RFC1918 internal subnets and external Internet routable addresses. Detects abnormal single session exfiltration spikes and staging servers.
          </p>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2 text-xs">
          <h4 className="font-semibold text-slate-200 flex items-center gap-2">
            <Zap className="w-4 h-4 text-amber-400" />
            Beaconing Analysis & Jitter Calculation (Rule RULE-C2-006)
          </h4>
          <p className="text-slate-400 leading-relaxed">
            Statistical interval analysis monitors TCP/TLS sessions exhibiting low-jitter heartbeat beacons towards suspicious non-standard external ports (4444, 8443, 1337).
          </p>
        </div>
      </div>

      {/* Network Anomaly Stream Table */}
      <div className="rounded-xl bg-slate-900 border border-slate-800 shadow-sm overflow-hidden">
        <div className="px-4 py-3 border-b border-slate-800 bg-slate-950/60 text-xs font-semibold text-slate-200 flex items-center justify-between">
          <span>Flow Telemetry & Anomalous Traffic Sessions ({flowEvents.length} Records)</span>
          <span className="text-slate-500 font-mono text-[11px]">Sensor Engine: Zeek / NetFlow v9</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-950/40 text-slate-400 font-mono text-[11px] uppercase">
                <th className="py-2.5 px-3">Timestamp</th>
                <th className="py-2.5 px-3">Category</th>
                <th className="py-2.5 px-3">Severity</th>
                <th className="py-2.5 px-3">Source &rarr; Dest</th>
                <th className="py-2.5 px-3">Asset</th>
                <th className="py-2.5 px-3">Bytes / Packets</th>
                <th className="py-2.5 px-3">Observation</th>
                <th className="py-2.5 px-3 text-right">Inspect</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {flowEvents.map((ev) => (
                <tr
                  key={ev.event_id}
                  onClick={() => onSelectEvent(ev)}
                  className="hover:bg-slate-800/40 cursor-pointer transition"
                >
                  <td className="py-2.5 px-3 font-mono text-slate-400 text-[11px]">
                    {new Date(ev.timestamp).toLocaleTimeString()}
                  </td>
                  <td className="py-2.5 px-3 font-medium text-slate-200">{ev.threat_category}</td>
                  <td className="py-2.5 px-3">
                    <SeverityBadge severity={ev.severity} />
                  </td>
                  <td className="py-2.5 px-3 font-mono text-slate-300 text-[11px]">
                    <span className="text-cyan-400">{ev.source_ip}</span>:{ev.source_port} &rarr;{' '}
                    <span className="text-slate-200">{ev.destination_ip}</span>:{ev.destination_port}
                  </td>
                  <td className="py-2.5 px-3 font-semibold text-slate-200">{ev.asset}</td>
                  <td className="py-2.5 px-3 font-mono text-slate-300 text-[11px]">
                    {ev.bytes_transferred ? `${(ev.bytes_transferred / (1024 * 1024)).toFixed(2)} MB` : '0 KB'}{' '}
                    <span className="text-slate-500">({ev.packets || 0} pkts)</span>
                  </td>
                  <td className="py-2.5 px-3 max-w-xs truncate text-slate-300">{ev.message}</td>
                  <td className="py-2.5 px-3 text-right">
                    <span className="text-cyan-400 font-mono inline-flex items-center gap-1 hover:underline">
                      Flow &rarr;
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
