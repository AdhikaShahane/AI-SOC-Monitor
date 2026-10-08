/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { SecurityEvent } from '../../types/security';
import { SeverityBadge } from '../common/SeverityBadge';
import { Flame, Shield, ArrowDownLeft, ArrowUpRight, Filter, Globe, ChevronRight } from 'lucide-react';

interface FirewallMonitoringViewProps {
  events: SecurityEvent[];
  onSelectEvent: (event: SecurityEvent) => void;
}

export const FirewallMonitoringView: React.FC<FirewallMonitoringViewProps> = ({
  events,
  onSelectEvent,
}) => {
  const fwEvents = events.filter((e) => e.device_type === 'Firewall');

  const [filterAction, setFilterAction] = useState<string>('ALL');

  const filtered = fwEvents.filter((e) => {
    if (filterAction !== 'ALL' && e.action !== filterAction) return false;
    return true;
  });

  const allows = fwEvents.filter((e) => e.action === 'ALLOW').length;
  const drops = fwEvents.filter((e) => e.action === 'DROP' || e.action === 'BLOCK').length;
  const dropPct = fwEvents.length > 0 ? Math.round((drops / fwEvents.length) * 100) : 0;

  // Port distribution
  const portMap = new Map<number, number>();
  fwEvents.forEach((e) => {
    if (e.destination_port) {
      portMap.set(e.destination_port, (portMap.get(e.destination_port) || 0) + 1);
    }
  });

  const topPorts = Array.from(portMap.entries())
    .map(([port, count]) => ({ port, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 5);

  return (
    <div className="space-y-6">
      {/* Top Firewall Health Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 shadow-sm">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium">Total Firewall Events</span>
            <Flame className="w-4 h-4 text-orange-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-white">{fwEvents.length}</div>
          <span className="text-[11px] text-slate-500 font-mono">Sensors: fw-edge-01, fw-core</span>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 shadow-sm">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium">Policy ALLOW Rate</span>
            <ArrowDownLeft className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-emerald-400">{allows}</div>
          <span className="text-[11px] text-slate-500 font-mono">Standard enterprise ingress</span>
        </div>

        <div className="p-4 rounded-xl bg-red-950/20 border border-red-900/60 shadow-sm">
          <div className="flex items-center justify-between text-red-300 mb-2">
            <span className="text-xs font-medium">Policy DROP / BLOCK</span>
            <Shield className="w-4 h-4 text-red-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-red-400">{drops}</div>
          <span className="text-[11px] text-red-400/80 font-mono">Edge ACL & IPS Enforcement</span>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 shadow-sm">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium">Drop Ratio</span>
            <span className="font-mono text-xs text-cyan-400">{dropPct}%</span>
          </div>
          <div className="h-2 bg-slate-950 rounded-full overflow-hidden border border-slate-800 my-2">
            <div className="h-full bg-red-500 rounded-full" style={{ width: `${dropPct}%` }} />
          </div>
          <span className="text-[11px] text-slate-500 font-mono">Normal perimeter threshold &lt; 30%</span>
        </div>
      </div>

      {/* Port distribution and Policy Rules */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Top Destination Ports */}
        <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 shadow-sm space-y-3">
          <h3 className="text-sm font-semibold text-white flex items-center gap-2">
            <Globe className="w-4 h-4 text-cyan-400" />
            Top Targeted Destination Ports
          </h3>
          <div className="space-y-2">
            {topPorts.map((item) => (
              <div
                key={item.port}
                className="flex items-center justify-between p-2 rounded-lg bg-slate-950 border border-slate-800/80 text-xs"
              >
                <div className="flex items-center gap-2">
                  <span className="font-mono font-bold text-cyan-400">Port {item.port}</span>
                  <span className="text-slate-400">
                    {item.port === 80
                      ? '(HTTP)'
                      : item.port === 443
                      ? '(HTTPS)'
                      : item.port === 22
                      ? '(SSH)'
                      : item.port === 21
                      ? '(FTP)'
                      : item.port === 3389
                      ? '(RDP)'
                      : item.port === 4444
                      ? '(Metasploit / C2)'
                      : item.port === 8443
                      ? '(Alt HTTPS / C2)'
                      : '(Custom)'}
                  </span>
                </div>
                <span className="font-mono text-slate-300 bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
                  {item.count} sessions
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Firewall Active Policies */}
        <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 shadow-sm space-y-3">
          <h3 className="text-sm font-semibold text-white flex items-center gap-2">
            <Shield className="w-4 h-4 text-cyan-400" />
            Edge Boundary Security Policies
          </h3>
          <div className="space-y-2 text-xs">
            <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between">
              <div>
                <span className="font-mono text-cyan-300 font-semibold">RULE-101: Web Tier Ingress</span>
                <p className="text-[11px] text-slate-400">Allow TCP 80, 443 to DMZ VIP</p>
              </div>
              <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 text-[10px] font-bold">
                ENFORCED
              </span>
            </div>
            <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between">
              <div>
                <span className="font-mono text-cyan-300 font-semibold">RULE-104: Default Ingress Deny</span>
                <p className="text-[11px] text-slate-400">Drop unauthorized external ports (21, 23, 3389, 445)</p>
              </div>
              <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 text-[10px] font-bold">
                ENFORCED
              </span>
            </div>
            <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between">
              <div>
                <span className="font-mono text-cyan-300 font-semibold">RULE-202: Egress Threat Blocker</span>
                <p className="text-[11px] text-slate-400">Block outbound connections to C2 ports (4444, 1337, 6667)</p>
              </div>
              <span className="px-2 py-0.5 rounded bg-red-950 text-red-400 text-[10px] font-bold">
                ALERT & DROP
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Firewall Log Feed Table */}
      <div className="rounded-xl bg-slate-900 border border-slate-800 shadow-sm overflow-hidden">
        <div className="flex items-center justify-between px-4 py-3 border-b border-slate-800 bg-slate-950/60 text-xs">
          <span className="font-semibold text-slate-200">
            Perimeter Firewall Session Table ({filtered.length} logs)
          </span>
          <div className="flex items-center gap-2">
            <span className="text-slate-400 text-xs">Filter Action:</span>
            <select
              value={filterAction}
              onChange={(e) => setFilterAction(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded px-2 py-1 text-slate-200 text-xs"
            >
              <option value="ALL">All Actions</option>
              <option value="ALLOW">ALLOW</option>
              <option value="DROP">DROP</option>
              <option value="BLOCK">BLOCK</option>
            </select>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-950/40 text-slate-400 font-mono text-[11px] uppercase">
                <th className="py-2.5 px-3">Timestamp</th>
                <th className="py-2.5 px-3">Device</th>
                <th className="py-2.5 px-3">Action</th>
                <th className="py-2.5 px-3">Protocol</th>
                <th className="py-2.5 px-3">Source &rarr; Destination</th>
                <th className="py-2.5 px-3">Target Asset</th>
                <th className="py-2.5 px-3">Severity</th>
                <th className="py-2.5 px-3">Message</th>
                <th className="py-2.5 px-3 text-right">Inspect</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filtered.map((ev) => (
                <tr
                  key={ev.event_id}
                  onClick={() => onSelectEvent(ev)}
                  className="hover:bg-slate-800/40 cursor-pointer transition"
                >
                  <td className="py-2.5 px-3 font-mono text-slate-400 text-[11px]">
                    {new Date(ev.timestamp).toLocaleTimeString()}
                  </td>
                  <td className="py-2.5 px-3 font-mono text-slate-300">{ev.device}</td>
                  <td className="py-2.5 px-3">
                    <span
                      className={`font-mono font-bold text-[11px] ${
                        ev.action === 'ALLOW' ? 'text-emerald-400' : 'text-red-400'
                      }`}
                    >
                      {ev.action}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 font-mono text-slate-400">{ev.protocol}</td>
                  <td className="py-2.5 px-3 font-mono text-slate-300 text-[11px]">
                    <span className="text-cyan-400">{ev.source_ip}</span>:{ev.source_port} &rarr;{' '}
                    <span className="text-slate-200">{ev.destination_ip}</span>:{ev.destination_port}
                  </td>
                  <td className="py-2.5 px-3 font-semibold text-slate-200">{ev.asset}</td>
                  <td className="py-2.5 px-3">
                    <SeverityBadge severity={ev.severity} />
                  </td>
                  <td className="py-2.5 px-3 max-w-xs truncate text-slate-300">{ev.message}</td>
                  <td className="py-2.5 px-3 text-right">
                    <span className="text-cyan-400 font-mono inline-flex items-center gap-1 hover:underline">
                      View <ChevronRight className="w-3 h-3" />
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
