/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { SecurityEvent } from '../../types/security';
import { SeverityBadge, DetectionMethodBadge } from '../common/SeverityBadge';
import { KeyRound, UserX, UserCheck, ShieldAlert, AlertTriangle, ChevronRight } from 'lucide-react';

interface AuthMonitoringViewProps {
  events: SecurityEvent[];
  onSelectEvent: (event: SecurityEvent) => void;
}

export const AuthMonitoringView: React.FC<AuthMonitoringViewProps> = ({
  events,
  onSelectEvent,
}) => {
  const authEvents = events.filter((e) => e.device_type === 'Authentication');

  const failed = authEvents.filter((e) => e.action === 'FAILURE');
  const success = authEvents.filter((e) => e.action === 'SUCCESS');
  const privEsc = authEvents.filter((e) => e.threat_category === 'Privilege Escalation');
  const bruteForce = authEvents.filter(
    (e) => e.threat_category === 'Brute Force' || e.threat_category === 'Suspicious Authentication'
  );

  return (
    <div className="space-y-6">
      {/* Top Auth Metrics */}
      <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 shadow-sm">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium">Total Auth Events</span>
            <KeyRound className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-white">{authEvents.length}</div>
          <span className="text-[11px] text-slate-500 font-mono">Sensors: dc-auth-01, jump-bastion</span>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 shadow-sm">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium">Valid Logins (SUCCESS)</span>
            <UserCheck className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-emerald-400">{success.length}</div>
          <span className="text-[11px] text-slate-500 font-mono">SSO / SSH Verified</span>
        </div>

        <div className="p-4 rounded-xl bg-amber-950/20 border border-amber-900/60 shadow-sm">
          <div className="flex items-center justify-between text-amber-300 mb-2">
            <span className="text-xs font-medium">Auth Failures</span>
            <UserX className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-amber-400">{failed.length}</div>
          <span className="text-[11px] text-amber-400/80 font-mono">Bad password / Unknown user</span>
        </div>

        <div className="p-4 rounded-xl bg-red-950/20 border border-red-900/60 shadow-sm">
          <div className="flex items-center justify-between text-red-300 mb-2">
            <span className="text-xs font-medium">Privilege Escalations</span>
            <ShieldAlert className="w-4 h-4 text-red-400 animate-pulse" />
          </div>
          <div className="text-2xl font-bold font-mono text-red-400">{privEsc.length}</div>
          <span className="text-[11px] text-red-400/80 font-mono">Sudo / Root escalation alerts</span>
        </div>
      </div>

      {/* Detection Spotlight: Suspicious Auth Sequences & Brute Force */}
      {bruteForce.length > 0 && (
        <div className="p-4 rounded-xl bg-red-950/30 border border-red-800/80 space-y-2">
          <div className="flex items-center gap-2 text-red-400 font-semibold text-xs uppercase tracking-wider">
            <AlertTriangle className="w-4 h-4" />
            Active Credential Attack Alert: Brute Force & Suspicious Sequences Detected
          </div>
          <p className="text-xs text-slate-200">
            Deterministic correlation rule matched consecutive failed authentication attempts followed by successful logon from external IP 185.220.101.5. Immediate password rotation and credential isolation recommended.
          </p>
        </div>
      )}

      {/* Authentication Stream Table */}
      <div className="rounded-xl bg-slate-900 border border-slate-800 shadow-sm overflow-hidden">
        <div className="px-4 py-3 border-b border-slate-800 bg-slate-950/60 text-xs font-semibold text-slate-200 flex items-center justify-between">
          <span>Identity & Access Audit Log ({authEvents.length} Records)</span>
          <span className="text-slate-500 font-mono text-[11px]">Protocols: SSH, Kerberos, SAML 2.0</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-950/40 text-slate-400 font-mono text-[11px] uppercase">
                <th className="py-2.5 px-3">Timestamp</th>
                <th className="py-2.5 px-3">User</th>
                <th className="py-2.5 px-3">Action</th>
                <th className="py-2.5 px-3">Severity</th>
                <th className="py-2.5 px-3">Detection</th>
                <th className="py-2.5 px-3">Source IP</th>
                <th className="py-2.5 px-3">Target Asset</th>
                <th className="py-2.5 px-3">Audit Message</th>
                <th className="py-2.5 px-3 text-right">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {authEvents.map((ev) => (
                <tr
                  key={ev.event_id}
                  onClick={() => onSelectEvent(ev)}
                  className="hover:bg-slate-800/40 cursor-pointer transition"
                >
                  <td className="py-2.5 px-3 font-mono text-slate-400 text-[11px]">
                    {new Date(ev.timestamp).toLocaleTimeString()}
                  </td>
                  <td className="py-2.5 px-3 font-mono font-bold text-cyan-300">
                    {ev.username || '-'}
                  </td>
                  <td className="py-2.5 px-3">
                    <span
                      className={`font-mono font-bold text-[11px] ${
                        ev.action === 'SUCCESS' ? 'text-emerald-400' : 'text-red-400'
                      }`}
                    >
                      {ev.action}
                    </span>
                  </td>
                  <td className="py-2.5 px-3">
                    <SeverityBadge severity={ev.severity} />
                  </td>
                  <td className="py-2.5 px-3">
                    <DetectionMethodBadge method={ev.detection_method} />
                  </td>
                  <td className="py-2.5 px-3 font-mono text-slate-300 text-[11px]">
                    {ev.source_ip}
                  </td>
                  <td className="py-2.5 px-3 font-semibold text-slate-200">{ev.asset}</td>
                  <td className="py-2.5 px-3 max-w-sm truncate text-slate-300">{ev.message}</td>
                  <td className="py-2.5 px-3 text-right">
                    <span className="text-cyan-400 font-mono inline-flex items-center gap-1 hover:underline">
                      Triage <ChevronRight className="w-3 h-3" />
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
