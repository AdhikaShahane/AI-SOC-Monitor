/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { AttackTimelineItem } from '../../types/security';
import { SeverityBadge } from './SeverityBadge';
import { Clock, ShieldAlert, CheckCircle2, AlertTriangle, ArrowRight, ExternalLink } from 'lucide-react';

interface AttackTimelineProps {
  items: AttackTimelineItem[];
  compact?: boolean;
  onSelectEventId?: (eventId: string) => void;
}

export const AttackTimeline: React.FC<AttackTimelineProps> = ({
  items,
  compact = false,
  onSelectEventId,
}) => {
  if (!items || items.length === 0) {
    return (
      <div className="py-6 px-4 text-center rounded-lg bg-slate-900/60 border border-slate-800 text-xs text-slate-400">
        No attack sequence events recorded for this incident yet.
      </div>
    );
  }

  return (
    <div className="relative pl-6 space-y-4 before:absolute before:left-2.5 before:top-2 before:bottom-2 before:w-px before:bg-slate-800">
      {items.map((item, index) => {
        const isCritical = item.severity === 'CRITICAL';
        const isHigh = item.severity === 'HIGH';
        const isSuccess = item.action.toLowerCase().includes('success');

        const dotColor = isCritical
          ? 'bg-red-500 border-red-950'
          : isHigh
          ? 'bg-amber-500 border-amber-950'
          : isSuccess
          ? 'bg-emerald-500 border-emerald-950'
          : 'bg-slate-400 border-slate-950';

        return (
          <div key={item.id || index} className="relative group text-xs">
            {/* Timeline node dot */}
            <span
              className={`absolute -left-[19px] top-1.5 w-2.5 h-2.5 rounded-full border-2 ${dotColor} transition-transform group-hover:scale-125`}
            />

            <div className="bg-slate-900/90 border border-slate-800/90 rounded-lg p-3 hover:border-slate-700 transition">
              {/* Primary Line: 19:42:01 — Failed authentication */}
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-2 font-mono text-xs">
                  <span className="text-slate-400 tabular-nums font-semibold">
                    {item.time_display || item.timestamp.slice(11, 19)}
                  </span>
                  <span className="text-slate-600 font-bold">&mdash;</span>
                  <span
                    className={`font-semibold tracking-tight ${
                      isCritical
                        ? 'text-red-400'
                        : isHigh
                        ? 'text-amber-300'
                        : isSuccess
                        ? 'text-emerald-400'
                        : 'text-slate-200'
                    }`}
                  >
                    {item.action}
                  </span>
                </div>

                <div className="flex items-center gap-1.5">
                  {item.severity && <SeverityBadge severity={item.severity} />}
                  {item.event_id && onSelectEventId && (
                    <button
                      onClick={() => onSelectEventId(item.event_id!)}
                      className="text-[11px] font-mono text-cyan-400 hover:text-cyan-300 inline-flex items-center gap-0.5 ml-1 transition"
                      title={`Inspect raw event ${item.event_id}`}
                    >
                      {item.event_id}
                      <ExternalLink className="w-3 h-3" />
                    </button>
                  )}
                </div>
              </div>

              {/* Secondary Details: Description & Context */}
              {!compact && (
                <div className="mt-1.5 pt-1.5 border-t border-slate-800/60 text-slate-300 text-[11px] leading-relaxed flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <p className="font-sans text-slate-300">{item.description}</p>
                  {(item.source_ip || item.asset) && (
                    <div className="flex items-center gap-2 text-slate-400 font-mono text-[10px] shrink-0">
                      {item.source_ip && <span>Src: {item.source_ip}</span>}
                      {item.asset && <span>Target: {item.asset}</span>}
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
};
