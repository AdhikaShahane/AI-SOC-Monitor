/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import {
  LayoutDashboard,
  Activity,
  Flame,
  Radio,
  KeyRound,
  BarChart2,
  AlertOctagon,
  Sparkles,
  FileText,
  Sliders,
  Shield,
  Layers,
} from 'lucide-react';

export type ActiveModule =
  | 'dashboard'
  | 'events'
  | 'firewall'
  | 'ids'
  | 'auth'
  | 'network'
  | 'incidents'
  | 'ai-analyst'
  | 'reports'
  | 'settings';

interface SidebarProps {
  activeModule: ActiveModule;
  onSelectModule: (module: ActiveModule) => void;
  openIncidentsCount: number;
  criticalEventsCount: number;
  totalEventsCount: number;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeModule,
  onSelectModule,
  openIncidentsCount,
  criticalEventsCount,
  totalEventsCount,
}) => {
  const navItems = [
    {
      id: 'dashboard' as ActiveModule,
      name: 'SOC Dashboard',
      icon: LayoutDashboard,
      badge: null,
    },
    {
      id: 'events' as ActiveModule,
      name: 'Security Events',
      icon: Activity,
      badge: totalEventsCount > 0 ? totalEventsCount : null,
      badgeColor: 'bg-slate-800 text-slate-300',
    },
    {
      id: 'firewall' as ActiveModule,
      name: 'Firewall Monitoring',
      icon: Flame,
      badge: null,
    },
    {
      id: 'ids' as ActiveModule,
      name: 'IDS / IPS Alerts',
      icon: Radio,
      badge: null,
    },
    {
      id: 'auth' as ActiveModule,
      name: 'Auth Monitoring',
      icon: KeyRound,
      badge: null,
    },
    {
      id: 'network' as ActiveModule,
      name: 'Network Anomaly',
      icon: BarChart2,
      badge: null,
    },
    {
      id: 'incidents' as ActiveModule,
      name: 'Incident Management',
      icon: AlertOctagon,
      badge: openIncidentsCount > 0 ? openIncidentsCount : null,
      badgeColor: 'bg-red-950 text-red-300 border border-red-800',
    },
    {
      id: 'ai-analyst' as ActiveModule,
      name: 'AI Security Analyst',
      icon: Sparkles,
      badge: 'GEMINI',
      badgeColor: 'bg-purple-950 text-purple-300 border border-purple-800 font-mono text-[10px]',
    },
    {
      id: 'reports' as ActiveModule,
      name: 'Reports & Post-Mortem',
      icon: FileText,
      badge: null,
    },
    {
      id: 'settings' as ActiveModule,
      name: 'Detection Rules & Config',
      icon: Sliders,
      badge: null,
    },
  ];

  return (
    <aside className="w-full md:w-64 bg-slate-950 border-r border-slate-800/80 flex flex-col shrink-0">
      {/* Navigation list */}
      <div className="p-3 space-y-1">
        <div className="px-3 py-1.5 text-[10px] font-mono uppercase tracking-wider text-slate-500 font-semibold">
          SOC Operations Center
        </div>
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeModule === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onSelectModule(item.id)}
              className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs font-medium transition select-none ${
                isActive
                  ? 'bg-cyan-950/80 text-cyan-300 border border-cyan-800/80 shadow-sm'
                  : 'text-slate-400 hover:text-slate-100 hover:bg-slate-900'
              }`}
            >
              <div className="flex items-center gap-2.5">
                <Icon
                  className={`w-4 h-4 ${
                    isActive ? 'text-cyan-400' : 'text-slate-500 group-hover:text-slate-400'
                  }`}
                />
                <span>{item.name}</span>
              </div>
              {item.badge && (
                <span
                  className={`px-1.5 py-0.5 rounded text-[11px] font-medium ${
                    item.badgeColor || 'bg-slate-800 text-slate-300'
                  }`}
                >
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* Threat Posture Gauge in Sidebar Footer */}
      <div className="mt-auto p-4 border-t border-slate-900 bg-slate-950/80">
        <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800 text-xs">
          <div className="flex items-center justify-between mb-1.5">
            <span className="text-slate-400 font-medium flex items-center gap-1.5">
              <Shield className="w-3.5 h-3.5 text-cyan-400" />
              Defense Posture
            </span>
            <span
              className={`font-mono font-bold text-[11px] ${
                criticalEventsCount > 0 ? 'text-red-400' : 'text-emerald-400'
              }`}
            >
              {criticalEventsCount > 0 ? 'ELEVATED' : 'SECURE'}
            </span>
          </div>
          <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden mb-2">
            <div
              className={`h-full rounded-full transition-all duration-500 ${
                criticalEventsCount > 0 ? 'bg-red-500 w-3/4' : 'bg-emerald-500 w-1/4'
              }`}
            />
          </div>
          <div className="flex items-center justify-between text-[11px] text-slate-500 font-mono">
            <span>Critical Alerts: {criticalEventsCount}</span>
            <span>Open Incidents: {openIncidentsCount}</span>
          </div>
        </div>
      </div>
    </aside>
  );
};
