/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import {
  Shield,
  Activity,
  Play,
  Pause,
  Upload,
  Download,
  Trash2,
  RefreshCw,
  Search,
  Sparkles,
  Radio,
} from 'lucide-react';

interface NavbarProps {
  isStreaming: boolean;
  onToggleStreaming: () => void;
  onGenerateSampleLogs: () => void;
  onOpenUploadModal: () => void;
  onClearLogs: () => void;
  onExportLogs: () => void;
  searchQuery: string;
  onSearchChange: (query: string) => void;
  totalEventsCount: number;
  criticalEventsCount: number;
  aiEngineStatus: { online: boolean; ai_available: boolean; model: string };
}

export const Navbar: React.FC<NavbarProps> = ({
  isStreaming,
  onToggleStreaming,
  onGenerateSampleLogs,
  onOpenUploadModal,
  onClearLogs,
  onExportLogs,
  searchQuery,
  onSearchChange,
  totalEventsCount,
  criticalEventsCount,
  aiEngineStatus,
}) => {
  return (
    <header className="sticky top-0 z-40 w-full bg-slate-950/95 border-b border-slate-800/80 backdrop-blur-md px-4 py-2.5">
      <div className="flex flex-col lg:flex-row items-stretch lg:items-center justify-between gap-3">
        {/* Brand & SOC Status */}
        <div className="flex items-center justify-between lg:justify-start gap-4">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-slate-900 border border-slate-800 text-cyan-400 shadow-sm">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-base tracking-tight text-white flex items-center gap-1.5">
                  Sentinel<span className="text-cyan-400 font-mono">AI</span>
                </span>
                <span className="text-xs text-slate-500 font-mono">SOC</span>
              </div>
              <p className="text-[11px] text-slate-400 hidden sm:block">
                Security Monitoring & Incident Analysis Platform
              </p>
            </div>
          </div>

          {/* DEFCON Status Pill */}
          <div className="flex items-center gap-2 px-2.5 py-1 rounded-lg bg-slate-900 border border-slate-800 text-[11px]">
            <span
              className={`w-2 h-2 rounded-full ${criticalEventsCount > 0 ? 'bg-red-500' : 'bg-amber-400'}`}
            />
            <span className="font-mono text-slate-400">DEFCON:</span>
            <span className={`font-mono font-semibold ${criticalEventsCount > 0 ? 'text-red-400' : 'text-amber-400'}`}>
              {criticalEventsCount > 0 ? '2 (CRITICAL)' : '3 (ELEVATED)'}
            </span>
          </div>
        </div>

        {/* Global Search Bar */}
        <div className="flex-1 max-w-md mx-0 lg:mx-4">
          <div className="relative">
            <Search className="absolute left-3 top-2.5 w-4 h-4 text-slate-500" />
            <input
              type="text"
              placeholder="Search IP, Event ID, Asset, User, or CVE..."
              value={searchQuery}
              onChange={(e) => onSearchChange(e.target.value)}
              className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-slate-900/90 border border-slate-800 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 transition"
            />
            {searchQuery && (
              <button
                onClick={() => onSearchChange('')}
                className="absolute right-2.5 top-2 text-xs text-slate-400 hover:text-white"
              >
                &times;
              </button>
            )}
          </div>
        </div>

        {/* Actions & Stream Controls */}
        <div className="flex flex-wrap items-center gap-2 justify-end">
          {/* Live Stream Ingestion Toggle */}
          <button
            onClick={onToggleStreaming}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 border transition ${
              isStreaming
                ? 'bg-emerald-950/80 border-emerald-700/80 text-emerald-300'
                : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-200'
            }`}
            title="Simulate live streaming packet & event ingestion every 4s"
          >
            {isStreaming ? (
              <>
                <Radio className="w-3.5 h-3.5 text-emerald-400 animate-pulse" />
                <span>Live Feed Active</span>
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5 text-slate-400" />
                <span>Start Stream</span>
              </>
            )}
          </button>

          {/* Sample Attack Scenarios Generator */}
          <button
            onClick={onGenerateSampleLogs}
            className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-cyan-950/80 hover:bg-cyan-900 border border-cyan-800/80 text-cyan-300 flex items-center gap-1.5 transition shadow"
            title="Generate full 500+ event synthetic dataset across 8 realistic scenarios"
          >
            <RefreshCw className="w-3.5 h-3.5 text-cyan-400" />
            <span>Generate Demo Dataset</span>
          </button>

          {/* Ingest Menu */}
          <button
            onClick={onOpenUploadModal}
            className="px-2.5 py-1.5 rounded-lg text-xs font-medium bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 flex items-center gap-1.5 transition"
            title="Upload custom JSON or CSV logs"
          >
            <Upload className="w-3.5 h-3.5 text-slate-400" />
            <span className="hidden sm:inline">Upload</span>
          </button>

          <button
            onClick={onExportLogs}
            className="px-2.5 py-1.5 rounded-lg text-xs font-medium bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 flex items-center gap-1.5 transition"
            title="Export all events to JSON"
          >
            <Download className="w-3.5 h-3.5 text-slate-400" />
            <span className="hidden sm:inline">Export</span>
          </button>

          <button
            onClick={onClearLogs}
            className="p-1.5 rounded-lg text-xs font-medium bg-slate-900 hover:bg-red-950/50 hover:text-red-400 border border-slate-800 text-slate-400 transition"
            title="Clear current log buffer"
          >
            <Trash2 className="w-3.5 h-3.5" />
          </button>

          {/* AI Engine Status Badge */}
          <div
            className={`hidden xl:flex items-center gap-1.5 px-2.5 py-1 rounded border text-[11px] font-mono ${
              aiEngineStatus.ai_available
                ? 'bg-purple-950/60 border-purple-800/60 text-purple-300'
                : 'bg-slate-900 border-slate-800 text-slate-400'
            }`}
          >
            <Sparkles className="w-3.5 h-3.5 text-purple-400" />
            <span>{aiEngineStatus.ai_available ? 'Gemini 3.8 Flash' : 'Rule Engine Active'}</span>
          </div>
        </div>
      </div>
    </header>
  );
};
