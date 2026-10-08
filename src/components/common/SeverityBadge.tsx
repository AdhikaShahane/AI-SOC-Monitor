/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { DetectionMethod, SeverityLevel, IncidentStatus } from '../../types/security';

export const SeverityBadge: React.FC<{ severity: SeverityLevel; className?: string }> = ({
  severity,
  className = '',
}) => {
  switch (severity) {
    case 'CRITICAL':
      return (
        <span
          className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-semibold tracking-wide bg-red-950/80 text-red-400 border border-red-800/80 ${className}`}
        >
          <span className="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse" />
          CRITICAL
        </span>
      );
    case 'HIGH':
      return (
        <span
          className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-semibold tracking-wide bg-amber-950/70 text-amber-400 border border-amber-800/70 ${className}`}
        >
          <span className="w-1.5 h-1.5 rounded-full bg-amber-500" />
          HIGH
        </span>
      );
    case 'MEDIUM':
      return (
        <span
          className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-medium tracking-wide bg-yellow-950/50 text-yellow-300 border border-yellow-800/60 ${className}`}
        >
          <span className="w-1.5 h-1.5 rounded-full bg-yellow-400" />
          MEDIUM
        </span>
      );
    case 'LOW':
      return (
        <span
          className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-medium tracking-wide bg-sky-950/50 text-sky-300 border border-sky-800/60 ${className}`}
        >
          <span className="w-1.5 h-1.5 rounded-full bg-sky-400" />
          LOW
        </span>
      );
    case 'INFORMATIONAL':
    default:
      return (
        <span
          className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-medium tracking-wide bg-slate-900 text-slate-400 border border-slate-800 ${className}`}
        >
          <span className="w-1.5 h-1.5 rounded-full bg-slate-500" />
          INFO
        </span>
      );
  }
};

export const DetectionMethodBadge: React.FC<{ method: DetectionMethod; className?: string }> = ({
  method,
  className = '',
}) => {
  switch (method) {
    case 'RULE':
      return (
        <span
          title="Detected by deterministic security correlation rule"
          className={`inline-flex items-center px-1.5 py-0.5 rounded text-[11px] font-mono font-semibold tracking-wider bg-emerald-950/70 text-emerald-400 border border-emerald-800/70 ${className}`}
        >
          RULE
        </span>
      );
    case 'AI':
      return (
        <span
          title="Assessed by Gemini AI Security Analyst"
          className={`inline-flex items-center px-1.5 py-0.5 rounded text-[11px] font-mono font-semibold tracking-wider bg-purple-950/70 text-purple-300 border border-purple-700/70 ${className}`}
        >
          AI
        </span>
      );
    case 'RULE_AND_AI':
      return (
        <span
          title="Corroborated by both Deterministic Rule and Gemini AI"
          className={`inline-flex items-center px-1.5 py-0.5 rounded text-[11px] font-mono font-semibold tracking-wider bg-gradient-to-r from-emerald-950 to-purple-950 text-cyan-300 border border-cyan-800/60 ${className}`}
        >
          RULE + AI
        </span>
      );
    default:
      return null;
  }
};

export const IncidentStatusBadge: React.FC<{ status: IncidentStatus }> = ({ status }) => {
  switch (status) {
    case 'New':
      return (
        <span className="px-2 py-0.5 rounded text-xs font-semibold bg-rose-950/80 text-rose-300 border border-rose-800">
          New
        </span>
      );
    case 'Investigating':
      return (
        <span className="px-2 py-0.5 rounded text-xs font-semibold bg-amber-950/80 text-amber-300 border border-amber-800">
          Investigating
        </span>
      );
    case 'Contained':
      return (
        <span className="px-2 py-0.5 rounded text-xs font-semibold bg-blue-950/80 text-blue-300 border border-blue-800">
          Contained
        </span>
      );
    case 'Resolved':
      return (
        <span className="px-2 py-0.5 rounded text-xs font-semibold bg-emerald-950/80 text-emerald-300 border border-emerald-800">
          Resolved
        </span>
      );
    case 'False Positive':
      return (
        <span className="px-2 py-0.5 rounded text-xs font-semibold bg-slate-900 text-slate-400 border border-slate-800 line-through">
          False Positive
        </span>
      );
  }
};
