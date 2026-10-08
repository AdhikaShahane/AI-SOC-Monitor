/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { Incident, SecurityEvent, SOCMetrics } from '../../types/security';
import { FileText, Sparkles, Download, Copy, Printer, CheckCircle, ShieldCheck } from 'lucide-react';
import { generateSOCReport } from '../../services/aiAnalystClient';

interface ReportsViewProps {
  metrics: SOCMetrics;
  incidents: Incident[];
  events: SecurityEvent[];
}

export const ReportsView: React.FC<ReportsViewProps> = ({
  metrics,
  incidents,
  events,
}) => {
  const [reportType, setReportType] = useState<'SHIFT_HANDOVER' | 'EXECUTIVE_SUMMARY' | 'INCIDENT_POSTMORTEM' | 'COMPLIANCE_NIST'>('SHIFT_HANDOVER');
  const [isGenerating, setIsGenerating] = useState(false);
  const [generatedReport, setGeneratedReport] = useState<string>('');
  const [copied, setCopied] = useState(false);

  const handleGenerate = async () => {
    setIsGenerating(true);
    try {
      const typeLabel =
        reportType === 'SHIFT_HANDOVER'
          ? 'SOC Shift Handover Report'
          : reportType === 'EXECUTIVE_SUMMARY'
          ? 'CISO Executive Cybersecurity Briefing'
          : reportType === 'INCIDENT_POSTMORTEM'
          ? 'Comprehensive Incident Response Post-Mortem'
          : 'NIST CSF & ISO 27001 Compliance Audit Report';

      const report = await generateSOCReport(typeLabel, metrics, incidents, events);
      setGeneratedReport(report);
    } catch (err) {
      console.error(err);
    } finally {
      setIsGenerating(false);
    }
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(generatedReport);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    const blob = new Blob([generatedReport], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `soc-report-${reportType.toLowerCase()}-${new Date().toISOString().slice(0, 10)}.md`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  const handlePrint = () => {
    window.print();
  };

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 shadow-sm flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-base font-semibold text-white flex items-center gap-2">
            <FileText className="w-5 h-5 text-cyan-400" />
            SOC Reports & Incident Briefings
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Automated intelligence reports for shift handovers, executive leadership, and compliance audits
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleGenerate}
            disabled={isGenerating}
            className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white font-semibold text-xs flex items-center gap-1.5 transition shadow"
          >
            <Sparkles className="w-4 h-4" />
            {isGenerating ? 'Synthesizing Report...' : 'Generate Report'}
          </button>
        </div>
      </div>

      {/* Report Template Selector */}
      <div className="grid grid-cols-1 sm:grid-cols-4 gap-3">
        {[
          {
            id: 'SHIFT_HANDOVER',
            title: 'SOC Shift Handover',
            desc: 'Daily briefing for incoming Tier-1/2/3 shift leads with active incidents and metrics.',
          },
          {
            id: 'EXECUTIVE_SUMMARY',
            title: 'Executive Threat Briefing',
            desc: 'High-level risk narrative designed for CISO and security directors.',
          },
          {
            id: 'INCIDENT_POSTMORTEM',
            title: 'Incident Post-Mortem',
            desc: 'Forensic attack chain reconstruction, root-cause analysis, and mitigation steps.',
          },
          {
            id: 'COMPLIANCE_NIST',
            title: 'NIST CSF & ISO Mapping',
            desc: 'Audit alignment for Identify, Protect, Detect, Respond, and Recover tiers.',
          },
        ].map((tmpl) => (
          <div
            key={tmpl.id}
            onClick={() => setReportType(tmpl.id as any)}
            className={`p-3.5 rounded-xl border cursor-pointer transition text-xs space-y-1.5 ${
              reportType === tmpl.id
                ? 'bg-cyan-950/40 border-cyan-500 text-white shadow-sm'
                : 'bg-slate-900 border-slate-800 text-slate-400 hover:border-slate-700'
            }`}
          >
            <h4 className="font-semibold text-slate-200">{tmpl.title}</h4>
            <p className="text-[11px] text-slate-400 leading-relaxed">{tmpl.desc}</p>
          </div>
        ))}
      </div>

      {/* Generated Report Viewer */}
      <div className="p-6 rounded-xl bg-slate-900 border border-slate-800 shadow-sm space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-slate-800">
          <div>
            <h3 className="text-sm font-semibold text-white">Generated SOC Intelligence Output</h3>
            <span className="text-xs text-slate-500 font-mono">
              Status: {generatedReport ? 'Ready for distribution' : 'Awaiting compilation'}
            </span>
          </div>

          {generatedReport && (
            <div className="flex items-center gap-2">
              <button
                onClick={handleCopy}
                className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs flex items-center gap-1.5 transition"
              >
                <Copy className="w-3.5 h-3.5" />
                {copied ? 'Copied!' : 'Copy'}
              </button>
              <button
                onClick={handleDownload}
                className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs flex items-center gap-1.5 transition"
              >
                <Download className="w-3.5 h-3.5" />
                Download MD
              </button>
              <button
                onClick={handlePrint}
                className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs flex items-center gap-1.5 transition"
              >
                <Printer className="w-3.5 h-3.5" />
                Print / Save PDF
              </button>
            </div>
          )}
        </div>

        {generatedReport ? (
          <div className="p-6 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 text-xs leading-relaxed font-sans whitespace-pre-wrap select-all max-h-[600px] overflow-y-auto">
            {generatedReport}
          </div>
        ) : (
          <div className="py-16 text-center text-slate-500 space-y-2">
            <FileText className="w-8 h-8 text-slate-600 mx-auto" />
            <p className="text-xs">
              Select a report template above and click &quot;Generate Report&quot; to compile telemetry.
            </p>
          </div>
        )}
      </div>
    </div>
  );
};
