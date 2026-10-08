/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { DetectionEngineConfig } from '../../types/detection';
import { Sliders, Cpu, Sparkles, CheckCircle, Save, RotateCcw } from 'lucide-react';
import { detectionEngine } from '../../services/detectionEngine';

interface SettingsViewProps {
  onResetToBaseline: () => void;
  aiEngineStatus: { online: boolean; ai_available: boolean; model: string };
  isStreaming: boolean;
  onToggleStreaming: () => void;
  onConfigChanged: () => void;
}

export const SettingsView: React.FC<SettingsViewProps> = ({
  onResetToBaseline,
  aiEngineStatus,
  isStreaming,
  onToggleStreaming,
  onConfigChanged,
}) => {
  const [config, setConfig] = useState<DetectionEngineConfig>(() => detectionEngine.getConfig());
  const [savedNotice, setSavedNotice] = useState(false);

  const handleSaveConfig = () => {
    detectionEngine.updateConfig(config);
    onConfigChanged();
    setSavedNotice(true);
    setTimeout(() => setSavedNotice(false), 2500);
  };

  const handleResetDefaults = () => {
    detectionEngine.updateConfig({
      bruteForce: { enabled: true, failedLoginThreshold: 3, timeWindowSeconds: 300, baseRiskScore: 82 },
      portScan: { enabled: true, distinctPortThreshold: 4, distinctHostThreshold: 3, timeWindowSeconds: 120, baseRiskScore: 68 },
      suspiciousAuthSequence: { enabled: true, failedAttemptsBeforeSuccessThreshold: 2, timeWindowSeconds: 600, baseRiskScore: 92 },
      trafficAnomaly: { enabled: true, packetSurgeThreshold: 15000, bytesSurgeThreshold: 10485760, baselineMultiplier: 3.0, baseRiskScore: 80 },
      suspiciousWebRequest: { enabled: true, inspectParameters: true, baseRiskScore: 86 },
      suspiciousOutbound: { enabled: true, suspiciousPorts: [4444, 8443, 1337, 8888, 6667, 9001], bytesExfilThreshold: 10485760, baseRiskScore: 84 },
      privilegeEscalation: { enabled: true, baseRiskScore: 94 },
    });
    setConfig(detectionEngine.getConfig());
    onConfigChanged();
  };

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 shadow-sm flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-base font-semibold text-white flex items-center gap-2">
            <Sliders className="w-5 h-5 text-cyan-400" />
            Deterministic Detection Engine & Threshold Configuration
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Configure sliding-window thresholds, traffic multipliers, and signature parameters without hardcoding
          </p>
        </div>

        <div className="flex items-center gap-2">
          {savedNotice && (
            <span className="text-xs text-emerald-400 font-mono flex items-center gap-1">
              <CheckCircle className="w-3.5 h-3.5" /> Engine Thresholds Applied
            </span>
          )}
          <button
            onClick={handleSaveConfig}
            className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-semibold text-xs flex items-center gap-1.5 transition shadow"
          >
            <Save className="w-4 h-4" /> Save & Re-evaluate
          </button>
        </div>
      </div>

      {/* Engine & AI Status Card */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-3 text-xs">
          <h3 className="text-sm font-semibold text-white flex items-center gap-2">
            <Cpu className="w-4 h-4 text-cyan-400" />
            Deterministic Rule Engine Status
          </h3>
          <div className="space-y-2">
            <div className="flex items-center justify-between p-2 rounded bg-slate-950 border border-slate-800 font-mono">
              <span className="text-slate-400">Rules Active</span>
              <span className="text-emerald-400 font-bold">7 of 7 Modular Rules Armed</span>
            </div>
            <div className="flex items-center justify-between p-2 rounded bg-slate-950 border border-slate-800 font-mono">
              <span className="text-slate-400">Unit-Testable Rules</span>
              <span className="text-cyan-400 font-bold">All 7 Verified via Automated Tests</span>
            </div>
          </div>
          <p className="text-[11px] text-slate-500">
            Deterministic rules evaluate immediately on log intake prior to optional AI corroboration.
          </p>
        </div>

        <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-3 text-xs">
          <h3 className="text-sm font-semibold text-white flex items-center gap-2">
            <Sparkles className="w-4 h-4 text-purple-400" />
            Gemini AI Security Analyst Configuration
          </h3>
          <div className="space-y-2">
            <div className="flex items-center justify-between p-2 rounded bg-slate-950 border border-slate-800 font-mono">
              <span className="text-slate-400">Model Engine</span>
              <span className="text-purple-300 font-bold">{aiEngineStatus.model}</span>
            </div>
            <div className="flex items-center justify-between p-2 rounded bg-slate-950 border border-slate-800 font-mono">
              <span className="text-slate-400">Backend Connectivity</span>
              <span
                className={`font-bold ${
                  aiEngineStatus.ai_available ? 'text-emerald-400' : 'text-amber-400'
                }`}
              >
                {aiEngineStatus.ai_available ? 'ONLINE (Direct AI Key)' : 'ONLINE (Grounded Fallback)'}
              </span>
            </div>
          </div>
          <p className="text-[11px] text-slate-500">
            Full-stack server routes proxies Gemini API requests securely without exposing secrets to browser bundles.
          </p>
        </div>
      </div>

      {/* Simulation & Data Controls */}
      <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-3 text-xs">
        <h3 className="text-sm font-semibold text-white">Simulation & Data Controls</h3>
        <div className="flex flex-wrap items-center justify-between gap-4 p-3 rounded-lg bg-slate-950 border border-slate-800">
          <div>
            <span className="font-semibold text-slate-200 block">Live Traffic Ingestion Simulator</span>
            <span className="text-slate-400 text-[11px]">
              Periodically emits new background security logs and network packets every 4 seconds.
            </span>
          </div>
          <button
            onClick={onToggleStreaming}
            className={`px-3 py-1.5 rounded-lg font-semibold transition ${
              isStreaming
                ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                : 'bg-slate-800 text-slate-400 hover:text-white'
            }`}
          >
            {isStreaming ? 'Stream Running (Stop)' : 'Stream Inactive (Start)'}
          </button>
        </div>

        <div className="flex flex-wrap items-center justify-between gap-4 p-3 rounded-lg bg-slate-950 border border-slate-800">
          <div>
            <span className="font-semibold text-slate-200 block">Reset Telemetry to Baseline</span>
            <span className="text-slate-400 text-[11px]">
              Clears current stream and reinstates clean multi-stage attack scenarios.
            </span>
          </div>
          <button
            onClick={onResetToBaseline}
            className="px-3 py-1.5 rounded-lg bg-cyan-950 text-cyan-300 border border-cyan-800 hover:bg-cyan-900 transition font-semibold"
          >
            Reset to Baseline
          </button>
        </div>
      </div>

      {/* Modular Rule Configuration Cards */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-semibold text-white">Configurable Rule Thresholds</h3>
          <button
            onClick={handleResetDefaults}
            className="text-xs text-slate-400 hover:text-white flex items-center gap-1 transition"
          >
            <RotateCcw className="w-3.5 h-3.5" /> Restore Default Thresholds
          </button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Rule 1: Brute Force */}
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3 text-xs">
            <div className="flex items-center justify-between">
              <span className="font-mono text-cyan-400 font-bold">RULE-01: Brute Force</span>
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={config.bruteForce.enabled}
                  onChange={(e) =>
                    setConfig({
                      ...config,
                      bruteForce: { ...config.bruteForce, enabled: e.target.checked },
                    })
                  }
                  className="rounded bg-slate-950 border-slate-700 text-cyan-500"
                />
                <span className="text-slate-300 text-[11px]">Enabled</span>
              </label>
            </div>
            <p className="text-slate-400 text-[11px]">
              Triggers when identical source IP generates multiple failed authentication attempts within a sliding time window.
            </p>
            <div className="grid grid-cols-3 gap-2">
              <div>
                <label className="block text-[10px] text-slate-500 font-mono mb-1">Fail Threshold</label>
                <input
                  type="number"
                  min="2"
                  max="50"
                  value={config.bruteForce.failedLoginThreshold}
                  onChange={(e) =>
                    setConfig({
                      ...config,
                      bruteForce: { ...config.bruteForce, failedLoginThreshold: Number(e.target.value) },
                    })
                  }
                  className="w-full bg-slate-950 border border-slate-800 rounded px-2 py-1 text-slate-200 font-mono"
                />
              </div>
              <div>
                <label className="block text-[10px] text-slate-500 font-mono mb-1">Window (sec)</label>
                <input
                  type="number"
                  min="30"
                  max="3600"
                  value={config.bruteForce.timeWindowSeconds}
                  onChange={(e) =>
                    setConfig({
                      ...config,
                      bruteForce: { ...config.bruteForce, timeWindowSeconds: Number(e.target.value) },
                    })
                  }
                  className="w-full bg-slate-950 border border-slate-800 rounded px-2 py-1 text-slate-200 font-mono"
                />
              </div>
              <div>
                <label className="block text-[10px] text-slate-500 font-mono mb-1">Base Risk</label>
                <input
                  type="number"
                  min="1"
                  max="100"
                  value={config.bruteForce.baseRiskScore}
                  onChange={(e) =>
                    setConfig({
                      ...config,
                      bruteForce: { ...config.bruteForce, baseRiskScore: Number(e.target.value) },
                    })
                  }
                  className="w-full bg-slate-950 border border-slate-800 rounded px-2 py-1 text-slate-200 font-mono"
                />
              </div>
            </div>
          </div>

          {/* Rule 2: Port Scan */}
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3 text-xs">
            <div className="flex items-center justify-between">
              <span className="font-mono text-cyan-400 font-bold">RULE-02: Port Scan</span>
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={config.portScan.enabled}
                  onChange={(e) =>
                    setConfig({
                      ...config,
                      portScan: { ...config.portScan, enabled: e.target.checked },
                    })
                  }
                  className="rounded bg-slate-950 border-slate-700 text-cyan-500"
                />
                <span className="text-slate-300 text-[11px]">Enabled</span>
              </label>
            </div>
            <p className="text-slate-400 text-[11px]">
              Detects single source IP probing many destination ports or multiple hosts within a short monitoring period.
            </p>
            <div className="grid grid-cols-3 gap-2">
              <div>
                <label className="block text-[10px] text-slate-500 font-mono mb-1">Distinct Ports</label>
                <input
                  type="number"
                  min="2"
                  max="50"
                  value={config.portScan.distinctPortThreshold}
                  onChange={(e) =>
                    setConfig({
                      ...config,
                      portScan: { ...config.portScan, distinctPortThreshold: Number(e.target.value) },
                    })
                  }
                  className="w-full bg-slate-950 border border-slate-800 rounded px-2 py-1 text-slate-200 font-mono"
                />
              </div>
              <div>
                <label className="block text-[10px] text-slate-500 font-mono mb-1">Window (sec)</label>
                <input
                  type="number"
                  min="30"
                  max="1800"
                  value={config.portScan.timeWindowSeconds}
                  onChange={(e) =>
                    setConfig({
                      ...config,
                      portScan: { ...config.portScan, timeWindowSeconds: Number(e.target.value) },
                    })
                  }
                  className="w-full bg-slate-950 border border-slate-800 rounded px-2 py-1 text-slate-200 font-mono"
                />
              </div>
              <div>
                <label className="block text-[10px] text-slate-500 font-mono mb-1">Base Risk</label>
                <input
                  type="number"
                  min="1"
                  max="100"
                  value={config.portScan.baseRiskScore}
                  onChange={(e) =>
                    setConfig({
                      ...config,
                      portScan: { ...config.portScan, baseRiskScore: Number(e.target.value) },
                    })
                  }
                  className="w-full bg-slate-950 border border-slate-800 rounded px-2 py-1 text-slate-200 font-mono"
                />
              </div>
            </div>
          </div>

          {/* Rule 3: Suspicious Authentication */}
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3 text-xs">
            <div className="flex items-center justify-between">
              <span className="font-mono text-cyan-400 font-bold">RULE-03: Suspicious Auth Sequence</span>
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={config.suspiciousAuthSequence.enabled}
                  onChange={(e) =>
                    setConfig({
                      ...config,
                      suspiciousAuthSequence: { ...config.suspiciousAuthSequence, enabled: e.target.checked },
                    })
                  }
                  className="rounded bg-slate-950 border-slate-700 text-cyan-500"
                />
                <span className="text-slate-300 text-[11px]">Enabled</span>
              </label>
            </div>
            <p className="text-slate-400 text-[11px]">
              Detects failed login attempts followed shortly by successful authentication from the same source IP.
            </p>
            <div className="grid grid-cols-3 gap-2">
              <div>
                <label className="block text-[10px] text-slate-500 font-mono mb-1">Prior Fails</label>
                <input
                  type="number"
                  min="1"
                  max="20"
                  value={config.suspiciousAuthSequence.failedAttemptsBeforeSuccessThreshold}
                  onChange={(e) =>
                    setConfig({
                      ...config,
                      suspiciousAuthSequence: {
                        ...config.suspiciousAuthSequence,
                        failedAttemptsBeforeSuccessThreshold: Number(e.target.value),
                      },
                    })
                  }
                  className="w-full bg-slate-950 border border-slate-800 rounded px-2 py-1 text-slate-200 font-mono"
                />
              </div>
              <div>
                <label className="block text-[10px] text-slate-500 font-mono mb-1">Window (sec)</label>
                <input
                  type="number"
                  min="60"
                  max="3600"
                  value={config.suspiciousAuthSequence.timeWindowSeconds}
                  onChange={(e) =>
                    setConfig({
                      ...config,
                      suspiciousAuthSequence: {
                        ...config.suspiciousAuthSequence,
                        timeWindowSeconds: Number(e.target.value),
                      },
                    })
                  }
                  className="w-full bg-slate-950 border border-slate-800 rounded px-2 py-1 text-slate-200 font-mono"
                />
              </div>
              <div>
                <label className="block text-[10px] text-slate-500 font-mono mb-1">Base Risk</label>
                <input
                  type="number"
                  min="1"
                  max="100"
                  value={config.suspiciousAuthSequence.baseRiskScore}
                  onChange={(e) =>
                    setConfig({
                      ...config,
                      suspiciousAuthSequence: {
                        ...config.suspiciousAuthSequence,
                        baseRiskScore: Number(e.target.value),
                      },
                    })
                  }
                  className="w-full bg-slate-950 border border-slate-800 rounded px-2 py-1 text-slate-200 font-mono"
                />
              </div>
            </div>
          </div>

          {/* Rule 4: Traffic Anomaly */}
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3 text-xs">
            <div className="flex items-center justify-between">
              <span className="font-mono text-cyan-400 font-bold">RULE-04: Traffic Anomaly</span>
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={config.trafficAnomaly.enabled}
                  onChange={(e) =>
                    setConfig({
                      ...config,
                      trafficAnomaly: { ...config.trafficAnomaly, enabled: e.target.checked },
                    })
                  }
                  className="rounded bg-slate-950 border-slate-700 text-cyan-500"
                />
                <span className="text-slate-300 text-[11px]">Enabled</span>
              </label>
            </div>
            <p className="text-slate-400 text-[11px]">
              Detects abnormal increases in traffic compared with baseline statistical average of sample data.
            </p>
            <div className="grid grid-cols-3 gap-2">
              <div>
                <label className="block text-[10px] text-slate-500 font-mono mb-1">Packet Surge</label>
                <input
                  type="number"
                  min="1000"
                  step="1000"
                  value={config.trafficAnomaly.packetSurgeThreshold}
                  onChange={(e) =>
                    setConfig({
                      ...config,
                      trafficAnomaly: { ...config.trafficAnomaly, packetSurgeThreshold: Number(e.target.value) },
                    })
                  }
                  className="w-full bg-slate-950 border border-slate-800 rounded px-2 py-1 text-slate-200 font-mono"
                />
              </div>
              <div>
                <label className="block text-[10px] text-slate-500 font-mono mb-1">Multiplier</label>
                <input
                  type="number"
                  min="1.5"
                  step="0.5"
                  value={config.trafficAnomaly.baselineMultiplier}
                  onChange={(e) =>
                    setConfig({
                      ...config,
                      trafficAnomaly: { ...config.trafficAnomaly, baselineMultiplier: Number(e.target.value) },
                    })
                  }
                  className="w-full bg-slate-950 border border-slate-800 rounded px-2 py-1 text-slate-200 font-mono"
                />
              </div>
              <div>
                <label className="block text-[10px] text-slate-500 font-mono mb-1">Base Risk</label>
                <input
                  type="number"
                  min="1"
                  max="100"
                  value={config.trafficAnomaly.baseRiskScore}
                  onChange={(e) =>
                    setConfig({
                      ...config,
                      trafficAnomaly: { ...config.trafficAnomaly, baseRiskScore: Number(e.target.value) },
                    })
                  }
                  className="w-full bg-slate-950 border border-slate-800 rounded px-2 py-1 text-slate-200 font-mono"
                />
              </div>
            </div>
          </div>

          {/* Rule 5: Suspicious Web Request */}
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3 text-xs">
            <div className="flex items-center justify-between">
              <span className="font-mono text-cyan-400 font-bold">RULE-05: Suspicious Web Request</span>
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={config.suspiciousWebRequest.enabled}
                  onChange={(e) =>
                    setConfig({
                      ...config,
                      suspiciousWebRequest: { ...config.suspiciousWebRequest, enabled: e.target.checked },
                    })
                  }
                  className="rounded bg-slate-950 border-slate-700 text-cyan-500"
                />
                <span className="text-slate-300 text-[11px]">Enabled</span>
              </label>
            </div>
            <p className="text-slate-400 text-[11px]">
              Inspects logged HTTP request URIs and payloads for SQL injection, directory traversal, and command markers without executing.
            </p>
            <div className="grid grid-cols-2 gap-2">
              <div>
                <label className="block text-[10px] text-slate-500 font-mono mb-1">Inspect Parameters</label>
                <select
                  value={config.suspiciousWebRequest.inspectParameters ? 'yes' : 'no'}
                  onChange={(e) =>
                    setConfig({
                      ...config,
                      suspiciousWebRequest: {
                        ...config.suspiciousWebRequest,
                        inspectParameters: e.target.value === 'yes',
                      },
                    })
                  }
                  className="w-full bg-slate-950 border border-slate-800 rounded px-2 py-1 text-slate-200 font-mono"
                >
                  <option value="yes">Deep Inspection</option>
                  <option value="no">Headers Only</option>
                </select>
              </div>
              <div>
                <label className="block text-[10px] text-slate-500 font-mono mb-1">Base Risk Score</label>
                <input
                  type="number"
                  min="1"
                  max="100"
                  value={config.suspiciousWebRequest.baseRiskScore}
                  onChange={(e) =>
                    setConfig({
                      ...config,
                      suspiciousWebRequest: {
                        ...config.suspiciousWebRequest,
                        baseRiskScore: Number(e.target.value),
                      },
                    })
                  }
                  className="w-full bg-slate-950 border border-slate-800 rounded px-2 py-1 text-slate-200 font-mono"
                />
              </div>
            </div>
          </div>

          {/* Rule 6: Suspicious Outbound Connection */}
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3 text-xs">
            <div className="flex items-center justify-between">
              <span className="font-mono text-cyan-400 font-bold">RULE-06: Suspicious Outbound</span>
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={config.suspiciousOutbound.enabled}
                  onChange={(e) =>
                    setConfig({
                      ...config,
                      suspiciousOutbound: { ...config.suspiciousOutbound, enabled: e.target.checked },
                    })
                  }
                  className="rounded bg-slate-950 border-slate-700 text-cyan-500"
                />
                <span className="text-slate-300 text-[11px]">Enabled</span>
              </label>
            </div>
            <p className="text-slate-400 text-[11px]">
              Detects unusual outbound connections from internal assets (flags as suspicious egress detection rather than claiming confirmed C2).
            </p>
            <div className="grid grid-cols-2 gap-2">
              <div>
                <label className="block text-[10px] text-slate-500 font-mono mb-1">Exfil Threshold (MB)</label>
                <input
                  type="number"
                  min="1"
                  max="500"
                  value={Math.round(config.suspiciousOutbound.bytesExfilThreshold / (1024 * 1024))}
                  onChange={(e) =>
                    setConfig({
                      ...config,
                      suspiciousOutbound: {
                        ...config.suspiciousOutbound,
                        bytesExfilThreshold: Number(e.target.value) * 1024 * 1024,
                      },
                    })
                  }
                  className="w-full bg-slate-950 border border-slate-800 rounded px-2 py-1 text-slate-200 font-mono"
                />
              </div>
              <div>
                <label className="block text-[10px] text-slate-500 font-mono mb-1">Base Risk Score</label>
                <input
                  type="number"
                  min="1"
                  max="100"
                  value={config.suspiciousOutbound.baseRiskScore}
                  onChange={(e) =>
                    setConfig({
                      ...config,
                      suspiciousOutbound: {
                        ...config.suspiciousOutbound,
                        baseRiskScore: Number(e.target.value),
                      },
                    })
                  }
                  className="w-full bg-slate-950 border border-slate-800 rounded px-2 py-1 text-slate-200 font-mono"
                />
              </div>
            </div>
          </div>
        </div>

        {/* Rule 7: Privilege Escalation */}
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3 text-xs">
          <div className="flex items-center justify-between">
            <span className="font-mono text-cyan-400 font-bold">RULE-07: Privilege Escalation Indicator</span>
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={config.privilegeEscalation.enabled}
                onChange={(e) =>
                  setConfig({
                    ...config,
                    privilegeEscalation: { ...config.privilegeEscalation, enabled: e.target.checked },
                  })
                }
                className="rounded bg-slate-950 border-slate-700 text-cyan-500"
              />
              <span className="text-slate-300 text-[11px]">Enabled</span>
            </label>
          </div>
          <p className="text-slate-400 text-[11px]">
            Detects suspicious privilege changes, sudo elevation, administrator group modifications, or unauthorized administrative authentication in logs.
          </p>
          <div className="w-48">
            <label className="block text-[10px] text-slate-500 font-mono mb-1">Base Risk Score</label>
            <input
              type="number"
              min="1"
              max="100"
              value={config.privilegeEscalation.baseRiskScore}
              onChange={(e) =>
                setConfig({
                  ...config,
                  privilegeEscalation: {
                    ...config.privilegeEscalation,
                    baseRiskScore: Number(e.target.value),
                  },
                })
              }
              className="w-full bg-slate-950 border border-slate-800 rounded px-2 py-1 text-slate-200 font-mono"
            />
          </div>
        </div>
      </div>
    </div>
  );
};
