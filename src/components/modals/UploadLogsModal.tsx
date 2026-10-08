/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { SecurityEvent } from '../../types/security';
import { detectionEngine } from '../../services/detectionEngine';
import { X, Upload, FileText, CheckCircle, AlertCircle } from 'lucide-react';

interface UploadLogsModalProps {
  onClose: () => void;
  onIngest: (newEvents: SecurityEvent[]) => void;
  existingEvents: SecurityEvent[];
}

export const UploadLogsModal: React.FC<UploadLogsModalProps> = ({
  onClose,
  onIngest,
  existingEvents,
}) => {
  const [fileType, setFileType] = useState<'JSON' | 'CSV'>('JSON');
  const [rawText, setRawText] = useState('');
  const [statusMsg, setStatusMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  const sampleJSON = `[
  {
    "event_id": "EVT-9001",
    "timestamp": "${new Date().toISOString()}",
    "source_ip": "194.26.29.112",
    "destination_ip": "10.0.1.50",
    "source_port": 51234,
    "destination_port": 443,
    "protocol": "HTTPS",
    "device": "waf-dmz-ingress",
    "device_type": "Web Server",
    "event_type": "WAF Exploit Alert",
    "action": "ALERT",
    "username": "unknown",
    "asset": "dmz-ecommerce-web",
    "message": "Detected directory traversal attempt /../../etc/passwd",
    "raw_payload": "GET /static/download?file=../../../../etc/passwd HTTP/1.1",
    "bytes_transferred": 1280
  }
]`;

  const sampleCSV = `event_id,timestamp,source_ip,destination_ip,source_port,destination_port,protocol,device,device_type,action,asset,message,raw_payload
EVT-9002,${new Date().toISOString()},185.220.101.99,10.0.1.10,48192,22,SSH,dc-auth-01,Authentication,FAILURE,jump-bastion-01,Repeated password failure for admin,Failed password for user admin port 48192
EVT-9003,${new Date().toISOString()},185.220.101.99,10.0.1.10,48198,22,SSH,dc-auth-01,Authentication,SUCCESS,jump-bastion-01,Accepted password for admin after 2 failures,Accepted password for admin`;

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target?.result as string;
      setRawText(content);
      if (file.name.endsWith('.csv')) {
        setFileType('CSV');
      } else {
        setFileType('JSON');
      }
    };
    reader.readAsText(file);
  };

  const parseAndIngest = () => {
    setStatusMsg(null);
    try {
      let parsedEvents: Partial<SecurityEvent>[] = [];

      if (fileType === 'JSON') {
        const data = JSON.parse(rawText);
        parsedEvents = Array.isArray(data) ? data : [data];
      } else {
        // CSV parsing
        const lines = rawText.split('\n').filter((l) => l.trim().length > 0);
        if (lines.length < 2) {
          throw new Error('CSV must have a header line and at least one data row.');
        }

        const headers = lines[0].split(',').map((h) => h.trim().toLowerCase());
        for (let i = 1; i < lines.length; i++) {
          const cols = lines[i].split(',').map((c) => c.trim());
          const obj: any = {};
          headers.forEach((h, idx) => {
            obj[h] = cols[idx] || '';
          });
          parsedEvents.push(obj);
        }
      }

      if (parsedEvents.length === 0) {
        throw new Error('No valid event records identified.');
      }

      // Correlate through deterministic detection engine
      const fullyProcessed: SecurityEvent[] = [];
      const runningContext = [...existingEvents];

      for (const raw of parsedEvents) {
        const evt: SecurityEvent = {
          event_id: raw.event_id || `EVT-${Math.floor(1000 + Math.random() * 9000)}`,
          timestamp: raw.timestamp || new Date().toISOString(),
          source_ip: raw.source_ip || '192.168.1.100',
          destination_ip: raw.destination_ip || '10.0.0.1',
          source_port: Number(raw.source_port) || 49152,
          destination_port: Number(raw.destination_port) || 80,
          protocol: (raw.protocol as any) || 'TCP',
          device: raw.device || 'external-sensor',
          device_type: (raw.device_type as any) || 'Firewall',
          event_type: raw.event_type || 'Custom Ingestion',
          action: (raw.action as any) || 'ALLOW',
          username: raw.username || '-',
          asset: raw.asset || 'corp-network',
          message: raw.message || 'Custom log ingested',
          severity: raw.severity || 'INFORMATIONAL',
          risk_score: Number(raw.risk_score) || 10,
          detection_method: 'RULE',
          status: 'OPEN',
          threat_category: raw.threat_category || 'Normal Activity',
          raw_payload: raw.raw_payload || raw.message || '',
          bytes_transferred: Number(raw.bytes_transferred) || 0,
          packets: Number(raw.packets) || 1,
        };

        const evaluated = detectionEngine.processEvent(evt, runningContext);
        fullyProcessed.push(evaluated);
        runningContext.push(evaluated);
      }

      onIngest(fullyProcessed);
      setStatusMsg({
        type: 'success',
        text: `Successfully ingested and rule-correlated ${fullyProcessed.length} security events!`,
      });

      setTimeout(() => {
        onClose();
      }, 1200);
    } catch (err: any) {
      setStatusMsg({
        type: 'error',
        text: `Ingestion failed: ${err.message || 'Syntax error in log payload.'}`,
      });
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4 overflow-y-auto">
      <div className="relative w-full max-w-3xl bg-slate-900 border border-slate-800 rounded-xl shadow-2xl text-slate-100 overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-slate-950/80">
          <div className="flex items-center gap-3">
            <span className="p-2 rounded-lg bg-cyan-950/80 text-cyan-400">
              <Upload className="w-5 h-5" />
            </span>
            <div>
              <h3 className="text-base font-semibold text-white">Ingest External Security Logs</h3>
              <p className="text-xs text-slate-400">
                Upload or paste JSON / CSV telemetry. Deterministic rules correlate automatically on intake.
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6 space-y-4 text-xs">
          {/* Format Selector & File Upload */}
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <span className="text-slate-400 font-semibold">Log Format:</span>
              <button
                type="button"
                onClick={() => setFileType('JSON')}
                className={`px-3 py-1 rounded font-medium transition ${
                  fileType === 'JSON' ? 'bg-cyan-600 text-white' : 'bg-slate-800 text-slate-400 hover:text-white'
                }`}
              >
                JSON Array
              </button>
              <button
                type="button"
                onClick={() => setFileType('CSV')}
                className={`px-3 py-1 rounded font-medium transition ${
                  fileType === 'CSV' ? 'bg-cyan-600 text-white' : 'bg-slate-800 text-slate-400 hover:text-white'
                }`}
              >
                CSV
              </button>
            </div>

            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => setRawText(fileType === 'JSON' ? sampleJSON : sampleCSV)}
                className="text-cyan-400 hover:underline"
              >
                Load Template
              </button>

              <label className="cursor-pointer px-3 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 flex items-center gap-1.5 border border-slate-700 transition">
                <FileText className="w-3.5 h-3.5" />
                Select File
                <input
                  type="file"
                  accept=".json,.csv,.txt,.log"
                  onChange={handleFileUpload}
                  className="hidden"
                />
              </label>
            </div>
          </div>

          {/* Textarea */}
          <div>
            <label className="block text-slate-300 font-semibold mb-1">
              Log Payload Data ({fileType}):
            </label>
            <textarea
              rows={12}
              value={rawText}
              onChange={(e) => setRawText(e.target.value)}
              placeholder={`Paste raw ${fileType} events here or select a file...`}
              className="w-full p-3 rounded-lg bg-slate-950 border border-slate-800 font-mono text-xs text-cyan-300/90 focus:outline-none focus:border-cyan-500 leading-relaxed"
            />
          </div>

          {/* Notification */}
          {statusMsg && (
            <div
              className={`p-3 rounded-lg flex items-center gap-2 text-xs ${
                statusMsg.type === 'success'
                  ? 'bg-emerald-950/80 border border-emerald-800 text-emerald-300'
                  : 'bg-red-950/80 border border-red-800 text-red-300'
              }`}
            >
              {statusMsg.type === 'success' ? (
                <CheckCircle className="w-4 h-4 shrink-0" />
              ) : (
                <AlertCircle className="w-4 h-4 shrink-0" />
              )}
              <span>{statusMsg.text}</span>
            </div>
          )}

          {/* Actions */}
          <div className="flex items-center justify-end gap-3 pt-3 border-t border-slate-800">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={parseAndIngest}
              disabled={!rawText.trim()}
              className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white font-semibold flex items-center gap-1.5 transition shadow"
            >
              <Upload className="w-4 h-4" />
              Parse & Run Detection Engine
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
