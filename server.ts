/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import express from 'express';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import { GoogleGenAI, Type } from '@google/genai';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: '10mb' }));

// Initialize GoogleGenAI SDK server-side
const apiKey = process.env.GEMINI_API_KEY || '';
const hasGeminiKey = Boolean(apiKey && apiKey !== 'MY_GEMINI_API_KEY');

const ai = hasGeminiKey
  ? new GoogleGenAI({
      apiKey,
      httpOptions: {
        headers: {
          'User-Agent': 'aistudio-build',
        },
      },
    })
  : null;

// Health / Status endpoint
app.get('/api/health', (_req, res) => {
  res.json({
    status: 'online',
    timestamp: new Date().toISOString(),
    ai_available: hasGeminiKey,
    model: 'gemini-3.8-flash',
  });
});

// Helper for deterministic fallback if Gemini key is missing or fails
function getDeterministicFallbackAnalysis(event: any) {
  const isSqli = (event.message || '').toLowerCase().includes('union') || (event.raw_payload || '').includes('UNION');
  const isAuth = event.device_type === 'Authentication' && event.action === 'FAILURE';
  const isPriv = (event.message || '').includes('root') || (event.message || '').includes('sudo');

  let cat = event.threat_category || 'Normal Activity';
  let sev = event.severity || 'INFORMATIONAL';
  let risk = event.risk_score || 35;
  let reason = event.detection_reason || 'Standard operational log telemetry';

  const evidence = [
    `Event ID: ${event.event_id}`,
    `Source: ${event.source_ip}:${event.source_port} -> Destination: ${event.destination_ip}:${event.destination_port}`,
    `Asset involved: ${event.asset} (${event.device_type} on ${event.device})`,
    `Protocol: ${event.protocol} | Action: ${event.action}`,
    `Observed message: "${event.message}"`,
  ];

  if (event.raw_payload) {
    evidence.push(`Raw payload recorded: ${event.raw_payload.slice(0, 150)}`);
  }

  const recs = [
    `Verify external source IP (${event.source_ip}) against internal egress/ingress boundary rules.`,
    `Inspect authentication and audit logs on ${event.asset} around timestamp ${event.timestamp}.`,
    `Ensure host endpoint monitoring is active on target asset ${event.asset}.`,
  ];

  if (isSqli) {
    cat = 'SQL Injection Attempt';
    sev = 'HIGH';
    risk = 88;
    recs.unshift('Inspect WAF inspection rules and apply parameterized queries on application endpoint.');
  } else if (isAuth) {
    recs.unshift(`Apply perimeter connection rate limit or temporary IP block on ${event.source_ip}.`);
  } else if (isPriv) {
    cat = 'Privilege Escalation';
    sev = 'CRITICAL';
    risk = 95;
    recs.unshift('Isolate target host from internal network segment and audit active shell sessions.');
  }

  return {
    assessment: `Suspicious activity detected corresponding to ${cat}. Telemetry indicates anomalous pattern requiring analyst triage.`,
    threat_category: cat,
    severity: sev,
    risk_score: risk,
    confidence: 85,
    evidence,
    reasoning_summary: `Severity is assessed as ${sev} (Risk score: ${risk}) based on deterministic detection: ${reason}. Distinguishing evidence from inference: the log confirms ${event.action} on ${event.asset}, whereas attacker intent remains an unverified hypothesis until host investigation completes. Evidence indicates suspicious telemetry, not a confirmed compromise.`,
    recommended_actions: recs,
    false_positive_possibility: sev === 'CRITICAL' ? 'LOW' : 'MEDIUM',
    additional_information_needed: [
      `Host-level process audit and volatile memory dump from asset ${event.asset}.`,
      `Verified external reputation data for source IP ${event.source_ip} (external reputation is not provided in raw logs).`,
      `Prior 24-hour authentication history for associated accounts.`,
    ],
    analyzed_at: new Date().toISOString(),
    model: 'Rule-Corroborator-Heuristic (Deterministic Fallback)',
    status: 'GROUNDED_RULE_HEURISTIC',
  };
}

// Endpoint 1: Analyze Single Event
app.post('/api/ai/analyze-event', async (req, res) => {
  try {
    const { event } = req.body;
    if (!event) {
      return res.status(400).json({ error: 'Missing security event payload' });
    }

    if (!ai) {
      return res.json({
        analysis: getDeterministicFallbackAnalysis(event),
        note: 'Grounded heuristic analysis generated (Gemini API key not configured in environment).',
      });
    }

    const prompt = `Analyze the following single security event captured by a Security Operations Center:
Event Details:
- Event ID: ${event.event_id}
- Timestamp: ${event.timestamp}
- Source IP: ${event.source_ip}:${event.source_port}
- Destination IP: ${event.destination_ip}:${event.destination_port}
- Protocol: ${event.protocol}
- Device: ${event.device} (${event.device_type})
- Event Type: ${event.event_type}
- Action: ${event.action}
- Username: ${event.username}
- Asset: ${event.asset}
- Message: ${event.message}
- Deterministic Detection Reason: ${event.detection_reason || 'None'}
- Raw Payload: ${event.raw_payload || 'N/A'}

Provide a structured, grounded forensic assessment adhering to all compliance rules.`;

    const response = await ai.models.generateContent({
      model: 'gemini-3.8-flash',
      contents: prompt,
      config: {
        systemInstruction: `You are SentinelAI Security Analyst, an elite SOC Tier-3 Defensive Investigator.
MANDATORY COMPLIANCE RULES:
1. Never invent log entries.
2. Never invent IP reputation information unless it is actually provided in the supplied data.
3. Never claim an attack is confirmed when the evidence only indicates suspicious activity.
4. Clearly distinguish evidence from inference.
5. Explain why the event received its severity.
6. Recommend defensive actions only.
7. If evidence is insufficient, explicitly say so.
8. Do not execute commands.
9. Do not provide offensive exploitation instructions.
Output ONLY valid JSON adhering strictly to the responseSchema.`,
        responseMimeType: 'application/json',
        responseSchema: {
          type: Type.OBJECT,
          properties: {
            assessment: {
              type: Type.STRING,
              description: 'Clear analyst assessment summary of the suspicious event',
            },
            threat_category: {
              type: Type.STRING,
              description: 'Primary threat category, e.g. SQL Injection Attempt, Brute Force, Command-and-Control Indicator, Normal Activity',
            },
            severity: {
              type: Type.STRING,
              enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL'],
            },
            risk_score: {
              type: Type.NUMBER,
              description: 'Risk score from 0 to 100',
            },
            confidence: {
              type: Type.NUMBER,
              description: 'Analyst confidence from 0 to 100 based strictly on provided data',
            },
            evidence: {
              type: Type.ARRAY,
              items: { type: Type.STRING },
              description: 'Concrete indicators and facts directly present in the log (never invented)',
            },
            reasoning_summary: {
              type: Type.STRING,
              description: 'Explanation of why the event received its severity, explicitly distinguishing evidence from inference',
            },
            recommended_actions: {
              type: Type.ARRAY,
              items: { type: Type.STRING },
              description: 'Defensive containment, investigation, and recovery actions only',
            },
            false_positive_possibility: {
              type: Type.STRING,
              enum: ['LOW', 'MEDIUM', 'HIGH'],
            },
            additional_information_needed: {
              type: Type.ARRAY,
              items: { type: Type.STRING },
              description: 'Explicit list of missing telemetry, host artifacts, or queries needed if evidence is incomplete',
            },
          },
          required: [
            'assessment',
            'threat_category',
            'severity',
            'risk_score',
            'confidence',
            'evidence',
            'reasoning_summary',
            'recommended_actions',
            'false_positive_possibility',
            'additional_information_needed',
          ],
        },
      },
    });

    const text = response.text || '{}';
    const parsed = JSON.parse(text);
    return res.json({
      analysis: {
        ...parsed,
        analyzed_at: new Date().toISOString(),
        model: 'gemini-3.8-flash',
        status: 'AI_ASSESSED',
      },
    });
  } catch (error: any) {
    console.error('Gemini analyze-event error:', error);
    // Graceful fallback to grounded heuristic
    return res.json({
      analysis: getDeterministicFallbackAnalysis(req.body.event),
      fallbackReason: error?.message || 'Server error communicating with AI model',
    });
  }
});

// Endpoint 2: Analyze Incident (Multi-event correlation)
app.post('/api/ai/analyze-incident', async (req, res) => {
  try {
    const { incident, events } = req.body;
    if (!incident || !events) {
      return res.status(400).json({ error: 'Missing incident or associated events payload' });
    }

    if (!ai) {
      // Deterministic incident fallback
      return res.json({
        analysis: {
          assessment: `Multi-stage suspicious security activity correlated across ${events.length} events targeting ${incident.target_assets.join(', ')}.`,
          threat_category: incident.threat_category,
          severity: incident.severity,
          risk_score: incident.severity === 'CRITICAL' ? 95 : 80,
          confidence: 88,
          evidence: events.slice(0, 5).map((e: any) => `[${e.timestamp}] ${e.device_type} (${e.action}): ${e.message}`),
          reasoning_summary: `Assigned severity ${incident.severity} based on correlation of multiple sequential alerts from origin(s) ${incident.threat_actors_ips.join(', ')}. Evidence reflects observed network drops and authentication records; actual attacker persistence is an inference pending host DFIR validation.`,
          recommended_actions: [
            `Isolate target host(s): ${incident.target_assets.join(', ')} from the internal corporate subnet.`,
            `Apply edge boundary drops for suspected threat origin IPs (${incident.threat_actors_ips.join(', ')}).`,
            `Revoke active credentials and terminate sessions for involved user accounts.`,
            `Perform endpoint forensic volatile RAM preservation for DFIR analysis.`,
          ],
          false_positive_possibility: 'LOW',
          additional_information_needed: [
            `Endpoint EDR process telemetry on targeted assets: ${incident.target_assets.join(', ')}.`,
            `NetFlow session duration logs prior to initial detected event.`,
            `External threat intelligence verification for ${incident.threat_actors_ips.join(', ')} (external reputation is unverified in raw logs).`,
          ],
          analyzed_at: new Date().toISOString(),
          model: 'Correlation-Engine (Deterministic Grounded Heuristic)',
          status: 'GROUNDED_RULE_HEURISTIC',
        },
      });
    }

    const eventSummaries = events.map((e: any, idx: number) => {
      return `Event #${idx + 1} [${e.event_id}] ${e.timestamp}: Source=${e.source_ip}:${e.source_port} -> Dest=${e.destination_ip}:${e.destination_port} | Asset=${e.asset} | Device=${e.device} (${e.device_type}) | Action=${e.action} | Rule=${e.rule_name || e.detection_reason || 'N/A'} | Msg="${e.message}" | Payload="${e.raw_payload || ''}"`;
    }).join('\n');

    const prompt = `Analyze the following correlated cybersecurity incident containing ${events.length} aggregated security events:
Incident Metadata:
- Incident ID: ${incident.incident_id}
- Title: ${incident.title}
- Current Status: ${incident.status}
- Tagged Severity: ${incident.severity}
- Category: ${incident.threat_category}
- Targeted Assets: ${incident.target_assets.join(', ')}
- Suspected Threat IPs: ${incident.threat_actors_ips.join(', ')}

Associated Security Events Timeline:
${eventSummaries}

Provide a comprehensive defensive analysis adhering strictly to the 9 SOC Analyst Rules.`;

    const response = await ai.models.generateContent({
      model: 'gemini-3.8-flash',
      contents: prompt,
      config: {
        systemInstruction: `You are SentinelAI Security Analyst, Lead Incident Commander & DFIR Investigator.
MANDATORY COMPLIANCE RULES:
1. Never invent log entries.
2. Never invent IP reputation information unless it is actually provided in the supplied data.
3. Never claim an attack is confirmed when the evidence only indicates suspicious activity.
4. Clearly distinguish evidence from inference.
5. Explain why the event received its severity.
6. Recommend defensive actions only.
7. If evidence is insufficient, explicitly say so.
8. Do not execute commands.
9. Do not provide offensive exploitation instructions.
Output ONLY valid JSON adhering strictly to the responseSchema.`,
        responseMimeType: 'application/json',
        responseSchema: {
          type: Type.OBJECT,
          properties: {
            assessment: { type: Type.STRING },
            threat_category: { type: Type.STRING },
            severity: {
              type: Type.STRING,
              enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL'],
            },
            risk_score: { type: Type.NUMBER },
            confidence: { type: Type.NUMBER },
            evidence: {
              type: Type.ARRAY,
              items: { type: Type.STRING },
            },
            reasoning_summary: { type: Type.STRING },
            recommended_actions: {
              type: Type.ARRAY,
              items: { type: Type.STRING },
            },
            false_positive_possibility: {
              type: Type.STRING,
              enum: ['LOW', 'MEDIUM', 'HIGH'],
            },
            additional_information_needed: {
              type: Type.ARRAY,
              items: { type: Type.STRING },
            },
          },
          required: [
            'assessment',
            'threat_category',
            'severity',
            'risk_score',
            'confidence',
            'evidence',
            'reasoning_summary',
            'recommended_actions',
            'false_positive_possibility',
            'additional_information_needed',
          ],
        },
      },
    });

    const parsed = JSON.parse(response.text || '{}');
    return res.json({
      analysis: {
        ...parsed,
        analyzed_at: new Date().toISOString(),
        model: 'gemini-3.8-flash',
        status: 'AI_ASSESSED',
      },
    });
  } catch (error: any) {
    console.error('Gemini analyze-incident error:', error);
    return res.status(500).json({ error: error?.message || 'Error processing incident analysis' });
  }
});

// Endpoint 3: Interactive Security Analyst Inquiry
app.post('/api/ai/query', async (req, res) => {
  try {
    const { query, eventsContext = [], incidentsContext = [] } = req.body;
    if (!query) {
      return res.status(400).json({ error: 'Missing analyst query string' });
    }

    if (!ai) {
      return res.json({
        answer: `SOC Analyst Assistant (Offline Mode): Based on current system state with ${eventsContext.length} active events and ${incidentsContext.length} incidents, rule correlation indicates active monitoring of edge ingress, jump bastions, and authentication servers. For question "${query}", ensure edge firewalls block suspicious source IPs and inspect related access logs.`,
        status: 'OFFLINE_RULE_BASED',
      });
    }

    const eventsSnippet = eventsContext.slice(0, 15).map((e: any) =>
      `[${e.event_id}] ${e.timestamp} | ${e.source_ip} -> ${e.destination_ip} (${e.asset}) | ${e.device_type} | ${e.severity} | ${e.message}`
    ).join('\n');

    const prompt = `User Query from SOC Analyst:
"${query}"

SOC Current Telemetry Context:
Active Events count: ${eventsContext.length}
Recent Events Sample:
${eventsSnippet}

Open Incidents count: ${incidentsContext.length}
Incidents Summary:
${incidentsContext.map((i: any) => `- [${i.incident_id}] ${i.title} (${i.severity}, Status: ${i.status})`).join('\n')}

Answer the analyst's question with precise cybersecurity rigor, referencing specific event IDs, IPs, assets, and protocols where appropriate. Maintain strict defensive grounding.`;

    const response = await ai.models.generateContent({
      model: 'gemini-3.8-flash',
      contents: prompt,
      config: {
        systemInstruction: 'You are SentinelAI Copilot, an AI Senior Security Analyst supporting SOC Tier-1, 2, and 3 engineers. Provide clear, direct, and technically sound answers grounded in the provided logs and SOC best practices. Format in clear markdown with bullet points.',
      },
    });

    return res.json({
      answer: response.text || 'No response generated.',
      status: 'ONLINE',
    });
  } catch (error: any) {
    console.error('Gemini query error:', error);
    return res.json({
      answer: `Unable to query AI engine: ${error?.message || 'Connection error'}. Please verify system connectivity.`,
      status: 'ERROR',
    });
  }
});

// Endpoint 4: Generate Executive / Shift Report
app.post('/api/ai/generate-report', async (req, res) => {
  try {
    const { type, metrics, incidents, recentEvents } = req.body;

    if (!ai) {
      const summaryText = `# SentinelAI SOC Shift Handover Report (Standard Baseline)
**Generated:** ${new Date().toISOString()}
**SOC Threat Posture:** DEFCON 3 (Elevated Vigilance)

## Executive Summary
During the current shift, a total of **${metrics?.total_events || 0} security events** were ingested across Firewall, IDS/IPS, Authentication, Web Server, and Network Flow devices.
- **Critical Alerts:** ${metrics?.critical_events || 0}
- **High Severity:** ${metrics?.high_events || 0}
- **Active Open Incidents:** ${incidents?.length || 0}

## Key Attack Categories
${(metrics?.top_threat_categories || []).map((c: any) => `- **${c.category}:** ${c.count} detections`).join('\n')}

## Incident Summary
${(incidents || []).map((i: any) => `### ${i.incident_id}: ${i.title}
- **Severity:** ${i.severity} | **Status:** ${i.status}
- **Target Assets:** ${i.target_assets?.join(', ')}
- **Attacker IP(s):** ${i.threat_actors_ips?.join(', ')}
`).join('\n\n')}

## Recommended SOC Priorities for Incoming Shift
1. Monitor edge firewall drop rates on DMZ web tier.
2. Confirm password reset and MFA enforcement on jump-bastion-01.
3. Review outbound egress connection logs to high ports 8443 and 4444.
`;
      return res.json({ report: summaryText, generated_by: 'Deterministic SOC Template Engine' });
    }

    const prompt = `Generate a comprehensive, professional ${type || 'SOC Shift Handover'} Report for cybersecurity leadership and incoming shift engineers.
Metrics:
- Total Events Ingested: ${metrics?.total_events || 0}
- Critical Events: ${metrics?.critical_events || 0}
- High Severity Events: ${metrics?.high_events || 0}
- Medium Severity: ${metrics?.medium_events || 0}
- Active Incidents: ${incidents?.length || 0}

Top Threat Categories:
${JSON.stringify(metrics?.top_threat_categories || [])}

Open Incidents:
${JSON.stringify(incidents || [])}

Recent Critical Events:
${JSON.stringify((recentEvents || []).slice(0, 8))}

Format the report with clean Markdown sections:
1. Executive Summary & DEFCON/Threat Condition
2. Key Incidents & Attack Timeline Reconstruction
3. Attacker Infrastructure & Targeted Assets Breakdown
4. MITRE ATT&CK Tactic Distribution
5. Immediate Action Items & Recommendations for Next Shift.`;

    const response = await ai.models.generateContent({
      model: 'gemini-3.8-flash',
      contents: prompt,
      config: {
        systemInstruction: 'You are the Lead SOC Shift Commander. Produce an authoritative, highly detailed executive and operational report. Ground all statements strictly in the provided data.',
      },
    });

    return res.json({ report: response.text || '', generated_by: 'gemini-3.8-flash' });
  } catch (error: any) {
    console.error('Report error:', error);
    return res.status(500).json({ error: error?.message || 'Failed to generate report' });
  }
});

// Mount Vite or static server
async function startServer() {
  if (process.env.NODE_ENV !== 'production') {
    const { createServer } = await import('vite');
    const vite = await createServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.resolve(distPath, 'index.html'));
    });
  }

  app.listen(PORT, () => {
    console.log(`SentinelAI Security Monitoring Server running on http://localhost:${PORT}`);
  });
}

startServer();
