/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { AIAnalysisResult, Incident, SecurityEvent, SOCMetrics } from '../types/security';

export async function checkAIHealth(): Promise<{ online: boolean; ai_available: boolean; model: string }> {
  try {
    const res = await fetch('/api/health');
    if (!res.ok) throw new Error('Health check non-ok');
    const data = await res.json();
    return {
      online: true,
      ai_available: Boolean(data.ai_available),
      model: data.model || 'gemini-3.8-flash',
    };
  } catch (err) {
    return { online: false, ai_available: false, model: 'Offline' };
  }
}

export async function analyzeEventWithAI(event: SecurityEvent): Promise<AIAnalysisResult> {
  try {
    const res = await fetch('/api/ai/analyze-event', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ event }),
    });

    if (!res.ok) {
      throw new Error(`Server returned ${res.status}`);
    }

    const data = await res.json();
    if (data.analysis) {
      return data.analysis;
    }
    throw new Error(data.error || 'No analysis returned');
  } catch (err: any) {
    console.warn('AI analysis API call failed, falling back to client-side grounded corroboration', err);
    // Graceful client fallback with grounded heuristics
    return {
      assessment: `Suspicious activity detected corresponding to ${event.threat_category || 'Normal Activity'}. Deterministic rule correlation flagged this event for analyst triage.`,
      threat_category: event.threat_category || 'Normal Activity',
      severity: event.severity || 'INFORMATIONAL',
      risk_score: event.risk_score || 25,
      confidence: 80,
      evidence: [
        `Observed Source IP: ${event.source_ip}:${event.source_port}`,
        `Observed Destination IP: ${event.destination_ip}:${event.destination_port}`,
        `Reporting Device: ${event.device} (${event.device_type})`,
        `Payload Excerpt: ${event.raw_payload || event.message}`,
      ],
      reasoning_summary: `Assigned severity ${event.severity || 'INFORMATIONAL'} because deterministic engine identified ${event.rule_name || event.detection_reason || 'operational activity'}. Evidence is strictly taken from log fields; external threat actor intent remains an inference pending host investigation.`,
      recommended_actions: [
        `Cross-reference source IP ${event.source_ip} with edge firewall session table.`,
        `Review logs on target asset ${event.asset} for concurrent anomaly spikes.`,
        `If anomalous, escalate to SOC Level 2 Incident Responder.`,
      ],
      false_positive_possibility: event.severity === 'CRITICAL' ? 'LOW' : 'MEDIUM',
      additional_information_needed: [
        `Host-level process tree from ${event.asset}.`,
        `Historical baseline connection rate for source IP ${event.source_ip}.`,
      ],
      analyzed_at: new Date().toISOString(),
      model: 'Client-Grounded-Heuristic',
      status: 'GROUNDED_RULE_HEURISTIC',
    };
  }
}

export async function analyzeIncidentWithAI(
  incident: Incident,
  events: SecurityEvent[]
): Promise<AIAnalysisResult> {
  try {
    const res = await fetch('/api/ai/analyze-incident', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ incident, events }),
    });

    if (!res.ok) {
      throw new Error(`Server returned ${res.status}`);
    }

    const data = await res.json();
    if (data.analysis) {
      return data.analysis;
    }
    throw new Error(data.error || 'Failed to analyze incident');
  } catch (err) {
    console.warn('AI Incident analysis API failed, using grounded fallback', err);
    return {
      assessment: `Multi-stage suspicious security activity correlated across ${events.length} security alerts targeting asset(s) ${incident.target_assets.join(', ')}.`,
      threat_category: incident.threat_category,
      severity: incident.severity,
      risk_score: incident.severity === 'CRITICAL' ? 95 : 82,
      confidence: 85,
      evidence: events.slice(0, 4).map((e) => `[${e.timestamp}] ${e.device_type} (${e.action}): ${e.message}`),
      reasoning_summary: `Assigned severity ${incident.severity} based on correlation of sequential alerts from suspected origin(s) ${incident.threat_actors_ips.join(', ')}. Evidence documents network drops and auth logs; actual attacker persistence is an inference until host validation completes.`,
      recommended_actions: [
        `Apply boundary IP drop for threat origins: ${incident.threat_actors_ips.join(', ')}.`,
        `Perform network isolation on affected asset: ${incident.target_assets.join(', ')}.`,
        `Audit compromised user accounts and terminate active SSH/Web sessions.`,
        `Preserve system volatile RAM and audit logs for forensic attribution.`,
      ],
      false_positive_possibility: 'LOW',
      additional_information_needed: [
        `Endpoint EDR process telemetry on targeted assets: ${incident.target_assets.join(', ')}.`,
        `External reputation intelligence on threat IPs (not present in raw log).`,
      ],
      analyzed_at: new Date().toISOString(),
      model: 'Correlation-Engine-Grounded',
      status: 'GROUNDED_RULE_HEURISTIC',
    };
  }
}

export async function queryAIAnalyst(
  query: string,
  eventsContext: SecurityEvent[],
  incidentsContext: Incident[]
): Promise<string> {
  try {
    const res = await fetch('/api/ai/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query, eventsContext, incidentsContext }),
    });

    if (!res.ok) throw new Error('Query error');
    const data = await res.json();
    return data.answer || 'No answer returned.';
  } catch (err: any) {
    return `**Offline SOC Rule Analyst:**\n\nUnable to reach server AI service. Telemetry indicates ${eventsContext.length} active events and ${incidentsContext.length} open incidents. For query *"${query}"*, inspect the Events module for matching source IPs or review the Incident timeline.`;
  }
}

export async function generateSOCReport(
  type: string,
  metrics: SOCMetrics,
  incidents: Incident[],
  recentEvents: SecurityEvent[]
): Promise<string> {
  try {
    const res = await fetch('/api/ai/generate-report', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type, metrics, incidents, recentEvents }),
    });

    if (!res.ok) throw new Error('Report generation error');
    const data = await res.json();
    return data.report || 'Report could not be generated.';
  } catch (err: any) {
    return `# SentinelAI SOC Summary Report\n\n**Generated:** ${new Date().toISOString()}\n\n- Total Events: ${metrics.total_events}\n- Critical: ${metrics.critical_events}\n- High: ${metrics.high_events}\n- Open Incidents: ${incidents.length}\n\n*Grounded report generated via local metrics accumulator.*`;
  }
}
