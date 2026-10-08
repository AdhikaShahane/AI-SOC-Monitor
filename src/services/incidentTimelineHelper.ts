/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { AttackTimelineItem, Incident, SecurityEvent } from '../types/security';

function formatTime(iso: string): string {
  try {
    const d = new Date(iso);
    if (isNaN(d.getTime())) return '00:00:00';
    return d.toTimeString().split(' ')[0]; // returns "HH:MM:SS"
  } catch {
    return '00:00:00';
  }
}

function deriveActionTitle(event: SecurityEvent): string {
  const msg = (event.message || '').toLowerCase();
  const evtType = (event.event_type || '').toLowerCase();

  if (event.action === 'FAILURE' && (evtType.includes('auth') || msg.includes('password') || msg.includes('login'))) {
    return 'Failed authentication';
  }
  if (event.action === 'SUCCESS' && (evtType.includes('auth') || msg.includes('login') || msg.includes('session'))) {
    return 'Successful authentication';
  }
  if (msg.includes('sudo') || msg.includes('root') || msg.includes('privilege')) {
    return 'Privilege escalation executed';
  }
  if (msg.includes('sql') || msg.includes('union select')) {
    return 'SQL injection payload detected';
  }
  if (msg.includes('syn flood') || msg.includes('flood') || msg.includes('surge')) {
    return 'Volumetric traffic surge initiated';
  }
  if (msg.includes('port') || msg.includes('sweep') || msg.includes('probe')) {
    return 'Network port reconnaissance probe';
  }
  if (event.action === 'BLOCK' || event.action === 'DROP') {
    return 'Perimeter security policy block';
  }
  if (event.device_type === 'Network Flow' || msg.includes('exfiltration') || msg.includes('egress')) {
    return 'Internal resource accessed & egress session opened';
  }
  if (event.action === 'ALERT') {
    return 'IDS intrusion signature triggered';
  }

  return event.event_type || 'Security event logged';
}

/**
 * Returns a clean, chronological attack timeline for any incident.
 * Pulls from correlated events if available, or falls back to stored timeline items.
 */
export function getIncidentAttackTimeline(
  incident: Incident,
  allEvents: SecurityEvent[] = []
): AttackTimelineItem[] {
  // If incident has correlated events in the current telemetry buffer
  const correlated = allEvents
    .filter((e) => incident.event_ids.includes(e.event_id))
    .sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());

  if (correlated.length > 0) {
    return correlated.map((ev, index) => {
      const timeStr = formatTime(ev.timestamp);
      const action = deriveActionTitle(ev);
      const target = ev.asset ? ` on ${ev.asset}` : '';
      const src = ev.source_ip ? ` from ${ev.source_ip}` : '';
      const user = ev.username && ev.username !== '-' ? ` (${ev.username})` : '';

      return {
        id: `tl-${incident.incident_id}-${ev.event_id}-${index}`,
        timestamp: ev.timestamp,
        time_display: timeStr,
        action,
        description: `${action}${user}${src}${target}: ${ev.message}`,
        source_ip: ev.source_ip,
        destination_ip: ev.destination_ip,
        asset: ev.asset,
        username: ev.username !== '-' ? ev.username : undefined,
        severity: ev.severity,
        event_id: ev.event_id,
      };
    });
  }

  // Fallback to predefined incident timeline if provided
  if (incident.attack_timeline && incident.attack_timeline.length > 0) {
    return incident.attack_timeline;
  }

  // Fallback synthesis based on incident summary & created_at
  const baseTime = new Date(incident.created_at).getTime() || Date.now();
  const synthTime = (offsetSec: number) => formatTime(new Date(baseTime + offsetSec * 1000).toISOString());

  return [
    {
      id: `tl-${incident.incident_id}-1`,
      timestamp: new Date(baseTime).toISOString(),
      time_display: synthTime(0),
      action: 'Initial reconnaissance probe',
      description: `Initial reconnaissance probe observed against ${incident.target_assets.join(', ')}`,
      severity: 'MEDIUM',
    },
    {
      id: `tl-${incident.incident_id}-2`,
      timestamp: new Date(baseTime + 15000).toISOString(),
      time_display: synthTime(15),
      action: 'Anomalous activity detected',
      description: incident.summary,
      severity: incident.severity,
    },
    {
      id: `tl-${incident.incident_id}-3`,
      timestamp: new Date(baseTime + 45000).toISOString(),
      time_display: synthTime(45),
      action: 'Security boundary alert triggered',
      description: `Automated detection correlation flagged incident ${incident.incident_id}`,
      severity: incident.severity,
    },
  ];
}
