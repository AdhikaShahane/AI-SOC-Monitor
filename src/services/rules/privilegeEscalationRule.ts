/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { SecurityEvent } from '../../types/security';
import { PrivilegeEscalationRuleConfig, RuleDetectionResult } from '../../types/detection';

const PRIV_PATTERNS = [
  { term: 'sudo su', desc: 'Execution of sudo su shell elevation' },
  { term: 'sudo -i', desc: 'Interactive root login shell spawn via sudo' },
  { term: 'wheel group', desc: 'User modification to administrative wheel group' },
  { term: 'domain admins', desc: 'Active Directory group escalation to Domain Admins' },
  { term: 'sedebugprivilege', desc: 'Security token privilege SeDebugPrivilege enabled' },
  { term: 'elevated to root', desc: 'Process execution token transition to UID 0 (root)' },
  { term: 'uac bypass', desc: 'User Account Control token manipulation' },
  { term: 'privilege escalation', desc: 'Endpoint detection engine flagged privilege escalation event' },
];

export function evaluatePrivilegeEscalation(
  events: SecurityEvent[],
  config: PrivilegeEscalationRuleConfig
): RuleDetectionResult[] {
  if (!config.enabled || events.length === 0) return [];

  const detections: RuleDetectionResult[] = [];

  for (const ev of events) {
    const textToScan = `${ev.message || ''} ${ev.raw_payload || ''} ${ev.event_type || ''}`.toLowerCase();

    const matchedPattern = PRIV_PATTERNS.find((p) => textToScan.includes(p.term));
    const isRootTarget =
      (ev.username === 'root' || ev.username === 'Administrator') &&
      ev.event_type.toLowerCase().includes('escalat');

    if (matchedPattern || isRootTarget) {
      const alreadyDetected = detections.some((d) => d.related_event_ids.includes(ev.event_id));
      if (!alreadyDetected) {
        const desc = matchedPattern ? matchedPattern.desc : 'Privileged identity elevation event';

        const evidence = [
          `Administrative escalation signature detected: ${desc}.`,
          `User context: '${ev.username || 'unknown'}'.`,
          `Target asset: ${ev.asset} (${ev.device}).`,
          `Recorded audit log: "${ev.message}".`,
          ev.raw_payload ? `Raw command payload: "${ev.raw_payload.slice(0, 150)}"` : '',
          `Mitre ATT&CK Reference: Privilege Escalation (T1548: Abuse Elevation Control Mechanism).`,
        ].filter(Boolean);

        detections.push({
          detection_id: `DET-PRIV-ESC-${ev.event_id}`,
          rule_id: 'RULE-07-PRIVILEGE-ESCALATION',
          rule_name: 'Privilege Escalation & Administrative Account Elevation',
          category: 'Privilege Escalation',
          severity: 'CRITICAL',
          risk_score: config.baseRiskScore,
          confidence: 96,
          source_ip: ev.source_ip,
          affected_username: ev.username,
          affected_accounts: ev.username ? [ev.username] : [],
          affected_asset: ev.asset,
          evidence,
          timestamp: ev.timestamp,
          related_event_ids: [ev.event_id],
          metadata: {
            mechanism: desc,
          },
        });
      }
    }
  }

  return detections;
}
