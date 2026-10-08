/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { SecurityEvent } from '../../types/security';
import { SuspiciousAuthRuleConfig, RuleDetectionResult } from '../../types/detection';

export function evaluateSuspiciousAuth(
  events: SecurityEvent[],
  config: SuspiciousAuthRuleConfig
): RuleDetectionResult[] {
  if (!config.enabled || events.length === 0) return [];

  const detections: RuleDetectionResult[] = [];

  const authEvents = events
    .filter(
      (e) =>
        e.device_type === 'Authentication' &&
        (e.action === 'SUCCESS' || e.action === 'FAILURE') &&
        e.source_ip &&
        e.source_ip !== '-'
    )
    .sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());

  const windowMs = config.timeWindowSeconds * 1000;

  // Look for any SUCCESS event that was preceded by >= failedAttemptsBeforeSuccessThreshold FAILUREs from same IP
  for (let i = 0; i < authEvents.length; i++) {
    const current = authEvents[i];
    if (current.action !== 'SUCCESS') continue;

    const successTime = new Date(current.timestamp).getTime();
    const sourceIp = current.source_ip;

    const priorFails = authEvents.filter((e) => {
      if (e.action !== 'FAILURE') return false;
      if (e.source_ip !== sourceIp) return false;
      const t = new Date(e.timestamp).getTime();
      return t < successTime && t >= successTime - windowMs;
    });

    if (priorFails.length >= config.failedAttemptsBeforeSuccessThreshold) {
      const relatedIds = [...priorFails.map((f) => f.event_id), current.event_id];
      const targetedUsernames = Array.from(
        new Set(priorFails.map((f) => f.username).concat(current.username).filter(Boolean))
      );

      const alreadyDetected = detections.some(
        (d) =>
          d.source_ip === sourceIp &&
          d.related_event_ids.includes(current.event_id)
      );

      if (!alreadyDetected) {
        const severity = 'CRITICAL';
        const riskScore = Math.min(100, config.baseRiskScore + (priorFails.length >= 4 ? 6 : 2));
        const confidence = 94;

        const evidence = [
          `Detected credential compromise sequence: Successful login for account '${current.username}' from IP ${sourceIp} immediately following ${priorFails.length} failed attempts.`,
          `Authentication history: ${priorFails
            .map((f) => `[${f.timestamp.slice(11, 19)}] FAIL user='${f.username}'`)
            .join(', ')} -> [${current.timestamp.slice(11, 19)}] SUCCESS user='${current.username}'.`,
          `Targeted asset: ${current.asset} via authentication sensor ${current.device}.`,
          `Potential attack vector: Password guessing / brute force breakthrough or credential stuffing validation.`,
        ];

        detections.push({
          detection_id: `DET-AUTH-SEQ-${sourceIp.replace(/[^a-zA-Z0-9]/g, '_')}-${current.event_id}`,
          rule_id: 'RULE-03-SUSPICIOUS-AUTH',
          rule_name: 'Suspicious Auth Sequence (Brute-Force to Success Breakthrough)',
          category: 'Suspicious Authentication',
          severity,
          risk_score: riskScore,
          confidence,
          source_ip: sourceIp,
          affected_username: current.username,
          affected_accounts: targetedUsernames,
          affected_asset: current.asset,
          evidence,
          timestamp: current.timestamp,
          related_event_ids: relatedIds,
        });
      }
    }
  }

  return detections;
}
