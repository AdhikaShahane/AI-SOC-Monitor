/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { SecurityEvent } from '../../types/security';
import { BruteForceRuleConfig, RuleDetectionResult } from '../../types/detection';

export function evaluateBruteForce(
  events: SecurityEvent[],
  config: BruteForceRuleConfig
): RuleDetectionResult[] {
  if (!config.enabled || events.length === 0) return [];

  const detections: RuleDetectionResult[] = [];

  // Filter for failed authentication attempts with valid source IP
  const authFails = events
    .filter(
      (e) =>
        e.device_type === 'Authentication' &&
        e.action === 'FAILURE' &&
        e.source_ip &&
        e.source_ip !== '-'
    )
    .sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());

  // Group by source IP
  const groupedByIp = new Map<string, SecurityEvent[]>();
  for (const ev of authFails) {
    const list = groupedByIp.get(ev.source_ip) || [];
    list.push(ev);
    groupedByIp.set(ev.source_ip, list);
  }

  const windowMs = config.timeWindowSeconds * 1000;

  for (const [sourceIp, ipEvents] of groupedByIp.entries()) {
    // Sliding window analysis per source IP
    for (let i = 0; i < ipEvents.length; i++) {
      const windowStart = new Date(ipEvents[i].timestamp).getTime();
      const inWindow = ipEvents.filter((e) => {
        const t = new Date(e.timestamp).getTime();
        return t >= windowStart && t <= windowStart + windowMs;
      });

      if (inWindow.length >= config.failedLoginThreshold) {
        const relatedIds = inWindow.map((e) => e.event_id);
        const affectedAccounts = Array.from(
          new Set(inWindow.map((e) => e.username).filter((u) => u && u !== '-'))
        );

        // Avoid duplicate detection covering identical events
        const alreadyFound = detections.some(
          (d) =>
            d.source_ip === sourceIp &&
            d.related_event_ids.some((id) => relatedIds.includes(id))
        );

        if (!alreadyFound) {
          const failCount = inWindow.length;
          const severity = failCount >= config.failedLoginThreshold + 3 ? 'CRITICAL' : 'HIGH';
          const riskScore = Math.min(100, config.baseRiskScore + (failCount - config.failedLoginThreshold) * 3);
          const confidence = Math.min(98, 85 + (failCount >= 5 ? 10 : 5));

          const evidence = [
            `Observed ${failCount} consecutive failed login attempts from IP ${sourceIp} within ${Math.round(
              (new Date(inWindow[inWindow.length - 1].timestamp).getTime() - windowStart) / 1000
            )} seconds.`,
            `Targeted account username(s): ${
              affectedAccounts.length > 0 ? affectedAccounts.join(', ') : 'Unknown / Multiple invalid accounts'
            }.`,
            `Authentication sensor(s) involved: ${Array.from(new Set(inWindow.map((e) => e.device))).join(', ')}.`,
            `First failure: ${inWindow[0].timestamp} | Most recent failure: ${inWindow[inWindow.length - 1].timestamp}.`,
          ];

          detections.push({
            detection_id: `DET-BRUTE-${sourceIp.replace(/[^a-zA-Z0-9]/g, '_')}-${inWindow[0].event_id}`,
            rule_id: 'RULE-01-BRUTE-FORCE',
            rule_name: 'Brute Force Authentication Storm',
            category: 'Brute Force',
            severity,
            risk_score: riskScore,
            confidence,
            source_ip: sourceIp,
            affected_accounts: affectedAccounts,
            evidence,
            timestamp: inWindow[inWindow.length - 1].timestamp,
            related_event_ids: relatedIds,
            affected_asset: inWindow[0].asset,
          });
        }
      }
    }
  }

  return detections;
}
