/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { SecurityEvent } from '../../types/security';
import { PortScanRuleConfig, RuleDetectionResult } from '../../types/detection';

export function evaluatePortScan(
  events: SecurityEvent[],
  config: PortScanRuleConfig
): RuleDetectionResult[] {
  if (!config.enabled || events.length === 0) return [];

  const detections: RuleDetectionResult[] = [];

  // Consider connection attempts (Firewall drops/allows, IDS alerts, Flow records)
  const networkEvents = events
    .filter((e) => e.source_ip && e.source_ip !== '-' && e.destination_port > 0)
    .sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());

  // Group by source IP
  const groupedByIp = new Map<string, SecurityEvent[]>();
  for (const ev of networkEvents) {
    const list = groupedByIp.get(ev.source_ip) || [];
    list.push(ev);
    groupedByIp.set(ev.source_ip, list);
  }

  const windowMs = config.timeWindowSeconds * 1000;

  for (const [sourceIp, ipEvents] of groupedByIp.entries()) {
    for (let i = 0; i < ipEvents.length; i++) {
      const windowStart = new Date(ipEvents[i].timestamp).getTime();
      const inWindow = ipEvents.filter((e) => {
        const t = new Date(e.timestamp).getTime();
        return t >= windowStart && t <= windowStart + windowMs;
      });

      const uniquePorts = Array.from(new Set(inWindow.map((e) => e.destination_port))).sort(
        (a, b) => a - b
      );
      const uniqueHosts = Array.from(
        new Set(inWindow.map((e) => e.destination_ip || e.asset).filter(Boolean))
      );

      const hasPortScan = uniquePorts.length >= config.distinctPortThreshold;
      const hasHostSweep = uniqueHosts.length >= config.distinctHostThreshold;

      if (hasPortScan || hasHostSweep) {
        const relatedIds = inWindow.map((e) => e.event_id);

        const alreadyDetected = detections.some(
          (d) =>
            d.source_ip === sourceIp &&
            d.related_event_ids.some((id) => relatedIds.includes(id))
        );

        if (!alreadyDetected) {
          const isWideScan = uniquePorts.length >= 8 || uniqueHosts.length >= 5;
          const severity = isWideScan ? 'HIGH' : 'MEDIUM';
          const riskScore = Math.min(
            95,
            config.baseRiskScore + (uniquePorts.length - config.distinctPortThreshold) * 2
          );

          const scanType =
            hasPortScan && hasHostSweep
              ? 'Distributed Vertical & Horizontal Network Sweep'
              : hasPortScan
              ? 'Vertical Port Sweep (Service Discovery)'
              : 'Horizontal Subnet Host Probe';

          const evidence = [
            `Reconnaissance signature: ${scanType} originating from source IP ${sourceIp}.`,
            `Probed ${uniquePorts.length} distinct destination port(s): [${uniquePorts.slice(0, 10).join(', ')}${
              uniquePorts.length > 10 ? '...' : ''
            }].`,
            `Targeted ${uniqueHosts.length} distinct internal host(s)/asset(s): [${uniqueHosts.slice(0, 6).join(', ')}].`,
            `Recorded ${inWindow.length} connection attempts across a ${Math.round(
              (new Date(inWindow[inWindow.length - 1].timestamp).getTime() - windowStart) / 1000
            )}s window.`,
            `Perimeter action taken: ${
              inWindow.some((e) => e.action === 'DROP' || e.action === 'BLOCK')
                ? 'Multiple connection drops logged by boundary firewall'
                : 'SYN/TCP probes observed on monitoring interface'
            }.`,
          ];

          detections.push({
            detection_id: `DET-SCAN-${sourceIp.replace(/[^a-zA-Z0-9]/g, '_')}-${inWindow[0].event_id}`,
            rule_id: 'RULE-02-PORT-SCAN',
            rule_name: 'Network Service Discovery & Port Sweep',
            category: 'Port Scanning',
            severity,
            risk_score: riskScore,
            confidence: 90,
            source_ip: sourceIp,
            targeted_ports: uniquePorts,
            targeted_hosts: uniqueHosts,
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
