/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { SecurityEvent } from '../../types/security';
import { TrafficAnomalyRuleConfig, RuleDetectionResult } from '../../types/detection';

export function evaluateTrafficAnomaly(
  events: SecurityEvent[],
  config: TrafficAnomalyRuleConfig
): RuleDetectionResult[] {
  if (!config.enabled || events.length === 0) return [];

  const detections: RuleDetectionResult[] = [];

  // Calculate baseline metrics across all events with packet / byte data
  const packetsList = events.map((e) => Number(e.packets || 0)).filter((p) => p > 0);
  const bytesList = events.map((e) => Number(e.bytes_transferred || 0)).filter((b) => b > 0);

  const avgPackets =
    packetsList.length > 0 ? packetsList.reduce((a, b) => a + b, 0) / packetsList.length : 100;
  const avgBytes =
    bytesList.length > 0 ? bytesList.reduce((a, b) => a + b, 0) / bytesList.length : 5000;

  // Dynamic baseline threshold calculation
  const dynamicPacketThreshold = Math.max(
    config.packetSurgeThreshold,
    avgPackets * config.baselineMultiplier
  );
  const dynamicBytesThreshold = Math.max(
    config.bytesSurgeThreshold,
    avgBytes * config.baselineMultiplier
  );

  for (const ev of events) {
    const packets = Number(ev.packets || 0);
    const bytes = Number(ev.bytes_transferred || 0);
    const msg = (ev.message || '').toLowerCase();
    const payload = (ev.raw_payload || '').toLowerCase();

    const isExplicitFlood =
      msg.includes('syn flood') ||
      msg.includes('flood') ||
      msg.includes('traffic anomaly') ||
      payload.includes('rate_limit') ||
      payload.includes('flood');

    const isPacketSurge = packets >= dynamicPacketThreshold;
    const isBytesSurge = bytes >= dynamicBytesThreshold && ev.device_type !== 'Network Flow'; // Exfil handles heavy outbound flow

    if (isExplicitFlood || isPacketSurge || (packets > 5000 && isBytesSurge)) {
      const alreadyDetected = detections.some((d) => d.related_event_ids.includes(ev.event_id));
      if (!alreadyDetected) {
        const severity = packets >= 30000 || isExplicitFlood ? 'HIGH' : 'MEDIUM';
        const riskScore = Math.min(
          96,
          config.baseRiskScore + (packets > 20000 ? 10 : 0)
        );

        const packetDelta =
          avgPackets > 0 ? (packets / avgPackets).toFixed(1) : 'N/A';

        const evidence = [
          `Abnormal traffic spike observed on asset ${ev.asset}: ${packets.toLocaleString()} packets (${(
            bytes /
            (1024 * 1024)
          ).toFixed(2)} MB).`,
          `Traffic represents a ${packetDelta}x surge compared to current dataset baseline average of ${Math.round(
            avgPackets
          )} pkts/session.`,
          `Sensor log: "${ev.message}".`,
          `Boundary action: ${ev.action} on device ${ev.device} (${ev.device_type}).`,
          `Traffic flow: ${ev.source_ip}:${ev.source_port} -> ${ev.destination_ip}:${ev.destination_port} [${ev.protocol}].`,
        ];

        detections.push({
          detection_id: `DET-TRAFFIC-ANOMALY-${ev.event_id}`,
          rule_id: 'RULE-04-TRAFFIC-ANOMALY',
          rule_name: 'Traffic Volume Spike & Anomaly Baseline Deviation',
          category: 'DDoS/Traffic Anomaly',
          severity,
          risk_score: riskScore,
          confidence: 88,
          affected_asset: ev.asset,
          source_ip: ev.source_ip,
          destination_ip: ev.destination_ip,
          evidence,
          timestamp: ev.timestamp,
          related_event_ids: [ev.event_id],
          metadata: {
            observedPackets: packets,
            baselineAvgPackets: Math.round(avgPackets),
            observedBytes: bytes,
          },
        });
      }
    }
  }

  return detections;
}
