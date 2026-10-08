/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { SecurityEvent } from '../../types/security';
import { SuspiciousOutboundRuleConfig, RuleDetectionResult } from '../../types/detection';

function isInternalIP(ip: string): boolean {
  if (!ip) return false;
  return (
    ip.startsWith('10.') ||
    ip.startsWith('192.168.') ||
    ip.startsWith('172.16.') ||
    ip.startsWith('172.17.') ||
    ip.startsWith('172.18.') ||
    ip.startsWith('172.19.') ||
    ip.startsWith('172.20.') ||
    ip.startsWith('172.31.') ||
    ip === '127.0.0.1' ||
    ip === 'localhost'
  );
}

export function evaluateSuspiciousOutbound(
  events: SecurityEvent[],
  config: SuspiciousOutboundRuleConfig
): RuleDetectionResult[] {
  if (!config.enabled || events.length === 0) return [];

  const detections: RuleDetectionResult[] = [];

  for (const ev of events) {
    const srcIp = ev.source_ip || '';
    const dstIp = ev.destination_ip || '';
    const dstPort = Number(ev.destination_port || 0);
    const bytes = Number(ev.bytes_transferred || 0);
    const msg = (ev.message || '').toLowerCase();
    const payload = (ev.raw_payload || '').toLowerCase();

    // Check if traffic is egress from internal private IP to external non-RFC1918 destination
    const isOutbound = isInternalIP(srcIp) && !isInternalIP(dstIp) && dstIp !== '-';
    if (!isOutbound) continue;

    const isSuspiciousPort = config.suspiciousPorts.includes(dstPort);
    const isExfiltrationSpike = bytes >= config.bytesExfilThreshold;
    const isBlockedEgress = ev.action === 'BLOCK' || ev.action === 'DROP';
    const isBeaconKeyword = msg.includes('beacon') || payload.includes('beacon') || msg.includes('c2');

    if (isSuspiciousPort || isExfiltrationSpike || isBlockedEgress || isBeaconKeyword) {
      const alreadyDetected = detections.some((d) => d.related_event_ids.includes(ev.event_id));
      if (!alreadyDetected) {
        let category: 'Suspicious Outbound Traffic' | 'Command-and-Control Indicator' | 'Data Exfiltration Indicator' =
          'Suspicious Outbound Traffic';
        let severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' = 'HIGH';
        let riskScore = config.baseRiskScore;

        if (isExfiltrationSpike) {
          category = 'Data Exfiltration Indicator';
          severity = 'CRITICAL';
          riskScore = Math.max(riskScore, 92);
        } else if (isBeaconKeyword || dstPort === 4444 || dstPort === 1337) {
          category = 'Command-and-Control Indicator';
          severity = isBlockedEgress ? 'HIGH' : 'CRITICAL';
          riskScore = Math.max(riskScore, 88);
        }

        const evidence = [
          `Unusual outbound session initiated: Internal asset ${ev.asset} (${srcIp}:${ev.source_port}) attempting external connection to ${dstIp}:${dstPort} [${ev.protocol}].`,
          isSuspiciousPort
            ? `Target port ${dstPort} is non-standard for enterprise egress (frequently associated with staging/remote management/testing listeners).`
            : `Outbound connection flagged based on anomaly filter.`,
          isExfiltrationSpike
            ? `Transferred data volume ${(bytes / (1024 * 1024)).toFixed(1)} MB exceeds baseline threshold (${(
                config.bytesExfilThreshold /
                (1024 * 1024)
              ).toFixed(1)} MB).`
            : `Telemetry observed ${bytes.toLocaleString()} bytes over session.`,
          `Sensor device: ${ev.device} (${ev.device_type}) | Log action: ${ev.action}.`,
          `Note: Detection classified as suspicious outbound connection based on telemetry heuristics; actual intent requires host-level forensic verification.`,
        ];

        detections.push({
          detection_id: `DET-OUTBOUND-${ev.event_id}`,
          rule_id: 'RULE-06-SUSPICIOUS-OUTBOUND',
          rule_name: 'Suspicious Outbound Connection & Egress Indicator',
          category,
          severity,
          risk_score: riskScore,
          confidence: 86,
          source_ip: srcIp,
          destination_ip: dstIp,
          affected_asset: ev.asset,
          targeted_ports: [dstPort],
          evidence,
          timestamp: ev.timestamp,
          related_event_ids: [ev.event_id],
          metadata: {
            destinationPort: dstPort,
            bytesTransferred: bytes,
            outboundAction: ev.action,
          },
        });
      }
    }
  }

  return detections;
}
