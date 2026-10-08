/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { SecurityEvent } from '../../types/security';
import { SuspiciousWebRequestRuleConfig, RuleDetectionResult } from '../../types/detection';

interface ExploitPattern {
  name: string;
  pattern: RegExp;
  category: 'SQL Injection Attempt' | 'Malware Indicator';
  description: string;
}

const WEB_ATTACK_PATTERNS: ExploitPattern[] = [
  {
    name: 'SQLi: Union Select Query',
    pattern: /union(\s+all)?\s+select/i,
    category: 'SQL Injection Attempt',
    description: 'UNION SELECT statement injected into HTTP request parameters to extract database schema or records.',
  },
  {
    name: 'SQLi: Boolean Authentication Bypass',
    pattern: /('|%27)\s*or\s*('|%27)?(1=1|'1'='1'|true)/i,
    category: 'SQL Injection Attempt',
    description: 'Boolean tautology string intended to bypass SQL authentication or query where-clauses.',
  },
  {
    name: 'SQLi: Database Metadata / Schema Enumeration',
    pattern: /(information_schema|sysobjects|syscolumns|all_tables)/i,
    category: 'SQL Injection Attempt',
    description: 'Query targeting internal SQL metadata tables to enumerate databases, tables, and columns.',
  },
  {
    name: 'SQLi: Stacked Query / Command Execution Stored Procedure',
    pattern: /(xp_cmdshell|exec\s+sp_|waitfor\s+delay|pg_sleep)/i,
    category: 'SQL Injection Attempt',
    description: 'Database administrative or time-delay stored procedure injection.',
  },
  {
    name: 'Directory Traversal & Sensitive File Probe',
    pattern: /(\.\.\/|\.\.\\|%2e%2e%2f|\/etc\/passwd|\/etc\/shadow|win\.ini|boot\.ini)/i,
    category: 'SQL Injection Attempt',
    description: 'Path traversal sequences attempting to break out of webroot and read system configuration files.',
  },
  {
    name: 'Cross-Site Scripting (XSS) / Script Injection',
    pattern: /(<script[\s>]|javascript:|onload=|onerror=)/i,
    category: 'SQL Injection Attempt',
    description: 'Client-side script tag or event handler injection detected in HTTP URI or body.',
  },
];

export function evaluateSuspiciousWebRequest(
  events: SecurityEvent[],
  config: SuspiciousWebRequestRuleConfig
): RuleDetectionResult[] {
  if (!config.enabled || events.length === 0) return [];

  const detections: RuleDetectionResult[] = [];

  for (const ev of events) {
    const isWebContext =
      ev.device_type === 'Web Server' ||
      ev.protocol === 'HTTP' ||
      ev.protocol === 'HTTPS' ||
      ev.destination_port === 80 ||
      ev.destination_port === 443 ||
      ev.destination_port === 8080;

    if (!isWebContext && !ev.raw_payload) continue;

    const payloadText = `${ev.raw_payload || ''} ${ev.message || ''}`;

    for (const pat of WEB_ATTACK_PATTERNS) {
      if (pat.pattern.test(payloadText)) {
        const alreadyDetected = detections.some((d) => d.related_event_ids.includes(ev.event_id));
        if (!alreadyDetected) {
          const matchSnippet = payloadText.match(pat.pattern)?.[0] || 'matched-pattern';

          const evidence = [
            `Deterministic pattern match: Detected '${pat.name}' in web request logged by ${ev.device} (${ev.device_type}).`,
            `Suspicious marker matched: "${matchSnippet.slice(0, 80)}" (classified as suspicious without execution).`,
            `Technical pattern description: ${pat.description}.`,
            `Source origin: ${ev.source_ip}:${ev.source_port} -> Destination: ${ev.destination_ip}:${ev.destination_port}.`,
            `Targeted web application / asset: ${ev.asset}.`,
            `Sensor action recorded: ${ev.action}.`,
          ];

          detections.push({
            detection_id: `DET-WEB-ATTACK-${ev.event_id}`,
            rule_id: 'RULE-05-SUSPICIOUS-WEB',
            rule_name: 'Suspicious Web Request & Exploit Pattern Detector',
            category: pat.category,
            severity: 'HIGH',
            risk_score: config.baseRiskScore,
            confidence: 92,
            affected_asset: ev.asset,
            source_ip: ev.source_ip,
            destination_ip: ev.destination_ip,
            evidence,
            timestamp: ev.timestamp,
            related_event_ids: [ev.event_id],
            metadata: {
              matchedSignature: pat.name,
              matchSnippet,
            },
          });
        }
      }
    }
  }

  return detections;
}
