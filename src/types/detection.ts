/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { SeverityLevel, ThreatCategory } from './security';

export interface RuleDetectionResult {
  detection_id: string;
  rule_id: string;
  rule_name: string;
  category: ThreatCategory;
  severity: SeverityLevel;
  risk_score: number;
  confidence: number; // 0 - 100
  evidence: string[];
  timestamp: string;
  related_event_ids: string[];
  source_ip?: string;
  destination_ip?: string;
  affected_accounts?: string[];
  affected_username?: string;
  targeted_ports?: number[];
  targeted_hosts?: string[];
  affected_asset?: string;
  metadata?: Record<string, any>;
}

export interface BruteForceRuleConfig {
  enabled: boolean;
  failedLoginThreshold: number; // default: 3
  timeWindowSeconds: number; // default: 300 (5 mins)
  baseRiskScore: number; // default: 82
}

export interface PortScanRuleConfig {
  enabled: boolean;
  distinctPortThreshold: number; // default: 4
  distinctHostThreshold: number; // default: 3
  timeWindowSeconds: number; // default: 120 (2 mins)
  baseRiskScore: number; // default: 68
}

export interface SuspiciousAuthRuleConfig {
  enabled: boolean;
  failedAttemptsBeforeSuccessThreshold: number; // default: 2
  timeWindowSeconds: number; // default: 600 (10 mins)
  baseRiskScore: number; // default: 92
}

export interface TrafficAnomalyRuleConfig {
  enabled: boolean;
  packetSurgeThreshold: number; // default: 15000 pkts
  bytesSurgeThreshold: number; // default: 10MB
  baselineMultiplier: number; // default: 3.0x sample baseline
  baseRiskScore: number; // default: 80
}

export interface SuspiciousWebRequestRuleConfig {
  enabled: boolean;
  inspectParameters: boolean;
  baseRiskScore: number; // default: 86
}

export interface SuspiciousOutboundRuleConfig {
  enabled: boolean;
  suspiciousPorts: number[]; // default: [4444, 8443, 1337, 8888, 6667, 9001]
  bytesExfilThreshold: number; // default: 10485760 (10MB)
  baseRiskScore: number; // default: 84
}

export interface PrivilegeEscalationRuleConfig {
  enabled: boolean;
  baseRiskScore: number; // default: 94
}

export interface DetectionEngineConfig {
  bruteForce: BruteForceRuleConfig;
  portScan: PortScanRuleConfig;
  suspiciousAuthSequence: SuspiciousAuthRuleConfig;
  trafficAnomaly: TrafficAnomalyRuleConfig;
  suspiciousWebRequest: SuspiciousWebRequestRuleConfig;
  suspiciousOutbound: SuspiciousOutboundRuleConfig;
  privilegeEscalation: PrivilegeEscalationRuleConfig;
}

export const DEFAULT_ENGINE_CONFIG: DetectionEngineConfig = {
  bruteForce: {
    enabled: true,
    failedLoginThreshold: 3,
    timeWindowSeconds: 300,
    baseRiskScore: 82,
  },
  portScan: {
    enabled: true,
    distinctPortThreshold: 4,
    distinctHostThreshold: 3,
    timeWindowSeconds: 120,
    baseRiskScore: 68,
  },
  suspiciousAuthSequence: {
    enabled: true,
    failedAttemptsBeforeSuccessThreshold: 2,
    timeWindowSeconds: 600,
    baseRiskScore: 92,
  },
  trafficAnomaly: {
    enabled: true,
    packetSurgeThreshold: 15000,
    bytesSurgeThreshold: 10485760, // 10MB
    baselineMultiplier: 3.0,
    baseRiskScore: 80,
  },
  suspiciousWebRequest: {
    enabled: true,
    inspectParameters: true,
    baseRiskScore: 86,
  },
  suspiciousOutbound: {
    enabled: true,
    suspiciousPorts: [4444, 8443, 1337, 8888, 6667, 9001],
    bytesExfilThreshold: 10485760, // 10MB
    baseRiskScore: 84,
  },
  privilegeEscalation: {
    enabled: true,
    baseRiskScore: 94,
  },
};
