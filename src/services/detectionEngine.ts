/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { SecurityEvent } from '../types/security';
import {
  DEFAULT_ENGINE_CONFIG,
  DetectionEngineConfig,
  RuleDetectionResult,
} from '../types/detection';
import { evaluateBruteForce } from './rules/bruteForceRule';
import { evaluatePortScan } from './rules/portScanRule';
import { evaluateSuspiciousAuth } from './rules/suspiciousAuthRule';
import { evaluateTrafficAnomaly } from './rules/trafficAnomalyRule';
import { evaluateSuspiciousWebRequest } from './rules/suspiciousWebRequestRule';
import { evaluateSuspiciousOutbound } from './rules/suspiciousOutboundRule';
import { evaluatePrivilegeEscalation } from './rules/privilegeEscalationRule';

// Re-export individual rule evaluation functions for unit testability
export {
  evaluateBruteForce,
  evaluatePortScan,
  evaluateSuspiciousAuth,
  evaluateTrafficAnomaly,
  evaluateSuspiciousWebRequest,
  evaluateSuspiciousOutbound,
  evaluatePrivilegeEscalation,
};

export class ModularDetectionEngine {
  private config: DetectionEngineConfig;

  constructor(customConfig: Partial<DetectionEngineConfig> = {}) {
    this.config = {
      ...DEFAULT_ENGINE_CONFIG,
      ...customConfig,
    };
  }

  public getConfig(): DetectionEngineConfig {
    return JSON.parse(JSON.stringify(this.config));
  }

  public updateConfig(newConfig: Partial<DetectionEngineConfig>): void {
    this.config = {
      ...this.config,
      ...newConfig,
    };
  }

  /**
   * Evaluates all 7 deterministic security rules across an entire corpus of events.
   * Produces deduplicated, prioritized detections with rich evidence.
   */
  public analyzeAllEvents(events: SecurityEvent[]): RuleDetectionResult[] {
    const allDetections: RuleDetectionResult[] = [
      ...evaluateBruteForce(events, this.config.bruteForce),
      ...evaluatePortScan(events, this.config.portScan),
      ...evaluateSuspiciousAuth(events, this.config.suspiciousAuthSequence),
      ...evaluateTrafficAnomaly(events, this.config.trafficAnomaly),
      ...evaluateSuspiciousWebRequest(events, this.config.suspiciousWebRequest),
      ...evaluateSuspiciousOutbound(events, this.config.suspiciousOutbound),
      ...evaluatePrivilegeEscalation(events, this.config.privilegeEscalation),
    ];

    // Sort detections by risk score descending, then timestamp descending
    return allDetections.sort((a, b) => {
      if (b.risk_score !== a.risk_score) {
        return b.risk_score - a.risk_score;
      }
      return new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime();
    });
  }

  /**
   * Ingests a single event in the context of recent historical telemetry.
   * Evaluates deterministic rules and updates the event's metadata.
   */
  public processEvent(
    event: SecurityEvent,
    historicalEvents: SecurityEvent[] = []
  ): SecurityEvent {
    const combinedContext = [event, ...historicalEvents];
    const detections = this.analyzeAllEvents(combinedContext);

    // Find any detection that explicitly references this event
    const matchedDetection = detections.find((d) =>
      d.related_event_ids.includes(event.event_id)
    );

    if (matchedDetection) {
      const existingAI = event.ai_analysis;
      return {
        ...event,
        severity: matchedDetection.severity,
        risk_score: matchedDetection.risk_score,
        threat_category: matchedDetection.category,
        detection_reason: matchedDetection.evidence[0] || 'Deterministic detection rule fired.',
        rule_id: matchedDetection.rule_id,
        rule_name: matchedDetection.rule_name,
        detection_method: existingAI ? 'RULE_AND_AI' : 'RULE',
      };
    }

    // Baseline Normal Activity
    return {
      ...event,
      severity: event.severity || 'INFORMATIONAL',
      risk_score: event.risk_score || 12,
      threat_category: event.threat_category || 'Normal Activity',
      detection_reason: event.detection_reason || 'Traffic matched standard enterprise operational baseline; no anomalous signatures found.',
      detection_method: event.ai_analysis ? 'AI' : 'RULE',
    };
  }
}

export const detectionEngine = new ModularDetectionEngine();
