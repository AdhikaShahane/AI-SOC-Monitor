/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';

export type DetectionMethod = 'RULE' | 'AI' | 'RULE_AND_AI';

export type EventStatus = 'OPEN' | 'INVESTIGATING' | 'IN_INCIDENT' | 'RESOLVED' | 'DISMISSED';

export type IncidentStatus = 'New' | 'Investigating' | 'Contained' | 'Resolved' | 'False Positive';

export type ThreatCategory =
  | 'Brute Force'
  | 'Port Scanning'
  | 'Suspicious Authentication'
  | 'Malware Indicator'
  | 'Command-and-Control Indicator'
  | 'DDoS/Traffic Anomaly'
  | 'SQL Injection Attempt'
  | 'Privilege Escalation'
  | 'Suspicious Outbound Traffic'
  | 'Data Exfiltration Indicator'
  | 'Normal Activity';

export type DeviceType = 'Firewall' | 'IDS/IPS' | 'Authentication' | 'Web Server' | 'Network Flow';

export type EventAction = 'ALLOW' | 'BLOCK' | 'DROP' | 'ALERT' | 'SUCCESS' | 'FAILURE';

export interface MitreAttackRef {
  tactic: string;
  technique_id: string;
  technique_name: string;
}

export interface AIAnalysisResult {
  assessment: string;
  threat_category: ThreatCategory | string;
  severity: SeverityLevel;
  risk_score: number;
  confidence: number;
  evidence: string[];
  reasoning_summary: string;
  recommended_actions: string[];
  false_positive_possibility: 'LOW' | 'MEDIUM' | 'HIGH' | string;
  additional_information_needed: string[];
  analyzed_at?: string;
  model?: string;
  status?: 'AI_ASSESSED' | 'GROUNDED_RULE_HEURISTIC';
}

export interface SecurityEvent {
  event_id: string;
  timestamp: string;
  source_ip: string;
  destination_ip: string;
  source_port: number;
  destination_port: number;
  protocol: 'TCP' | 'UDP' | 'ICMP' | 'HTTP' | 'HTTPS' | 'SSH' | 'DNS' | string;
  device: string;
  device_type: DeviceType;
  event_type: string;
  action: EventAction;
  username: string;
  asset: string;
  message: string;
  severity: SeverityLevel;
  risk_score: number;
  detection_method: DetectionMethod;
  status: EventStatus;
  threat_category: ThreatCategory;
  detection_reason?: string;
  rule_id?: string;
  rule_name?: string;
  mitre_attack?: MitreAttackRef;
  raw_payload?: string;
  bytes_transferred?: number;
  packets?: number;
  ai_analysis?: AIAnalysisResult;
}

export interface IncidentNote {
  id: string;
  author: string;
  timestamp: string;
  note: string;
}

export interface IncidentChecklistItem {
  id: string;
  title: string;
  completed: boolean;
  completed_by?: string;
  completed_at?: string;
}

export interface AttackTimelineItem {
  id: string;
  timestamp: string;
  time_display?: string;
  action: string;
  description: string;
  source_ip?: string;
  destination_ip?: string;
  asset?: string;
  username?: string;
  severity?: SeverityLevel;
  event_id?: string;
}

export interface Incident {
  incident_id: string;
  title: string;
  created_at: string;
  updated_at: string;
  severity: SeverityLevel;
  status: IncidentStatus;
  threat_category: ThreatCategory;
  assigned_to: string;
  event_ids: string[];
  target_assets: string[];
  threat_actors_ips: string[];
  summary: string;
  detection_origin: DetectionMethod;
  analyst_notes: IncidentNote[];
  mitre_tactics: string[];
  containment_checklist: IncidentChecklistItem[];
  attack_timeline?: AttackTimelineItem[];
  ai_analysis?: AIAnalysisResult;
}

export interface DetectionRule {
  rule_id: string;
  name: string;
  description: string;
  threat_category: ThreatCategory;
  default_severity: SeverityLevel;
  base_risk_score: number;
  enabled: boolean;
  threshold?: number;
  time_window_seconds?: number;
  mitre_attack: MitreAttackRef;
}

export interface SOCMetrics {
  total_events: number;
  critical_events: number;
  high_events: number;
  medium_events: number;
  low_events: number;
  events_today: number;
  open_incidents: number;
  top_source_ips: { ip: string; count: number; country?: string }[];
  top_target_assets: { asset: string; count: number }[];
  top_threat_categories: { category: ThreatCategory; count: number }[];
  severity_distribution: { name: string; count: number; color: string }[];
  events_over_time: { time: string; count: number; critical: number }[];
  attack_category_distribution: { category: string; count: number }[];
}
