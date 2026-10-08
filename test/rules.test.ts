/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import {
  evaluateBruteForce,
  evaluatePortScan,
  evaluateSuspiciousAuth,
  evaluateTrafficAnomaly,
  evaluateSuspiciousWebRequest,
  evaluateSuspiciousOutbound,
  evaluatePrivilegeEscalation,
  ModularDetectionEngine,
} from '../src/services/detectionEngine';
import { DEFAULT_ENGINE_CONFIG } from '../src/types/detection';
import { SecurityEvent } from '../src/types/security';

function assert(condition: boolean, msg: string) {
  if (!condition) {
    throw new Error(`Assertion failed: ${msg}`);
  }
}

console.log('--- Testing SentinelAI Deterministic Rules Engine ---');

// Test 1: Brute Force
{
  const events: SecurityEvent[] = [
    {
      event_id: 'BF-1',
      timestamp: new Date(Date.now() - 60000).toISOString(),
      source_ip: '198.51.100.5',
      destination_ip: '10.0.1.10',
      source_port: 50001,
      destination_port: 22,
      protocol: 'SSH',
      device: 'dc-auth',
      device_type: 'Authentication',
      event_type: 'Auth Failure',
      action: 'FAILURE',
      username: 'root',
      asset: 'bastion',
      message: 'Failed auth for root',
      severity: 'INFORMATIONAL',
      risk_score: 10,
      detection_method: 'RULE',
      status: 'OPEN',
      threat_category: 'Normal Activity',
    },
    {
      event_id: 'BF-2',
      timestamp: new Date(Date.now() - 40000).toISOString(),
      source_ip: '198.51.100.5',
      destination_ip: '10.0.1.10',
      source_port: 50002,
      destination_port: 22,
      protocol: 'SSH',
      device: 'dc-auth',
      device_type: 'Authentication',
      event_type: 'Auth Failure',
      action: 'FAILURE',
      username: 'admin',
      asset: 'bastion',
      message: 'Failed auth for admin',
      severity: 'INFORMATIONAL',
      risk_score: 10,
      detection_method: 'RULE',
      status: 'OPEN',
      threat_category: 'Normal Activity',
    },
    {
      event_id: 'BF-3',
      timestamp: new Date(Date.now() - 20000).toISOString(),
      source_ip: '198.51.100.5',
      destination_ip: '10.0.1.10',
      source_port: 50003,
      destination_port: 22,
      protocol: 'SSH',
      device: 'dc-auth',
      device_type: 'Authentication',
      event_type: 'Auth Failure',
      action: 'FAILURE',
      username: 'support',
      asset: 'bastion',
      message: 'Failed auth for support',
      severity: 'INFORMATIONAL',
      risk_score: 10,
      detection_method: 'RULE',
      status: 'OPEN',
      threat_category: 'Normal Activity',
    },
  ];

  const detections = evaluateBruteForce(events, DEFAULT_ENGINE_CONFIG.bruteForce);
  assert(detections.length === 1, 'Should detect 1 brute force sequence');
  assert(detections[0].category === 'Brute Force', 'Category must be Brute Force');
  assert(detections[0].source_ip === '198.51.100.5', 'Source IP should match');
  assert(detections[0].affected_accounts?.includes('root') ?? false, 'Should include root account');
  console.log('✓ Rule 1 (Brute Force): Passed');
}

// Test 2: Port Scan
{
  const now = Date.now();
  const scanPorts = [21, 22, 80, 443, 8080];
  const events: SecurityEvent[] = scanPorts.map((port, i) => ({
    event_id: `SCAN-${i}`,
    timestamp: new Date(now + i * 1000).toISOString(),
    source_ip: '203.0.113.99',
    destination_ip: '10.0.1.50',
    source_port: 40000 + i,
    destination_port: port,
    protocol: 'TCP',
    device: 'fw-edge',
    device_type: 'Firewall',
    event_type: 'Drop',
    action: 'DROP',
    username: '-',
    asset: 'web-srv',
    message: `Drop port ${port}`,
    severity: 'INFORMATIONAL',
    risk_score: 10,
    detection_method: 'RULE',
    status: 'OPEN',
    threat_category: 'Normal Activity',
  }));

  const detections = evaluatePortScan(events, DEFAULT_ENGINE_CONFIG.portScan);
  assert(detections.length === 1, 'Should detect 1 port scan');
  assert(detections[0].category === 'Port Scanning', 'Category must be Port Scanning');
  assert(detections[0].source_ip === '203.0.113.99', 'Source IP should match');
  assert(detections[0].targeted_ports?.length === 5, 'Should record all 5 ports');
  console.log('✓ Rule 2 (Port Scan): Passed');
}

// Test 3: Suspicious Authentication
{
  const now = Date.now();
  const events: SecurityEvent[] = [
    {
      event_id: 'AUTH-F1',
      timestamp: new Date(now - 30000).toISOString(),
      source_ip: '185.220.101.44',
      destination_ip: '10.0.1.5',
      source_port: 50001,
      destination_port: 443,
      protocol: 'HTTPS',
      device: 'dc-auth',
      device_type: 'Authentication',
      event_type: 'Login',
      action: 'FAILURE',
      username: 'jdoe',
      asset: 'vpn',
      message: 'Failed login',
      severity: 'INFORMATIONAL',
      risk_score: 10,
      detection_method: 'RULE',
      status: 'OPEN',
      threat_category: 'Normal Activity',
    },
    {
      event_id: 'AUTH-F2',
      timestamp: new Date(now - 20000).toISOString(),
      source_ip: '185.220.101.44',
      destination_ip: '10.0.1.5',
      source_port: 50002,
      destination_port: 443,
      protocol: 'HTTPS',
      device: 'dc-auth',
      device_type: 'Authentication',
      event_type: 'Login',
      action: 'FAILURE',
      username: 'jdoe',
      asset: 'vpn',
      message: 'Failed login',
      severity: 'INFORMATIONAL',
      risk_score: 10,
      detection_method: 'RULE',
      status: 'OPEN',
      threat_category: 'Normal Activity',
    },
    {
      event_id: 'AUTH-S1',
      timestamp: new Date(now - 5000).toISOString(),
      source_ip: '185.220.101.44',
      destination_ip: '10.0.1.5',
      source_port: 50003,
      destination_port: 443,
      protocol: 'HTTPS',
      device: 'dc-auth',
      device_type: 'Authentication',
      event_type: 'Login',
      action: 'SUCCESS',
      username: 'jdoe',
      asset: 'vpn',
      message: 'Success login after failures',
      severity: 'INFORMATIONAL',
      risk_score: 10,
      detection_method: 'RULE',
      status: 'OPEN',
      threat_category: 'Normal Activity',
    },
  ];

  const detections = evaluateSuspiciousAuth(events, DEFAULT_ENGINE_CONFIG.suspiciousAuthSequence);
  assert(detections.length === 1, 'Should detect suspicious authentication breakthrough');
  assert(detections[0].category === 'Suspicious Authentication', 'Category must be Suspicious Authentication');
  assert(detections[0].affected_username === 'jdoe', 'Target user must be jdoe');
  console.log('✓ Rule 3 (Suspicious Auth Breakthrough): Passed');
}

// Test 4: Traffic Anomaly
{
  const events: SecurityEvent[] = [
    {
      event_id: 'DOS-1',
      timestamp: new Date().toISOString(),
      source_ip: '198.51.100.210',
      destination_ip: '198.51.100.1',
      source_port: 39000,
      destination_port: 443,
      protocol: 'TCP',
      device: 'fw-edge',
      device_type: 'Firewall',
      event_type: 'Traffic',
      action: 'DROP',
      username: '-',
      asset: 'edge-vip',
      message: 'Volumetric TCP SYN flood surge detected on edge VIP: 35000 pkts/s',
      bytes_transferred: 15000000,
      packets: 35000,
      raw_payload: 'RATE_LIMIT flood',
      severity: 'INFORMATIONAL',
      risk_score: 10,
      detection_method: 'RULE',
      status: 'OPEN',
      threat_category: 'Normal Activity',
    },
  ];

  const detections = evaluateTrafficAnomaly(events, DEFAULT_ENGINE_CONFIG.trafficAnomaly);
  assert(detections.length === 1, 'Should detect traffic surge');
  assert(detections[0].category === 'DDoS/Traffic Anomaly', 'Category must be DDoS/Traffic Anomaly');
  assert(detections[0].affected_asset === 'edge-vip', 'Asset must match');
  console.log('✓ Rule 4 (Traffic Anomaly): Passed');
}

// Test 5: Suspicious Web Request
{
  const events: SecurityEvent[] = [
    {
      event_id: 'SQLI-1',
      timestamp: new Date().toISOString(),
      source_ip: '203.0.113.88',
      destination_ip: '10.0.1.50',
      source_port: 52140,
      destination_port: 443,
      protocol: 'HTTPS',
      device: 'waf',
      device_type: 'Web Server',
      event_type: 'HTTP Request',
      action: 'ALERT',
      username: '-',
      asset: 'ecommerce-web',
      message: "WAF SQLi match: UNION SELECT query injection in URI parameters",
      raw_payload: "GET /products?cat=1' UNION SELECT username,password_hash FROM users-- HTTP/1.1",
      severity: 'INFORMATIONAL',
      risk_score: 10,
      detection_method: 'RULE',
      status: 'OPEN',
      threat_category: 'Normal Activity',
    },
  ];

  const detections = evaluateSuspiciousWebRequest(events, DEFAULT_ENGINE_CONFIG.suspiciousWebRequest);
  assert(detections.length === 1, 'Should detect suspicious web request');
  assert(detections[0].category === 'SQL Injection Attempt', 'Category must be SQL Injection Attempt');
  console.log('✓ Rule 5 (Suspicious Web Request): Passed');
}

// Test 6: Suspicious Outbound Connection
{
  const events: SecurityEvent[] = [
    {
      event_id: 'OUT-1',
      timestamp: new Date().toISOString(),
      source_ip: '10.0.4.82',
      destination_ip: '198.51.100.200',
      source_port: 51210,
      destination_port: 4444,
      protocol: 'TCP',
      device: 'fw-edge',
      device_type: 'Firewall',
      event_type: 'Egress Block',
      action: 'BLOCK',
      username: 'sarah.jenkins',
      asset: 'workstation-fin-09',
      message: 'Firewall egress block rule: Unauthorized connection attempt on suspicious port 4444',
      raw_payload: 'BLOCK OUT src=10.0.4.82:51210 dst=198.51.100.200:4444',
      bytes_transferred: 120,
      packets: 2,
      severity: 'INFORMATIONAL',
      risk_score: 10,
      detection_method: 'RULE',
      status: 'OPEN',
      threat_category: 'Normal Activity',
    },
  ];

  const detections = evaluateSuspiciousOutbound(events, DEFAULT_ENGINE_CONFIG.suspiciousOutbound);
  assert(detections.length === 1, 'Should detect suspicious outbound connection');
  assert(detections[0].source_ip === '10.0.4.82', 'Internal source IP should match');
  assert(detections[0].destination_ip === '198.51.100.200', 'External destination IP should match');
  console.log('✓ Rule 6 (Suspicious Outbound Connection): Passed');
}

// Test 7: Privilege Escalation
{
  const events: SecurityEvent[] = [
    {
      event_id: 'PRIV-1',
      timestamp: new Date().toISOString(),
      source_ip: '10.0.1.10',
      destination_ip: '10.0.1.10',
      source_port: 0,
      destination_port: 0,
      protocol: 'SSH',
      device: 'bastion',
      device_type: 'Authentication',
      event_type: 'Privilege Escalation Event',
      action: 'ALERT',
      username: 'svc_deploy',
      asset: 'jump-bastion-01',
      message: 'sudo su - executed by user svc_deploy: process elevated to root privileges in /bin/bash',
      raw_payload: 'sudo: svc_deploy : TTY=pts/3 ; PWD=/home/svc_deploy ; USER=root ; COMMAND=/bin/su -',
      severity: 'INFORMATIONAL',
      risk_score: 10,
      detection_method: 'RULE',
      status: 'OPEN',
      threat_category: 'Normal Activity',
    },
  ];

  const detections = evaluatePrivilegeEscalation(events, DEFAULT_ENGINE_CONFIG.privilegeEscalation);
  assert(detections.length === 1, 'Should detect privilege escalation indicator');
  assert(detections[0].category === 'Privilege Escalation', 'Category must be Privilege Escalation');
  assert(detections[0].affected_username === 'svc_deploy', 'User must be svc_deploy');
  console.log('✓ Rule 7 (Privilege Escalation): Passed');
}

// Test Modular Detection Engine Integration
{
  const engine = new ModularDetectionEngine();
  const testEvent: SecurityEvent = {
    event_id: 'EVT-TEST-1',
    timestamp: new Date().toISOString(),
    source_ip: '198.51.100.99',
    destination_ip: '10.0.1.50',
    source_port: 45000,
    destination_port: 443,
    protocol: 'HTTPS',
    device: 'waf',
    device_type: 'Web Server',
    event_type: 'HTTP Request',
    action: 'ALERT',
    username: '-',
    asset: 'web-srv',
    message: "WAF SQLi match: ' OR '1'='1' --",
    raw_payload: "POST /login payload: username=' OR 1=1--",
    severity: 'INFORMATIONAL',
    risk_score: 10,
    detection_method: 'RULE',
    status: 'OPEN',
    threat_category: 'Normal Activity',
  };

  const processed = engine.processEvent(testEvent);
  assert(processed.threat_category === 'SQL Injection Attempt', 'Threat category should be updated');
  assert(processed.severity === 'HIGH', 'Severity should be upgraded to HIGH');
  assert(processed.risk_score >= 80, 'Risk score should reflect detection');
  console.log('✓ ModularDetectionEngine integration test: Passed');
}

console.log('\nAll 7 Deterministic Security Detection Rules Passed Successfully!\n');
