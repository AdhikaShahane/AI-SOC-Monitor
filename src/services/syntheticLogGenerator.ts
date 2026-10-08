/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { SecurityEvent } from '../types/security';
import { detectionEngine } from './detectionEngine';

export function generateSyntheticSecurityLogs(): SecurityEvent[] {
  const baseTime = Date.now();
  const rawEvents: Partial<SecurityEvent>[] = [];

  // =========================================================================
  // SCENARIO 1: SSH Brute-Force Attempt (10 Failed + 2 Firewall drops)
  // Shared identifiers:
  // Source IP: 198.51.100.142 | Target Asset: jump-bastion-01 (10.0.1.10:22)
  // =========================================================================
  const bruteAccounts = ['root', 'admin', 'ubuntu', 'support', 'oracle', 'deploy', 'ansible', 'test', 'guest', 'svc_ssh'];
  const s1Start = baseTime - 45 * 60 * 1000;
  bruteAccounts.forEach((acc, i) => {
    rawEvents.push({
      event_id: `EVT-BF-${100 + i}`,
      timestamp: new Date(s1Start + i * 14000).toISOString(),
      source_ip: '198.51.100.142',
      destination_ip: '10.0.1.10',
      source_port: 43100 + i,
      destination_port: 22,
      protocol: 'SSH',
      device: 'dc-auth-01',
      device_type: 'Authentication',
      event_type: 'SSH Auth Failure',
      action: 'FAILURE',
      username: acc,
      asset: 'jump-bastion-01',
      message: `Failed password for invalid user ${acc} from 198.51.100.142 port ${43100 + i} ssh2`,
      bytes_transferred: 840,
      packets: 8,
      raw_payload: `sshd[${28000 + i}]: Failed password for invalid user ${acc} from 198.51.100.142 port ${43100 + i} ssh2`,
      status: 'OPEN',
    });
  });
  rawEvents.push({
    event_id: 'EVT-BF-110',
    timestamp: new Date(s1Start + 150000).toISOString(),
    source_ip: '198.51.100.142',
    destination_ip: '10.0.1.10',
    source_port: 43110,
    destination_port: 22,
    protocol: 'TCP',
    device: 'fw-edge-01',
    device_type: 'Firewall',
    event_type: 'Rate Limit Block',
    action: 'DROP',
    username: '-',
    asset: 'jump-bastion-01',
    message: 'Perimeter firewall rate-limiting drop: repeated SSH connection attempts from 198.51.100.142',
    bytes_transferred: 64,
    packets: 1,
    raw_payload: 'DROP IN=eth0 SRC=198.51.100.142 DST=10.0.1.10 PROTO=TCP DPT=22 FLAGS=SYN',
    status: 'OPEN',
  });

  // =========================================================================
  // SCENARIO 2: Failed Logins Followed by Successful Login (Credential Compromise)
  // Shared identifiers:
  // Source IP: 185.220.101.44 | Username: svc_jenkins_ci | Asset: corp-vpn-gw (10.0.1.5)
  // =========================================================================
  const s2Start = baseTime - 35 * 60 * 1000;
  [1, 2, 3].forEach((attempt) => {
    rawEvents.push({
      event_id: `EVT-SEQ-${200 + attempt}`,
      timestamp: new Date(s2Start + attempt * 25000).toISOString(),
      source_ip: '185.220.101.44',
      destination_ip: '10.0.1.5',
      source_port: 50400 + attempt,
      destination_port: 443,
      protocol: 'HTTPS',
      device: 'dc-auth-01',
      device_type: 'Authentication',
      event_type: 'VPN Auth Failure',
      action: 'FAILURE',
      username: 'svc_jenkins_ci',
      asset: 'corp-vpn-gw',
      message: `Failed RADIUS password challenge for user svc_jenkins_ci attempt #${attempt}`,
      bytes_transferred: 1200,
      packets: 10,
      raw_payload: `radiusd[1902]: Auth-Failure User=svc_jenkins_ci Client-IP=185.220.101.44 Reason=InvalidPassword`,
      status: 'OPEN',
    });
  });
  // Breakthrough SUCCESS
  rawEvents.push({
    event_id: 'EVT-SEQ-204',
    timestamp: new Date(s2Start + 110000).toISOString(),
    source_ip: '185.220.101.44',
    destination_ip: '10.0.1.5',
    source_port: 50404,
    destination_port: 443,
    protocol: 'HTTPS',
    device: 'dc-auth-01',
    device_type: 'Authentication',
    event_type: 'VPN Auth Success',
    action: 'SUCCESS',
    username: 'svc_jenkins_ci',
    asset: 'corp-vpn-gw',
    message: 'Successful authentication for svc_jenkins_ci from 185.220.101.44 after 3 failed attempts',
    bytes_transferred: 3200,
    packets: 18,
    raw_payload: `radiusd[1910]: Auth-Success User=svc_jenkins_ci Client-IP=185.220.101.44 Session=VPN_SEC_8892`,
    status: 'OPEN',
  });
  rawEvents.push({
    event_id: 'EVT-SEQ-205',
    timestamp: new Date(s2Start + 125000).toISOString(),
    source_ip: '185.220.101.44',
    destination_ip: '10.0.1.5',
    source_port: 50405,
    destination_port: 443,
    protocol: 'HTTPS',
    device: 'fw-edge-01',
    device_type: 'Firewall',
    event_type: 'VPN Session Established',
    action: 'ALLOW',
    username: 'svc_jenkins_ci',
    asset: 'corp-vpn-gw',
    message: 'SSL VPN tunnel established for user svc_jenkins_ci assigned internal VIP 10.0.50.88',
    bytes_transferred: 8400,
    packets: 45,
    raw_payload: 'VPN_TUNNEL_UP User=svc_jenkins_ci Assigned-IP=10.0.50.88 Remote-IP=185.220.101.44',
    status: 'OPEN',
  });

  // =========================================================================
  // SCENARIO 3: Port Scanning (Network Reconnaissance Sweep)
  // Shared identifiers:
  // Source IP: 203.0.113.77 | Target Assets: vpn-gateway-01 & dmz-web-app (10.0.1.50)
  // Targeted ports: 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 1433, 3306, 3389, 8080
  // =========================================================================
  const scanPorts = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 1433, 3306, 3389, 8080];
  const s3Start = baseTime - 28 * 60 * 1000;
  scanPorts.forEach((port, idx) => {
    rawEvents.push({
      event_id: `EVT-SCAN-${300 + idx}`,
      timestamp: new Date(s3Start + idx * 4500).toISOString(),
      source_ip: '203.0.113.77',
      destination_ip: '10.0.1.50',
      source_port: 59000 + idx,
      destination_port: port,
      protocol: 'TCP',
      device: 'fw-edge-01',
      device_type: 'Firewall',
      event_type: 'Firewall Drop',
      action: 'DROP',
      username: '-',
      asset: 'vpn-gateway-01',
      message: `Boundary firewall policy drop: TCP SYN probe to port ${port}`,
      bytes_transferred: 64,
      packets: 1,
      raw_payload: `DROP IN=eth0 SRC=203.0.113.77 DST=10.0.1.50 PROTO=TCP SPT=${59000 + idx} DPT=${port} FLAGS=SYN`,
      status: 'OPEN',
    });
  });
  // Correlated IDS alert
  rawEvents.push({
    event_id: 'EVT-SCAN-320',
    timestamp: new Date(s3Start + 65000).toISOString(),
    source_ip: '203.0.113.77',
    destination_ip: '10.0.1.50',
    source_port: 59014,
    destination_port: 8080,
    protocol: 'TCP',
    device: 'ids-core-01',
    device_type: 'IDS/IPS',
    event_type: 'Intrusion Alert',
    action: 'ALERT',
    username: '-',
    asset: 'vpn-gateway-01',
    message: 'ET SCAN Nmap Scripting Engine User-Agent / Multi-Port Sweep probe detected',
    bytes_transferred: 180,
    packets: 3,
    raw_payload: 'SURICATA ALERT [1:2000537:8] ET SCAN Nmap SYN scan sweep signature triggered',
    status: 'OPEN',
  });

  // =========================================================================
  // SCENARIO 4: Sudden Traffic Spike (SYN Flood / DDoS Anomaly)
  // Shared identifiers:
  // Source IP: 198.51.100.210 | Target Asset: edge-gateway-vip (198.51.100.1:443)
  // =========================================================================
  const s4Start = baseTime - 20 * 60 * 1000;
  [1, 2, 3, 4, 5].forEach((i) => {
    rawEvents.push({
      event_id: `EVT-DOS-${400 + i}`,
      timestamp: new Date(s4Start + i * 15000).toISOString(),
      source_ip: '198.51.100.210',
      destination_ip: '198.51.100.1',
      source_port: 39000 + i * 100,
      destination_port: 443,
      protocol: 'TCP',
      device: 'fw-edge-01',
      device_type: 'Firewall',
      event_type: 'Traffic Anomaly',
      action: 'DROP',
      username: '-',
      asset: 'edge-gateway-vip',
      message: `Volumetric TCP SYN flood surge detected on edge VIP: ${30000 + i * 3500} pkts/s`,
      bytes_transferred: 12500000 + i * 1500000,
      packets: 32000 + i * 3500,
      raw_payload: `RATE_LIMIT: TCP SYN flood burst dropped on interface eth0 dst=198.51.100.1:443 rate=${32000 + i * 3500}pps`,
      status: 'OPEN',
    });
  });

  // =========================================================================
  // SCENARIO 5: Suspicious Web Request (SQL Injection & Path Traversal)
  // Shared identifiers:
  // Source IP: 203.0.113.88 | Target Asset: dmz-ecommerce-web (10.0.1.50:443)
  // =========================================================================
  const s5Start = baseTime - 15 * 60 * 1000;
  const webAttacks = [
    {
      uri: "/products?cat=1' UNION SELECT username,password_hash FROM users-- -",
      payload: "GET /products?cat=1'%20UNION%20SELECT%20username,password_hash%20FROM%20users-- HTTP/1.1",
      msg: 'WAF SQLi match: UNION SELECT query injection in URI parameters',
    },
    {
      uri: "/api/login with payload username=' OR '1'='1' --",
      payload: "POST /api/login HTTP/1.1 payload: username=' OR 1=1--&pwd=xxx",
      msg: 'WAF SQLi match: Boolean tautology authentication bypass string in POST payload',
    },
    {
      uri: "/download?file=../../../../etc/passwd",
      payload: "GET /download?file=../../../../etc/passwd HTTP/1.1",
      msg: 'WAF Path Traversal match: Directory traversal probe to /etc/passwd',
    },
    {
      uri: "/search?term='; EXEC xp_cmdshell('whoami');--",
      payload: "GET /search?term=';%20EXEC%20xp_cmdshell('whoami');-- HTTP/1.1",
      msg: 'WAF Exploit match: Database shell execution xp_cmdshell attempt',
    },
  ];

  webAttacks.forEach((atk, idx) => {
    rawEvents.push({
      event_id: `EVT-WEB-${500 + idx}`,
      timestamp: new Date(s5Start + idx * 30000).toISOString(),
      source_ip: '203.0.113.88',
      destination_ip: '10.0.1.50',
      source_port: 52140 + idx,
      destination_port: 443,
      protocol: 'HTTPS',
      device: 'waf-dmz-ingress',
      device_type: 'Web Server',
      event_type: 'HTTP Request',
      action: 'ALERT',
      username: 'guest_session',
      asset: 'dmz-ecommerce-web',
      message: atk.msg,
      bytes_transferred: 3400 + idx * 200,
      packets: 24,
      raw_payload: atk.payload,
      status: 'OPEN',
    });
  });

  // Correlated IDS alert for SQLi
  rawEvents.push({
    event_id: 'EVT-WEB-510',
    timestamp: new Date(s5Start + 35000).toISOString(),
    source_ip: '203.0.113.88',
    destination_ip: '10.0.1.50',
    source_port: 52140,
    destination_port: 443,
    protocol: 'TCP',
    device: 'ids-core-01',
    device_type: 'IDS/IPS',
    event_type: 'Intrusion Signature Alert',
    action: 'ALERT',
    username: '-',
    asset: 'dmz-ecommerce-web',
    message: 'ET WEB_SPECIFIC_APPS SQL Injection Union Select keyword detected in HTTP URI',
    bytes_transferred: 4200,
    packets: 30,
    raw_payload: 'SURICATA ALERT [1:2018402:4] ET WEB_SPECIFIC_APPS SQL Injection Attempt - Union Select',
    status: 'OPEN',
  });

  // =========================================================================
  // SCENARIO 6: Suspicious Outbound Connection (C2 Port & High Volume Exfil)
  // Shared identifiers:
  // Source IP: 10.0.4.82 (workstation-fin-09) | Destination: 198.51.100.200:8443
  // =========================================================================
  const s6Start = baseTime - 12 * 60 * 1000;
  rawEvents.push({
    event_id: 'EVT-OUT-601',
    timestamp: new Date(s6Start).toISOString(),
    source_ip: '10.0.4.82',
    destination_ip: '198.51.100.200',
    source_port: 51204,
    destination_port: 8443,
    protocol: 'TCP',
    device: 'zeek-netflow-01',
    device_type: 'Network Flow',
    event_type: 'Flow Anomaly',
    action: 'ALLOW',
    username: 'sarah.jenkins',
    asset: 'workstation-fin-09',
    message: 'Persistent outbound TCP session established to external IP 198.51.100.200:8443 volume 18.4MB',
    bytes_transferred: 19293798, // ~18.4 MB
    packets: 14800,
    raw_payload: 'FLOW_ESTABLISHED src=10.0.4.82:51204 dst=198.51.100.200:8443 tx_bytes=19293798 rx_bytes=48000 state=ESTABLISHED',
    status: 'OPEN',
  });
  rawEvents.push({
    event_id: 'EVT-OUT-602',
    timestamp: new Date(s6Start + 45000).toISOString(),
    source_ip: '10.0.4.82',
    destination_ip: '198.51.100.200',
    source_port: 51210,
    destination_port: 4444,
    protocol: 'TCP',
    device: 'fw-edge-01',
    device_type: 'Firewall',
    event_type: 'Outbound Egress Block',
    action: 'BLOCK',
    username: 'sarah.jenkins',
    asset: 'workstation-fin-09',
    message: 'Firewall egress block rule: Unauthorized connection attempt on suspicious port 4444 to 198.51.100.200',
    bytes_transferred: 120,
    packets: 2,
    raw_payload: 'BLOCK OUT src=10.0.4.82:51210 dst=198.51.100.200:4444 rule=Block_Malicious_C2_Ports',
    status: 'OPEN',
  });

  // =========================================================================
  // SCENARIO 7: Privilege Escalation Indicator
  // Shared identifiers:
  // Source IP: 10.0.1.10 | Target Asset: jump-bastion-01 | Username: svc_deploy
  // =========================================================================
  const s7Start = baseTime - 8 * 60 * 1000;
  rawEvents.push({
    event_id: 'EVT-PRIV-701',
    timestamp: new Date(s7Start).toISOString(),
    source_ip: '10.0.1.10',
    destination_ip: '10.0.1.10',
    source_port: 0,
    destination_port: 0,
    protocol: 'SSH',
    device: 'jump-bastion-01',
    device_type: 'Authentication',
    event_type: 'Privilege Escalation Event',
    action: 'ALERT',
    username: 'svc_deploy',
    asset: 'jump-bastion-01',
    message: 'sudo su - executed by user svc_deploy: process elevated to root privileges in /bin/bash',
    bytes_transferred: 0,
    packets: 0,
    raw_payload: 'sudo: svc_deploy : TTY=pts/3 ; PWD=/home/svc_deploy ; USER=root ; COMMAND=/bin/su -',
    status: 'OPEN',
  });
  rawEvents.push({
    event_id: 'EVT-PRIV-702',
    timestamp: new Date(s7Start + 15000).toISOString(),
    source_ip: '10.0.1.10',
    destination_ip: '10.0.1.10',
    source_port: 0,
    destination_port: 0,
    protocol: 'SSH',
    device: 'jump-bastion-01',
    device_type: 'Authentication',
    event_type: 'Security File Access',
    action: 'ALERT',
    username: 'root',
    asset: 'jump-bastion-01',
    message: 'Write access to /etc/sudoers.d/custom by UID 0 (root)',
    bytes_transferred: 0,
    packets: 0,
    raw_payload: 'AUDIT_SYSCALL: arch=x86_64 syscall=openat success=yes exe="/usr/bin/nano" path="/etc/sudoers.d/custom"',
    status: 'OPEN',
  });

  // =========================================================================
  // SCENARIO 8: Completely Normal Business Traffic (~480 Events)
  // Distributed across: Firewall (120), IDS/IPS (80), Auth (100), Web Server (100), Network Flow (80)
  // Realistic subnets, usernames, corporate domain lookups, and baseline metrics
  // =========================================================================
  const corpUsers = [
    'alex.turner', 'david.kim', 'elena.rostova', 'rachel.green',
    'michael.scott', 'jim.halpert', 'pam.beesly', 'dwight.schrute',
    'kevin.malone', 'angela.martin', 'oscar.martinez', 'stanley.hudson'
  ];

  const internalWorkstations = [
    'workstation-eng-01', 'workstation-eng-02', 'workstation-eng-03',
    'workstation-mkt-01', 'workstation-mkt-02', 'workstation-mkt-03',
    'workstation-fin-01', 'workstation-fin-02', 'workstation-hr-01',
    'workstation-exec-01', 'corp-build-node-01', 'corp-build-node-02'
  ];

  const externalSaasDomains = [
    { domain: 'github.com', ip: '140.82.112.4', port: 443 },
    { domain: 'microsoft365.com', ip: '52.96.166.130', port: 443 },
    { domain: 'slack.com', ip: '54.192.18.99', port: 443 },
    { domain: 'aws.amazon.com', ip: '52.216.230.12', port: 443 },
    { domain: 'google.com', ip: '142.250.190.46', port: 443 },
  ];

  let eventCounter = 1000;

  // 1. Normal Firewall Telemetry (120 events)
  for (let i = 0; i < 120; i++) {
    const user = corpUsers[i % corpUsers.length];
    const asset = internalWorkstations[i % internalWorkstations.length];
    const saas = externalSaasDomains[i % externalSaasDomains.length];
    const internalIp = `10.0.2.${20 + (i % 80)}`;
    const timeOffset = baseTime - (120 - i) * 28000;

    rawEvents.push({
      event_id: `EVT-FW-NORM-${eventCounter++}`,
      timestamp: new Date(timeOffset).toISOString(),
      source_ip: internalIp,
      destination_ip: saas.ip,
      source_port: 48000 + (i * 17) % 15000,
      destination_port: saas.port,
      protocol: 'HTTPS',
      device: 'fw-edge-01',
      device_type: 'Firewall',
      event_type: 'Web Traffic',
      action: 'ALLOW',
      username: user,
      asset,
      message: `Standard outbound HTTPS connection to ${saas.domain}`,
      bytes_transferred: Math.floor(2500 + (i * 311) % 45000),
      packets: Math.floor(12 + (i * 7) % 60),
      raw_payload: `TCP ESTABLISHED src=${internalIp} dst=${saas.ip}:${saas.port} proto=tcp app=ssl user=${user}`,
      status: 'OPEN',
    });
  }

  // 2. Normal IDS / IPS Telemetry (80 events)
  for (let i = 0; i < 80; i++) {
    const internalIp = `10.0.3.${10 + (i % 40)}`;
    const timeOffset = baseTime - (80 - i) * 42000;
    const destPort = i % 2 === 0 ? 443 : 80;

    rawEvents.push({
      event_id: `EVT-IDS-NORM-${eventCounter++}`,
      timestamp: new Date(timeOffset).toISOString(),
      source_ip: internalIp,
      destination_ip: '10.0.0.2',
      source_port: 52000 + (i * 13) % 10000,
      destination_port: destPort,
      protocol: destPort === 443 ? 'HTTPS' : 'HTTP',
      device: 'ids-core-01',
      device_type: 'IDS/IPS',
      event_type: 'Protocol Inspection',
      action: 'ALLOW',
      username: '-',
      asset: 'corp-cluster-core',
      message: 'Suricata protocol inspection: Standard TLS 1.3 handshake verified without anomaly',
      bytes_transferred: Math.floor(1800 + (i * 240) % 12000),
      packets: Math.floor(8 + (i * 3) % 25),
      raw_payload: `SURICATA INFO [1:2000001:1] Protocol TLSv1.3 Negotiation verified ALPN=h2`,
      status: 'OPEN',
    });
  }

  // 3. Normal Authentication Telemetry (100 events)
  for (let i = 0; i < 100; i++) {
    const user = corpUsers[i % corpUsers.length];
    const asset = internalWorkstations[i % internalWorkstations.length];
    const internalIp = `10.0.2.${15 + (i % 70)}`;
    const timeOffset = baseTime - (100 - i) * 35000;

    rawEvents.push({
      event_id: `EVT-AUTH-NORM-${eventCounter++}`,
      timestamp: new Date(timeOffset).toISOString(),
      source_ip: internalIp,
      destination_ip: '10.0.0.5',
      source_port: 54000 + (i * 29) % 10000,
      destination_port: 443,
      protocol: 'HTTPS',
      device: 'dc-auth-01',
      device_type: 'Authentication',
      event_type: 'SSO Login',
      action: 'SUCCESS',
      username: user,
      asset: 'corp-idp-01',
      message: `Successful SAML SSO authentication for ${user} with hardware token verification`,
      bytes_transferred: Math.floor(3200 + (i * 80) % 4000),
      packets: 16,
      raw_payload: `SAML_RESPONSE Status=SUCCESS User=${user}@corp.net Client-IP=${internalIp} MFA=YubiKey_Approved`,
      status: 'OPEN',
    });
  }

  // 4. Normal Web Server Telemetry (100 events)
  const commonWebUris = [
    { path: '/', status: 200 },
    { path: '/static/app.bundle.js', status: 200 },
    { path: '/static/theme.css', status: 304 },
    { path: '/api/v1/healthz', status: 200 },
    { path: '/favicon.ico', status: 200 },
    { path: '/dashboard', status: 200 },
    { path: '/api/v1/user/profile', status: 200 },
    { path: '/api/v1/notifications', status: 200 },
  ];

  for (let i = 0; i < 100; i++) {
    const uriObj = commonWebUris[i % commonWebUris.length];
    const timeOffset = baseTime - (100 - i) * 32000;
    const clientIp = `192.168.10.${10 + (i % 90)}`;

    rawEvents.push({
      event_id: `EVT-WEB-NORM-${eventCounter++}`,
      timestamp: new Date(timeOffset).toISOString(),
      source_ip: clientIp,
      destination_ip: '10.0.1.50',
      source_port: 41000 + (i * 33) % 20000,
      destination_port: 443,
      protocol: 'HTTPS',
      device: 'waf-dmz-ingress',
      device_type: 'Web Server',
      event_type: 'HTTP Access',
      action: 'ALLOW',
      username: `user_${(i % 15) + 1}`,
      asset: 'dmz-ecommerce-web',
      message: `HTTP GET ${uriObj.path} status ${uriObj.status}`,
      bytes_transferred: Math.floor(1400 + (i * 120) % 18000),
      packets: Math.floor(8 + (i * 2) % 20),
      raw_payload: `GET ${uriObj.path} HTTP/2.0 Status=${uriObj.status} User-Agent="Mozilla/5.0 Chrome/128.0"`,
      status: 'OPEN',
    });
  }

  // 5. Normal Network Traffic / Flow Telemetry (80 events)
  for (let i = 0; i < 80; i++) {
    const internalSrc = `10.0.1.${40 + (i % 20)}`;
    const timeOffset = baseTime - (80 - i) * 44000;
    const isDb = i % 2 === 0;

    rawEvents.push({
      event_id: `EVT-FLOW-NORM-${eventCounter++}`,
      timestamp: new Date(timeOffset).toISOString(),
      source_ip: internalSrc,
      destination_ip: isDb ? '10.0.3.15' : '10.0.0.2',
      source_port: 49000 + (i * 19) % 15000,
      destination_port: isDb ? 5432 : 53,
      protocol: isDb ? 'TCP' : 'DNS',
      device: 'zeek-netflow-01',
      device_type: 'Network Flow',
      event_type: isDb ? 'Database Connection' : 'DNS Resolution',
      action: 'ALLOW',
      username: isDb ? 'db_app_user' : '-',
      asset: isDb ? 'prod-db-cluster' : 'corp-dns-resolver',
      message: isDb
        ? 'Internal database connection pool session to PostgreSQL port 5432'
        : 'Internal DNS resolution query for corp-idp.internal.net',
      bytes_transferred: Math.floor(3500 + (i * 450) % 85000),
      packets: Math.floor(18 + (i * 4) % 90),
      raw_payload: isDb
        ? 'FLOW src=10.0.1.40:49182 dst=10.0.3.15:5432 proto=tcp state=ESTABLISHED'
        : 'DNS_REQ type=A domain=corp-idp.internal.net reply=10.0.0.5',
      status: 'OPEN',
    });
  }

  // Run all raw events through our deterministic detection engine!
  const processedEvents: SecurityEvent[] = [];
  for (const raw of rawEvents) {
    const fullEvent: SecurityEvent = {
      event_id: raw.event_id || `EVT-${Math.floor(1000 + Math.random() * 9000)}`,
      timestamp: raw.timestamp || new Date().toISOString(),
      source_ip: raw.source_ip || '192.168.1.100',
      destination_ip: raw.destination_ip || '10.0.0.1',
      source_port: raw.source_port || 49152,
      destination_port: raw.destination_port || 80,
      protocol: raw.protocol || 'TCP',
      device: raw.device || 'fw-edge-01',
      device_type: raw.device_type || 'Firewall',
      event_type: raw.event_type || 'Generic Event',
      action: raw.action || 'ALLOW',
      username: raw.username || '-',
      asset: raw.asset || 'corp-gateway',
      message: raw.message || 'System log event',
      severity: raw.severity || 'INFORMATIONAL',
      risk_score: raw.risk_score || 10,
      detection_method: 'RULE',
      status: raw.status || 'OPEN',
      threat_category: raw.threat_category || 'Normal Activity',
      raw_payload: raw.raw_payload || '',
      bytes_transferred: raw.bytes_transferred || 0,
      packets: raw.packets || 0,
    };

    const evaluated = detectionEngine.processEvent(fullEvent, processedEvents);
    processedEvents.push(evaluated);
  }

  // Sort chronological by timestamp
  return processedEvents.sort(
    (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
  );
}

export function generateRandomStreamEvent(existingEvents: SecurityEvent[]): SecurityEvent {
  const templates = [
    {
      source_ip: '198.51.100.99',
      destination_ip: '10.0.1.50',
      source_port: Math.floor(40000 + Math.random() * 20000),
      destination_port: 443,
      protocol: 'HTTPS',
      device: 'waf-dmz-ingress',
      device_type: 'Web Server' as const,
      event_type: 'HTTP Request',
      action: 'ALERT' as const,
      username: '-',
      asset: 'dmz-ecommerce-web',
      message: "HTTP POST /api/login with payload ' OR '1'='1' --",
      raw_payload: "POST /api/login HTTP/1.1 payload: username=' OR 1=1--&pwd=xxx",
    },
    {
      source_ip: '198.51.100.142',
      destination_ip: '10.0.1.10',
      source_port: Math.floor(40000 + Math.random() * 20000),
      destination_port: 22,
      protocol: 'SSH',
      device: 'dc-auth-01',
      device_type: 'Authentication' as const,
      event_type: 'SSH Auth Failure',
      action: 'FAILURE' as const,
      username: 'oracle',
      asset: 'jump-bastion-01',
      message: 'Failed password for invalid user oracle from 198.51.100.142',
      raw_payload: 'sshd: Failed password for oracle from 198.51.100.142 port 55432 ssh2',
    },
    {
      source_ip: '10.0.2.45',
      destination_ip: '142.250.190.46',
      source_port: Math.floor(50000 + Math.random() * 10000),
      destination_port: 443,
      protocol: 'HTTPS',
      device: 'fw-edge-01',
      device_type: 'Firewall' as const,
      event_type: 'Web Traffic',
      action: 'ALLOW' as const,
      username: 'alex.turner',
      asset: 'workstation-eng-01',
      message: 'Standard outbound HTTPS request to google.com',
      raw_payload: 'TCP ESTABLISHED 10.0.2.45 -> 142.250.190.46:443',
    },
    {
      source_ip: '10.0.4.82',
      destination_ip: '198.51.100.200',
      source_port: 54100,
      destination_port: 4444,
      protocol: 'TCP',
      device: 'fw-edge-01',
      device_type: 'Firewall' as const,
      event_type: 'Outbound Egress Block',
      action: 'BLOCK' as const,
      username: 'sarah.jenkins',
      asset: 'workstation-fin-09',
      message: 'Firewall blocked outbound connection on suspicious port 4444 to 198.51.100.200',
      raw_payload: 'BLOCK OUT src=10.0.4.82:54100 dst=198.51.100.200:4444',
    },
    {
      source_ip: '10.0.3.12',
      destination_ip: '10.0.0.2',
      source_port: 53120,
      destination_port: 53,
      protocol: 'DNS',
      device: 'fw-edge-01',
      device_type: 'Network Flow' as const,
      event_type: 'DNS Query',
      action: 'ALLOW' as const,
      username: '-',
      asset: 'prod-db-cluster',
      message: 'Internal reverse DNS lookup for 10.0.1.50',
      raw_payload: 'DNS_REQ type=PTR query=50.1.0.10.in-addr.arpa resolver=10.0.0.2',
    },
  ];

  const pick = templates[Math.floor(Math.random() * templates.length)];
  const rawEvent: SecurityEvent = {
    event_id: `EVT-${Math.floor(2000 + Math.random() * 8000)}`,
    timestamp: new Date().toISOString(),
    source_ip: pick.source_ip,
    destination_ip: pick.destination_ip,
    source_port: pick.source_port,
    destination_port: pick.destination_port,
    protocol: pick.protocol,
    device: pick.device,
    device_type: pick.device_type,
    event_type: pick.event_type,
    action: pick.action,
    username: pick.username,
    asset: pick.asset,
    message: pick.message,
    severity: 'INFORMATIONAL',
    risk_score: 10,
    detection_method: 'RULE',
    status: 'OPEN',
    threat_category: 'Normal Activity',
    raw_payload: pick.raw_payload,
    bytes_transferred: Math.floor(100 + Math.random() * 2500),
    packets: Math.floor(2 + Math.random() * 15),
  };

  return detectionEngine.processEvent(rawEvent, existingEvents);
}
