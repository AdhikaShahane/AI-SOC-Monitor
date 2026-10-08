/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { Incident, SecurityEvent, SOCMetrics, ThreatCategory } from '../types/security';

export function calculateSOCMetrics(events: SecurityEvent[], incidents: Incident[]): SOCMetrics {
  const total_events = events.length;
  let critical_events = 0;
  let high_events = 0;
  let medium_events = 0;
  let low_events = 0;

  const todayStr = new Date().toISOString().slice(0, 10);
  let events_today = 0;

  const sourceIpCount = new Map<string, number>();
  const assetCount = new Map<string, number>();
  const categoryCount = new Map<ThreatCategory, number>();

  for (const e of events) {
    if (e.severity === 'CRITICAL') critical_events++;
    else if (e.severity === 'HIGH') high_events++;
    else if (e.severity === 'MEDIUM') medium_events++;
    else if (e.severity === 'LOW') low_events++;

    if (e.timestamp && e.timestamp.startsWith(todayStr)) {
      events_today++;
    }

    if (e.source_ip && e.source_ip !== '-') {
      sourceIpCount.set(e.source_ip, (sourceIpCount.get(e.source_ip) || 0) + 1);
    }

    if (e.asset && e.asset !== '-') {
      assetCount.set(e.asset, (assetCount.get(e.asset) || 0) + 1);
    }

    if (e.threat_category) {
      categoryCount.set(e.threat_category, (categoryCount.get(e.threat_category) || 0) + 1);
    }
  }

  // Top source IPs
  const top_source_ips = Array.from(sourceIpCount.entries())
    .map(([ip, count]) => ({ ip, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 5);

  // Top targeted assets
  const top_target_assets = Array.from(assetCount.entries())
    .map(([asset, count]) => ({ asset, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 5);

  // Top threat categories
  const top_threat_categories = Array.from(categoryCount.entries())
    .map(([category, count]) => ({ category, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 6);

  // Severity distribution
  const severity_distribution = [
    { name: 'CRITICAL', count: critical_events, color: '#ef4444' },
    { name: 'HIGH', count: high_events, color: '#f59e0b' },
    { name: 'MEDIUM', count: medium_events, color: '#eab308' },
    { name: 'LOW', count: low_events, color: '#38bdf8' },
    { name: 'INFORMATIONAL', count: total_events - critical_events - high_events - medium_events - low_events, color: '#64748b' },
  ];

  // Events over time (bucket by 10 minute intervals or chronological bins)
  const timeBins = new Map<string, { count: number; critical: number }>();
  const sorted = [...events].sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
  
  for (const e of sorted) {
    const d = new Date(e.timestamp);
    const timeKey = `${d.getHours().toString().padStart(2, '0')}:${(Math.floor(d.getMinutes() / 10) * 10).toString().padStart(2, '0')}`;
    const curr = timeBins.get(timeKey) || { count: 0, critical: 0 };
    curr.count++;
    if (e.severity === 'CRITICAL' || e.severity === 'HIGH') {
      curr.critical++;
    }
    timeBins.set(timeKey, curr);
  }

  const events_over_time = Array.from(timeBins.entries())
    .map(([time, data]) => ({ time, count: data.count, critical: data.critical }))
    .slice(-8);

  const attack_category_distribution = Array.from(categoryCount.entries())
    .filter(([cat]) => cat !== 'Normal Activity')
    .map(([category, count]) => ({ category, count }))
    .sort((a, b) => b.count - a.count);

  const open_incidents = incidents.filter((i) => i.status === 'New' || i.status === 'Investigating').length;

  return {
    total_events,
    critical_events,
    high_events,
    medium_events,
    low_events,
    events_today: events_today || total_events,
    open_incidents,
    top_source_ips,
    top_target_assets,
    top_threat_categories,
    severity_distribution,
    events_over_time,
    attack_category_distribution,
  };
}
