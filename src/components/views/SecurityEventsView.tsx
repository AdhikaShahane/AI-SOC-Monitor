/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useMemo } from 'react';
import {
  DetectionMethod,
  DeviceType,
  EventStatus,
  SecurityEvent,
  SeverityLevel,
  ThreatCategory,
} from '../../types/security';
import { SeverityBadge, DetectionMethodBadge } from '../common/SeverityBadge';
import {
  Filter,
  Search,
  PlusCircle,
  Sparkles,
  ChevronRight,
  ShieldAlert,
  ArrowRight,
  CheckSquare,
  Square,
  RotateCcw,
  Clock,
  ArrowUpDown,
  Download,
  Eye,
  SlidersHorizontal,
  ChevronLeft,
  X,
  Layers,
  Activity,
} from 'lucide-react';

interface SecurityEventsViewProps {
  events: SecurityEvent[];
  onSelectEvent: (event: SecurityEvent) => void;
  onCreateIncidentFromEvents: (selectedEvents: SecurityEvent[]) => void;
  onAnalyzeEventAI: (event: SecurityEvent) => void;
  globalSearch: string;
}

type SortField = 'timestamp' | 'severity' | 'risk_score' | 'event_id';
type SortOrder = 'asc' | 'desc';
type TimeRangeOption = 'ALL' | '15m' | '1h' | '6h' | '24h';

const SEVERITY_WEIGHTS: Record<SeverityLevel, number> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFORMATIONAL: 1,
};

export const SecurityEventsView: React.FC<SecurityEventsViewProps> = ({
  events,
  onSelectEvent,
  onCreateIncidentFromEvents,
  onAnalyzeEventAI,
  globalSearch,
}) => {
  // Filter States
  const [localSearch, setLocalSearch] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL');
  const [selectedDeviceType, setSelectedDeviceType] = useState<string>('ALL');
  const [selectedMethod, setSelectedMethod] = useState<string>('ALL');
  const [selectedStatus, setSelectedStatus] = useState<string>('ALL');
  const [sourceIpFilter, setSourceIpFilter] = useState<string>('');
  const [destIpFilter, setDestIpFilter] = useState<string>('');
  const [timeRange, setTimeRange] = useState<TimeRangeOption>('ALL');

  // Sorting and Pagination States
  const [sortField, setSortField] = useState<SortField>('timestamp');
  const [sortOrder, setSortOrder] = useState<SortOrder>('desc');
  const [pageSize, setPageSize] = useState<number>(25);
  const [currentPage, setCurrentPage] = useState<number>(1);
  const [density, setDensity] = useState<'compact' | 'normal'>('compact');

  // Selection
  const [selectedEventIds, setSelectedEventIds] = useState<string[]>([]);
  const [isAdvancedFiltersOpen, setIsAdvancedFiltersOpen] = useState(false);

  const effectiveSearch = localSearch || globalSearch;

  // Compute latest event timestamp to anchor relative time calculations
  const latestTimestampMs = useMemo(() => {
    if (events.length === 0) return Date.now();
    return Math.max(...events.map((e) => new Date(e.timestamp).getTime() || 0));
  }, [events]);

  // Filtering Logic
  const filteredEvents = useMemo(() => {
    const rangeWindowMs: Record<TimeRangeOption, number> = {
      ALL: Infinity,
      '15m': 15 * 60 * 1000,
      '1h': 60 * 60 * 1000,
      '6h': 6 * 60 * 60 * 1000,
      '24h': 24 * 60 * 60 * 1000,
    };

    const maxDelta = rangeWindowMs[timeRange];

    return events.filter((ev) => {
      // 1. Severity
      if (selectedSeverity !== 'ALL' && ev.severity !== selectedSeverity) return false;

      // 2. Threat Category
      if (selectedCategory !== 'ALL' && ev.threat_category !== selectedCategory) return false;

      // 3. Device Type
      if (selectedDeviceType !== 'ALL' && ev.device_type !== selectedDeviceType) return false;

      // 4. Detection Method
      if (selectedMethod !== 'ALL' && ev.detection_method !== selectedMethod) return false;

      // 5. Status
      if (selectedStatus !== 'ALL' && ev.status !== selectedStatus) return false;

      // 6. Source IP Filter
      if (sourceIpFilter.trim()) {
        const queryIp = sourceIpFilter.trim().toLowerCase();
        if (!ev.source_ip.toLowerCase().includes(queryIp)) return false;
      }

      // 7. Destination IP Filter
      if (destIpFilter.trim()) {
        const queryDest = destIpFilter.trim().toLowerCase();
        if (!ev.destination_ip.toLowerCase().includes(queryDest)) return false;
      }

      // 8. Time Range
      if (maxDelta !== Infinity) {
        const evTime = new Date(ev.timestamp).getTime();
        if (latestTimestampMs - evTime > maxDelta) return false;
      }

      // 9. Free-text Search
      if (effectiveSearch) {
        const q = effectiveSearch.toLowerCase();
        const match =
          ev.event_id.toLowerCase().includes(q) ||
          ev.source_ip.toLowerCase().includes(q) ||
          ev.destination_ip.toLowerCase().includes(q) ||
          ev.asset.toLowerCase().includes(q) ||
          ev.username.toLowerCase().includes(q) ||
          ev.message.toLowerCase().includes(q) ||
          ev.threat_category.toLowerCase().includes(q) ||
          (ev.rule_id && ev.rule_id.toLowerCase().includes(q)) ||
          (ev.raw_payload && ev.raw_payload.toLowerCase().includes(q));
        if (!match) return false;
      }

      return true;
    });
  }, [
    events,
    selectedSeverity,
    selectedCategory,
    selectedDeviceType,
    selectedMethod,
    selectedStatus,
    sourceIpFilter,
    destIpFilter,
    timeRange,
    effectiveSearch,
    latestTimestampMs,
  ]);

  // Sorting Logic
  const sortedEvents = useMemo(() => {
    return [...filteredEvents].sort((a, b) => {
      let comparison = 0;
      if (sortField === 'timestamp') {
        comparison = new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime();
      } else if (sortField === 'severity') {
        comparison = SEVERITY_WEIGHTS[a.severity] - SEVERITY_WEIGHTS[b.severity];
      } else if (sortField === 'risk_score') {
        comparison = a.risk_score - b.risk_score;
      } else if (sortField === 'event_id') {
        comparison = a.event_id.localeCompare(b.event_id);
      }

      return sortOrder === 'asc' ? comparison : -comparison;
    });
  }, [filteredEvents, sortField, sortOrder]);

  // Pagination Slice
  const totalPages = Math.max(1, Math.ceil(sortedEvents.length / pageSize));
  const currentPageSafe = Math.min(currentPage, totalPages);
  const startIndex = (currentPageSafe - 1) * pageSize;
  const paginatedEvents = sortedEvents.slice(startIndex, startIndex + pageSize);

  // Active filter count
  const activeFiltersCount = useMemo(() => {
    let count = 0;
    if (selectedSeverity !== 'ALL') count++;
    if (selectedCategory !== 'ALL') count++;
    if (selectedDeviceType !== 'ALL') count++;
    if (selectedMethod !== 'ALL') count++;
    if (selectedStatus !== 'ALL') count++;
    if (sourceIpFilter.trim()) count++;
    if (destIpFilter.trim()) count++;
    if (timeRange !== 'ALL') count++;
    if (localSearch.trim()) count++;
    return count;
  }, [
    selectedSeverity,
    selectedCategory,
    selectedDeviceType,
    selectedMethod,
    selectedStatus,
    sourceIpFilter,
    destIpFilter,
    timeRange,
    localSearch,
  ]);

  const toggleSort = (field: SortField) => {
    if (sortField === field) {
      setSortOrder((prev) => (prev === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortField(field);
      setSortOrder('desc');
    }
  };

  const toggleSelect = (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (selectedEventIds.includes(id)) {
      setSelectedEventIds((prev) => prev.filter((x) => x !== id));
    } else {
      setSelectedEventIds((prev) => [...prev, id]);
    }
  };

  const selectAllCurrentPage = () => {
    const pageIds = paginatedEvents.map((e) => e.event_id);
    const allSelected = pageIds.every((id) => selectedEventIds.includes(id));
    if (allSelected) {
      setSelectedEventIds((prev) => prev.filter((id) => !pageIds.includes(id)));
    } else {
      setSelectedEventIds((prev) => Array.from(new Set([...prev, ...pageIds])));
    }
  };

  const handleCreateIncidentBulk = () => {
    const selected = events.filter((e) => selectedEventIds.includes(e.event_id));
    if (selected.length > 0) {
      onCreateIncidentFromEvents(selected);
      setSelectedEventIds([]);
    }
  };

  const resetAllFilters = () => {
    setSelectedSeverity('ALL');
    setSelectedCategory('ALL');
    setSelectedDeviceType('ALL');
    setSelectedMethod('ALL');
    setSelectedStatus('ALL');
    setSourceIpFilter('');
    setDestIpFilter('');
    setTimeRange('ALL');
    setLocalSearch('');
    setCurrentPage(1);
  };

  return (
    <div className="space-y-4">
      {/* Primary Toolbar: Search + Quick Tiers + Batch Actions */}
      <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 shadow-sm space-y-3">
        <div className="flex flex-col lg:flex-row items-stretch lg:items-center justify-between gap-3">
          {/* Search bar */}
          <div className="relative flex-1 max-w-lg">
            <Search className="absolute left-3 top-2.5 w-4 h-4 text-slate-500" />
            <input
              type="text"
              placeholder="Search Event ID, IP, Hostname, Account, Signature, or Payload..."
              value={localSearch}
              onChange={(e) => {
                setLocalSearch(e.target.value);
                setCurrentPage(1);
              }}
              className="w-full pl-9 pr-8 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 transition"
            />
            {localSearch && (
              <button
                onClick={() => setLocalSearch('')}
                className="absolute right-2.5 top-2.5 text-xs text-slate-500 hover:text-slate-200"
              >
                &times;
              </button>
            )}
          </div>

          {/* Action cluster */}
          <div className="flex flex-wrap items-center gap-2 justify-end">
            {selectedEventIds.length > 0 && (
              <button
                onClick={handleCreateIncidentBulk}
                className="px-3 py-1.5 rounded-lg bg-red-600 hover:bg-red-500 text-white text-xs font-semibold flex items-center gap-1.5 transition shadow"
              >
                <PlusCircle className="w-4 h-4" />
                <span>Create Incident ({selectedEventIds.length})</span>
              </button>
            )}

            <button
              onClick={() => setIsAdvancedFiltersOpen((prev) => !prev)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium border flex items-center gap-1.5 transition ${
                isAdvancedFiltersOpen || activeFiltersCount > 0
                  ? 'bg-cyan-950/70 border-cyan-700/80 text-cyan-300'
                  : 'bg-slate-950 border-slate-800 text-slate-300 hover:text-white'
              }`}
            >
              <SlidersHorizontal className="w-3.5 h-3.5" />
              <span>Filters</span>
              {activeFiltersCount > 0 && (
                <span className="ml-0.5 px-1.5 py-0.2 rounded-full text-[10px] bg-cyan-500 text-slate-950 font-bold">
                  {activeFiltersCount}
                </span>
              )}
            </button>

            {activeFiltersCount > 0 && (
              <button
                onClick={resetAllFilters}
                className="px-2.5 py-1.5 rounded-lg text-xs text-slate-400 hover:text-slate-200 bg-slate-950 border border-slate-800 flex items-center gap-1 transition"
                title="Reset all filters"
              >
                <RotateCcw className="w-3.5 h-3.5" />
                <span className="hidden sm:inline">Reset</span>
              </button>
            )}

            {/* Density switch */}
            <div className="flex items-center rounded-lg bg-slate-950 border border-slate-800 p-0.5 text-xs">
              <button
                onClick={() => setDensity('compact')}
                className={`px-2 py-1 rounded text-[11px] font-medium transition ${
                  density === 'compact' ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-slate-200'
                }`}
                title="Compact row view"
              >
                Compact
              </button>
              <button
                onClick={() => setDensity('normal')}
                className={`px-2 py-1 rounded text-[11px] font-medium transition ${
                  density === 'normal' ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-slate-200'
                }`}
                title="Normal row view"
              >
                Comfort
              </button>
            </div>
          </div>
        </div>

        {/* Filter Controls Bar (Expandable or standard) */}
        <div className="pt-2 border-t border-slate-800/80">
          <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-2 text-xs">
            {/* 1. Severity Filter */}
            <div>
              <label className="text-[11px] font-medium text-slate-400 block mb-1">Severity</label>
              <select
                value={selectedSeverity}
                onChange={(e) => {
                  setSelectedSeverity(e.target.value);
                  setCurrentPage(1);
                }}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2 py-1.5 text-slate-200 focus:outline-none focus:border-cyan-500 text-xs"
              >
                <option value="ALL">All Severities</option>
                <option value="CRITICAL">CRITICAL</option>
                <option value="HIGH">HIGH</option>
                <option value="MEDIUM">MEDIUM</option>
                <option value="LOW">LOW</option>
                <option value="INFORMATIONAL">INFO</option>
              </select>
            </div>

            {/* 2. Threat Category Filter */}
            <div>
              <label className="text-[11px] font-medium text-slate-400 block mb-1">Threat Category</label>
              <select
                value={selectedCategory}
                onChange={(e) => {
                  setSelectedCategory(e.target.value);
                  setCurrentPage(1);
                }}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2 py-1.5 text-slate-200 focus:outline-none focus:border-cyan-500 text-xs"
              >
                <option value="ALL">All Categories</option>
                <option value="Brute Force">Brute Force</option>
                <option value="Port Scanning">Port Scanning</option>
                <option value="Suspicious Authentication">Suspicious Auth</option>
                <option value="Malware Indicator">Malware Indicator</option>
                <option value="Command-and-Control Indicator">Command & Control</option>
                <option value="DDoS/Traffic Anomaly">DDoS / Traffic Anomaly</option>
                <option value="SQL Injection Attempt">SQL Injection</option>
                <option value="Privilege Escalation">Privilege Escalation</option>
                <option value="Suspicious Outbound Traffic">Suspicious Outbound</option>
                <option value="Data Exfiltration Indicator">Data Exfiltration</option>
                <option value="Normal Activity">Normal Baseline</option>
              </select>
            </div>

            {/* 3. Device Type Filter */}
            <div>
              <label className="text-[11px] font-medium text-slate-400 block mb-1">Device Type</label>
              <select
                value={selectedDeviceType}
                onChange={(e) => {
                  setSelectedDeviceType(e.target.value);
                  setCurrentPage(1);
                }}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2 py-1.5 text-slate-200 focus:outline-none focus:border-cyan-500 text-xs"
              >
                <option value="ALL">All Devices</option>
                <option value="Firewall">Firewall</option>
                <option value="IDS/IPS">IDS / IPS</option>
                <option value="Authentication">Authentication</option>
                <option value="Web Server">Web Server</option>
                <option value="Network Flow">Network Flow</option>
              </select>
            </div>

            {/* 4. Detection Method Filter */}
            <div>
              <label className="text-[11px] font-medium text-slate-400 block mb-1">Detection Origin</label>
              <select
                value={selectedMethod}
                onChange={(e) => {
                  setSelectedMethod(e.target.value);
                  setCurrentPage(1);
                }}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2 py-1.5 text-slate-200 focus:outline-none focus:border-cyan-500 text-xs"
              >
                <option value="ALL">All Methods</option>
                <option value="RULE">RULE</option>
                <option value="AI">AI</option>
                <option value="RULE_AND_AI">RULE + AI</option>
              </select>
            </div>

            {/* 5. Status Filter */}
            <div>
              <label className="text-[11px] font-medium text-slate-400 block mb-1">Status</label>
              <select
                value={selectedStatus}
                onChange={(e) => {
                  setSelectedStatus(e.target.value);
                  setCurrentPage(1);
                }}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2 py-1.5 text-slate-200 focus:outline-none focus:border-cyan-500 text-xs"
              >
                <option value="ALL">All Statuses</option>
                <option value="OPEN">OPEN</option>
                <option value="INVESTIGATING">INVESTIGATING</option>
                <option value="IN_INCIDENT">IN_INCIDENT</option>
                <option value="RESOLVED">RESOLVED</option>
                <option value="DISMISSED">DISMISSED</option>
              </select>
            </div>

            {/* 6. Time Range Filter */}
            <div>
              <label className="text-[11px] font-medium text-slate-400 block mb-1">Time Range</label>
              <select
                value={timeRange}
                onChange={(e) => {
                  setTimeRange(e.target.value as TimeRangeOption);
                  setCurrentPage(1);
                }}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2 py-1.5 text-slate-200 focus:outline-none focus:border-cyan-500 text-xs"
              >
                <option value="ALL">All Recorded</option>
                <option value="15m">Last 15m</option>
                <option value="1h">Last 1h</option>
                <option value="6h">Last 6h</option>
                <option value="24h">Last 24h</option>
              </select>
            </div>

            {/* 7. Source IP Input Filter */}
            <div>
              <label className="text-[11px] font-medium text-slate-400 block mb-1">Source IP</label>
              <input
                type="text"
                placeholder="e.g. 198.51."
                value={sourceIpFilter}
                onChange={(e) => {
                  setSourceIpFilter(e.target.value);
                  setCurrentPage(1);
                }}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2 py-1.5 text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500 text-xs font-mono"
              />
            </div>

            {/* 8. Destination IP Input Filter */}
            <div>
              <label className="text-[11px] font-medium text-slate-400 block mb-1">Dest IP</label>
              <input
                type="text"
                placeholder="e.g. 10.0.1."
                value={destIpFilter}
                onChange={(e) => {
                  setDestIpFilter(e.target.value);
                  setCurrentPage(1);
                }}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2 py-1.5 text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500 text-xs font-mono"
              />
            </div>
          </div>
        </div>
      </div>

      {/* Main Events Table Container */}
      <div className="rounded-xl bg-slate-900/90 border border-slate-800 shadow-sm overflow-hidden">
        {/* Table Subheader Strip: Selection Status + Pagination info */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between px-4 py-2.5 border-b border-slate-800 bg-slate-950/60 text-xs gap-2">
          <div className="flex items-center gap-3">
            <button
              onClick={selectAllCurrentPage}
              className="text-slate-400 hover:text-slate-200 transition"
              title="Select all on current page"
            >
              {paginatedEvents.length > 0 &&
              paginatedEvents.every((e) => selectedEventIds.includes(e.event_id)) ? (
                <CheckSquare className="w-4 h-4 text-cyan-400" />
              ) : (
                <Square className="w-4 h-4 text-slate-600" />
              )}
            </button>
            <span className="font-semibold text-slate-300">
              Showing {sortedEvents.length > 0 ? startIndex + 1 : 0}&ndash;
              {Math.min(startIndex + pageSize, sortedEvents.length)} of {sortedEvents.length} Events
              {sortedEvents.length !== events.length && (
                <span className="text-slate-500 font-normal ml-1">
                  (filtered from {events.length} total)
                </span>
              )}
            </span>
          </div>

          {/* Quick Pagination Control */}
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-1.5 text-slate-400 font-mono text-[11px]">
              <span>Rows:</span>
              <select
                value={pageSize}
                onChange={(e) => {
                  setPageSize(Number(e.target.value));
                  setCurrentPage(1);
                }}
                className="bg-slate-950 border border-slate-800 rounded px-1.5 py-0.5 text-slate-300 text-xs"
              >
                <option value={25}>25</option>
                <option value={50}>50</option>
                <option value={100}>100</option>
                <option value={250}>250</option>
              </select>
            </div>

            <div className="flex items-center gap-1 text-slate-400 text-xs font-mono">
              <span>
                Page {currentPageSafe} / {totalPages}
              </span>
              <button
                disabled={currentPageSafe <= 1}
                onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                className="p-1 rounded bg-slate-950 border border-slate-800 disabled:opacity-40 hover:text-white"
                title="Previous page"
              >
                <ChevronLeft className="w-3.5 h-3.5" />
              </button>
              <button
                disabled={currentPageSafe >= totalPages}
                onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
                className="p-1 rounded bg-slate-950 border border-slate-800 disabled:opacity-40 hover:text-white"
                title="Next page"
              >
                <ChevronRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        </div>

        {/* Tabular Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-950/40 text-slate-400 font-mono text-[11px] uppercase tracking-wider select-none">
                <th className="py-2.5 px-3 w-8">#</th>
                <th
                  onClick={() => toggleSort('event_id')}
                  className="py-2.5 px-3 cursor-pointer hover:text-cyan-400 transition"
                >
                  <div className="flex items-center gap-1">
                    <span>Event ID</span>
                    <ArrowUpDown className="w-3 h-3 text-slate-600" />
                  </div>
                </th>
                <th
                  onClick={() => toggleSort('timestamp')}
                  className="py-2.5 px-3 cursor-pointer hover:text-cyan-400 transition"
                >
                  <div className="flex items-center gap-1">
                    <span>Timestamp</span>
                    <ArrowUpDown className="w-3 h-3 text-slate-600" />
                  </div>
                </th>
                <th
                  onClick={() => toggleSort('severity')}
                  className="py-2.5 px-3 cursor-pointer hover:text-cyan-400 transition"
                >
                  <div className="flex items-center gap-1">
                    <span>Severity</span>
                    <ArrowUpDown className="w-3 h-3 text-slate-600" />
                  </div>
                </th>
                <th
                  onClick={() => toggleSort('risk_score')}
                  className="py-2.5 px-3 cursor-pointer hover:text-cyan-400 transition"
                >
                  <div className="flex items-center gap-1">
                    <span>Risk</span>
                    <ArrowUpDown className="w-3 h-3 text-slate-600" />
                  </div>
                </th>
                <th className="py-2.5 px-3">Method</th>
                <th className="py-2.5 px-3">Threat Category</th>
                <th className="py-2.5 px-3">Device & Type</th>
                <th className="py-2.5 px-3">Action</th>
                <th className="py-2.5 px-3">Source &rarr; Destination</th>
                <th className="py-2.5 px-3">Target Asset</th>
                <th className="py-2.5 px-3">Log Message</th>
                <th className="py-2.5 px-3 text-right">Inspect</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-sans">
              {sortedEvents.length === 0 ? (
                <tr>
                  <td colSpan={13} className="py-16 text-center text-slate-400">
                    <div className="max-w-md mx-auto space-y-3">
                      <ShieldAlert className="w-8 h-8 text-slate-600 mx-auto" />
                      <div>
                        <h4 className="text-sm font-semibold text-slate-200">
                          No matching security telemetry
                        </h4>
                        <p className="text-xs text-slate-500 mt-1">
                          No events in the current buffer match your combination of filters and search queries.
                        </p>
                      </div>
                      <button
                        onClick={resetAllFilters}
                        className="px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold inline-flex items-center gap-1.5 transition"
                      >
                        <RotateCcw className="w-3.5 h-3.5" />
                        Reset All Filters
                      </button>
                    </div>
                  </td>
                </tr>
              ) : (
                paginatedEvents.map((ev) => {
                  const isSelected = selectedEventIds.includes(ev.event_id);
                  const isCritical = ev.severity === 'CRITICAL';
                  const rowPadding = density === 'compact' ? 'py-1.5 px-3' : 'py-2.5 px-3';

                  return (
                    <tr
                      key={ev.event_id}
                      onClick={() => onSelectEvent(ev)}
                      className={`hover:bg-slate-800/50 cursor-pointer transition select-none ${
                        isSelected ? 'bg-cyan-950/25' : isCritical ? 'bg-red-950/10' : ''
                      }`}
                    >
                      {/* Checkbox */}
                      <td className={rowPadding} onClick={(e) => toggleSelect(ev.event_id, e)}>
                        {isSelected ? (
                          <CheckSquare className="w-3.5 h-3.5 text-cyan-400" />
                        ) : (
                          <Square className="w-3.5 h-3.5 text-slate-600" />
                        )}
                      </td>

                      {/* Event ID */}
                      <td className={`${rowPadding} font-mono font-semibold whitespace-nowrap text-cyan-400 text-xs`}>
                        {ev.event_id}
                      </td>

                      {/* Timestamp */}
                      <td className={`${rowPadding} font-mono text-slate-400 whitespace-nowrap text-[11px] tabular-nums`}>
                        {new Date(ev.timestamp).toLocaleTimeString()}
                      </td>

                      {/* Severity */}
                      <td className={`${rowPadding} whitespace-nowrap`}>
                        <SeverityBadge severity={ev.severity} />
                      </td>

                      {/* Risk Score */}
                      <td className={`${rowPadding} font-mono text-xs whitespace-nowrap`}>
                        <span
                          className={`font-bold tabular-nums ${
                            ev.risk_score >= 80
                              ? 'text-red-400'
                              : ev.risk_score >= 60
                              ? 'text-amber-400'
                              : 'text-slate-400'
                          }`}
                        >
                          {ev.risk_score}
                        </span>
                      </td>

                      {/* Method */}
                      <td className={`${rowPadding} whitespace-nowrap`}>
                        <DetectionMethodBadge method={ev.detection_method} />
                      </td>

                      {/* Threat Category */}
                      <td className={`${rowPadding} whitespace-nowrap font-medium text-slate-300 text-xs`}>
                        {ev.threat_category}
                      </td>

                      {/* Device & Device Type */}
                      <td className={`${rowPadding} whitespace-nowrap text-slate-400 text-xs`}>
                        <span className="font-mono text-slate-300">{ev.device}</span>
                        <span className="text-slate-500 ml-1">({ev.device_type})</span>
                      </td>

                      {/* Action */}
                      <td className={`${rowPadding} whitespace-nowrap`}>
                        <span
                          className={`font-mono font-bold text-[11px] ${
                            ev.action === 'ALLOW' || ev.action === 'SUCCESS'
                              ? 'text-emerald-400'
                              : 'text-red-400'
                          }`}
                        >
                          {ev.action}
                        </span>
                      </td>

                      {/* Source & Destination */}
                      <td className={`${rowPadding} font-mono text-slate-300 whitespace-nowrap text-[11px] tabular-nums`}>
                        <span className="text-cyan-300 font-semibold">{ev.source_ip}</span>
                        <span className="text-slate-500">:{ev.source_port}</span>
                        <span className="text-slate-600 mx-1">&rarr;</span>
                        <span className="text-slate-300">{ev.destination_ip}</span>
                        <span className="text-slate-500">:{ev.destination_port}</span>
                      </td>

                      {/* Target Asset */}
                      <td className={`${rowPadding} whitespace-nowrap font-semibold text-slate-200 text-xs`}>
                        {ev.asset}
                      </td>

                      {/* Log Message */}
                      <td
                        className={`${rowPadding} max-w-xs truncate text-slate-300 text-xs`}
                        title={ev.message}
                      >
                        {ev.message}
                      </td>

                      {/* Actions */}
                      <td className={`${rowPadding} text-right whitespace-nowrap`}>
                        <div className="flex items-center justify-end gap-1.5">
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              onAnalyzeEventAI(ev);
                            }}
                            className="p-1 rounded text-purple-400 hover:text-purple-300 hover:bg-purple-950/40 transition"
                            title="Run AI Forensic Analysis"
                          >
                            <Sparkles className="w-3.5 h-3.5" />
                          </button>
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              onSelectEvent(ev);
                            }}
                            className="text-cyan-400 hover:text-cyan-300 font-mono text-xs inline-flex items-center gap-0.5 ml-1"
                            title="Open full event drawer"
                          >
                            <ChevronRight className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Footer pagination bar */}
        <div className="flex flex-col sm:flex-row items-center justify-between px-4 py-3 border-t border-slate-800 bg-slate-950/40 text-xs text-slate-400">
          <div className="flex items-center gap-2">
            <span>
              Total Filtered Events:{' '}
              <span className="font-mono font-bold text-slate-200">{sortedEvents.length}</span>
            </span>
            {selectedEventIds.length > 0 && (
              <span className="text-cyan-400 font-mono">
                ({selectedEventIds.length} events selected)
              </span>
            )}
          </div>

          <div className="flex items-center gap-2 mt-2 sm:mt-0 font-mono text-[11px]">
            <button
              disabled={currentPageSafe <= 1}
              onClick={() => setCurrentPage(1)}
              className="px-2 py-1 rounded bg-slate-950 border border-slate-800 disabled:opacity-30 hover:text-white"
            >
              First
            </button>
            <button
              disabled={currentPageSafe <= 1}
              onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
              className="px-2 py-1 rounded bg-slate-950 border border-slate-800 disabled:opacity-30 hover:text-white"
            >
              Prev
            </button>
            <span className="px-2 py-1 text-slate-300">
              {currentPageSafe} of {totalPages}
            </span>
            <button
              disabled={currentPageSafe >= totalPages}
              onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
              className="px-2 py-1 rounded bg-slate-950 border border-slate-800 disabled:opacity-30 hover:text-white"
            >
              Next
            </button>
            <button
              disabled={currentPageSafe >= totalPages}
              onClick={() => setCurrentPage(totalPages)}
              className="px-2 py-1 rounded bg-slate-950 border border-slate-800 disabled:opacity-30 hover:text-white"
            >
              Last
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
