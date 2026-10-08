/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect, useMemo, useRef } from 'react';
import { Incident, SecurityEvent, SOCMetrics } from './types/security';
import { generateSyntheticSecurityLogs, generateRandomStreamEvent } from './services/syntheticLogGenerator';
import { getInitialSampleIncidents } from './services/sampleIncidents';
import { calculateSOCMetrics } from './services/metricsCalculator';
import { checkAIHealth } from './services/aiAnalystClient';
import { detectionEngine } from './services/detectionEngine';
import { Navbar } from './components/Navbar';
import { Sidebar, ActiveModule } from './components/Sidebar';
import { SOCDashboardView } from './components/views/SOCDashboardView';
import { SecurityEventsView } from './components/views/SecurityEventsView';
import { FirewallMonitoringView } from './components/views/FirewallMonitoringView';
import { IdsIpsMonitoringView } from './components/views/IdsIpsMonitoringView';
import { AuthMonitoringView } from './components/views/AuthMonitoringView';
import { NetworkAnomalyView } from './components/views/NetworkAnomalyView';
import { IncidentManagementView } from './components/views/IncidentManagementView';
import { AISecurityAnalystView } from './components/views/AISecurityAnalystView';
import { ReportsView } from './components/views/ReportsView';
import { SettingsView } from './components/views/SettingsView';
import { EventDetailModal } from './components/modals/EventDetailModal';
import { IncidentDetailModal } from './components/modals/IncidentDetailModal';
import { CreateIncidentModal } from './components/modals/CreateIncidentModal';
import { UploadLogsModal } from './components/modals/UploadLogsModal';

export default function App() {
  const [events, setEvents] = useState<SecurityEvent[]>(() => generateSyntheticSecurityLogs());
  const [incidents, setIncidents] = useState<Incident[]>(() => getInitialSampleIncidents());
  const [activeModule, setActiveModule] = useState<ActiveModule>('dashboard');
  const [isStreaming, setIsStreaming] = useState<boolean>(false);
  const [globalSearch, setGlobalSearch] = useState<string>('');

  // Modals
  const [selectedEventModal, setSelectedEventModal] = useState<SecurityEvent | null>(null);
  const [selectedIncidentModal, setSelectedIncidentModal] = useState<Incident | null>(null);
  const [isCreateIncidentOpen, setIsCreateIncidentOpen] = useState<boolean>(false);
  const [eventsToSeedIncident, setEventsToSeedIncident] = useState<SecurityEvent[]>([]);
  const [isUploadModalOpen, setIsUploadModalOpen] = useState<boolean>(false);

  // AI engine backend status
  const [aiHealth, setAiHealth] = useState<{ online: boolean; ai_available: boolean; model: string }>({
    online: false,
    ai_available: false,
    model: 'gemini-3.8-flash',
  });

  // Calculate live SOC metrics
  const metrics: SOCMetrics = useMemo(() => {
    return calculateSOCMetrics(events, incidents);
  }, [events, incidents]);

  // Initial AI backend health check
  useEffect(() => {
    checkAIHealth().then((res) => {
      setAiHealth(res);
    });
  }, []);

  // Streaming loop
  const eventsRef = useRef(events);
  eventsRef.current = events;

  useEffect(() => {
    if (!isStreaming) return;
    const interval = setInterval(() => {
      const newEvent = generateRandomStreamEvent(eventsRef.current);
      setEvents((prev) => [newEvent, ...prev.slice(0, 150)]); // keep buffer clean
    }, 4000);

    return () => clearInterval(interval);
  }, [isStreaming]);

  // Handlers
  const handleGenerateSampleLogs = () => {
    const freshEvents = generateSyntheticSecurityLogs();
    const freshIncidents = getInitialSampleIncidents();
    setEvents(freshEvents);
    setIncidents(freshIncidents);
  };

  const handleClearLogs = () => {
    setEvents([]);
  };

  const handleExportLogs = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(events, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `sentinel-ai-logs-${new Date().toISOString().slice(0, 10)}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const handleUpdateEvent = (updated: SecurityEvent) => {
    setEvents((prev) => prev.map((e) => (e.event_id === updated.event_id ? updated : e)));
    if (selectedEventModal && selectedEventModal.event_id === updated.event_id) {
      setSelectedEventModal(updated);
    }
  };

  const handleUpdateIncident = (updated: Incident) => {
    setIncidents((prev) => prev.map((i) => (i.incident_id === updated.incident_id ? updated : i)));
    if (selectedIncidentModal && selectedIncidentModal.incident_id === updated.incident_id) {
      setSelectedIncidentModal(updated);
    }
  };

  const handleCreateIncident = (newIncident: Incident) => {
    setIncidents((prev) => [newIncident, ...prev]);
    // Tag linked events as IN_INCIDENT
    setEvents((prev) =>
      prev.map((e) => {
        if (newIncident.event_ids.includes(e.event_id)) {
          return { ...e, status: 'IN_INCIDENT' };
        }
        return e;
      })
    );
  };

  const handleIngestExternal = (newEvents: SecurityEvent[]) => {
    setEvents((prev) => [...newEvents, ...prev]);
  };

  const handleReanalyzeEvents = () => {
    setEvents((prev) => {
      const reprocessed: SecurityEvent[] = [];
      for (const ev of prev) {
        reprocessed.push(detectionEngine.processEvent(ev, reprocessed));
      }
      return reprocessed;
    });
  };

  const handleOpenCreateIncidentFromEvents = (seedEvents: SecurityEvent[]) => {
    setEventsToSeedIncident(seedEvents);
    setIsCreateIncidentOpen(true);
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-cyan-500/30 selection:text-cyan-200">
      {/* Top Navigation */}
      <Navbar
        isStreaming={isStreaming}
        onToggleStreaming={() => setIsStreaming((prev) => !prev)}
        onGenerateSampleLogs={handleGenerateSampleLogs}
        onOpenUploadModal={() => setIsUploadModalOpen(true)}
        onClearLogs={handleClearLogs}
        onExportLogs={handleExportLogs}
        searchQuery={globalSearch}
        onSearchChange={setGlobalSearch}
        totalEventsCount={events.length}
        criticalEventsCount={metrics.critical_events}
        aiEngineStatus={aiHealth}
      />

      {/* Main Body Layout: Sidebar + Active Module */}
      <div className="flex-1 flex flex-col md:flex-row overflow-hidden">
        {/* Sidebar */}
        <Sidebar
          activeModule={activeModule}
          onSelectModule={setActiveModule}
          openIncidentsCount={metrics.open_incidents}
          criticalEventsCount={metrics.critical_events}
          totalEventsCount={events.length}
        />

        {/* View Content Canvas */}
        <main className="flex-1 overflow-y-auto p-4 sm:p-6 lg:p-8 bg-slate-950">
          {activeModule === 'dashboard' && (
            <SOCDashboardView
              metrics={metrics}
              events={events}
              incidents={incidents}
              onSelectEvent={setSelectedEventModal}
              onSelectIncident={setSelectedIncidentModal}
              onNavigateToModule={setActiveModule}
              onGenerateDemoDataset={handleGenerateSampleLogs}
            />
          )}

          {activeModule === 'events' && (
            <SecurityEventsView
              events={events}
              onSelectEvent={setSelectedEventModal}
              onCreateIncidentFromEvents={handleOpenCreateIncidentFromEvents}
              onAnalyzeEventAI={setSelectedEventModal}
              globalSearch={globalSearch}
            />
          )}

          {activeModule === 'firewall' && (
            <FirewallMonitoringView events={events} onSelectEvent={setSelectedEventModal} />
          )}

          {activeModule === 'ids' && (
            <IdsIpsMonitoringView events={events} onSelectEvent={setSelectedEventModal} />
          )}

          {activeModule === 'auth' && (
            <AuthMonitoringView events={events} onSelectEvent={setSelectedEventModal} />
          )}

          {activeModule === 'network' && (
            <NetworkAnomalyView events={events} onSelectEvent={setSelectedEventModal} />
          )}

          {activeModule === 'incidents' && (
            <IncidentManagementView
              incidents={incidents}
              allEvents={events}
              onSelectIncident={setSelectedIncidentModal}
              onOpenCreateIncidentModal={() => handleOpenCreateIncidentFromEvents([])}
              onSelectEvent={setSelectedEventModal}
              onUpdateIncident={handleUpdateIncident}
            />
          )}

          {activeModule === 'ai-analyst' && (
            <AISecurityAnalystView
              events={events}
              incidents={incidents}
              onUpdateEvent={handleUpdateEvent}
              onSelectEvent={setSelectedEventModal}
            />
          )}

          {activeModule === 'reports' && (
            <ReportsView metrics={metrics} incidents={incidents} events={events} />
          )}

          {activeModule === 'settings' && (
            <SettingsView
              onResetToBaseline={handleGenerateSampleLogs}
              aiEngineStatus={aiHealth}
              isStreaming={isStreaming}
              onToggleStreaming={() => setIsStreaming((prev) => !prev)}
              onConfigChanged={handleReanalyzeEvents}
            />
          )}
        </main>
      </div>

      {/* Modals & Drawers */}
      <EventDetailModal
        event={selectedEventModal}
        onClose={() => setSelectedEventModal(null)}
        onUpdateEvent={handleUpdateEvent}
        onCreateIncidentFromEvent={(ev) => handleOpenCreateIncidentFromEvents([ev])}
      />

      <IncidentDetailModal
        incident={selectedIncidentModal}
        allEvents={events}
        onClose={() => setSelectedIncidentModal(null)}
        onUpdateIncident={handleUpdateIncident}
        onSelectEvent={setSelectedEventModal}
      />

      {isCreateIncidentOpen && (
        <CreateIncidentModal
          initialEvents={eventsToSeedIncident}
          allEvents={events}
          onClose={() => setIsCreateIncidentOpen(false)}
          onCreate={handleCreateIncident}
        />
      )}

      {isUploadModalOpen && (
        <UploadLogsModal
          onClose={() => setIsUploadModalOpen(false)}
          onIngest={handleIngestExternal}
          existingEvents={events}
        />
      )}
    </div>
  );
}
