import React, { useState, useMemo, useEffect, useRef } from 'react';
import { EventsPageHeader } from './EventsPageHeader';
import { EventsKpiSection } from './EventsKpiSection';
import { EventsFilterToolbar } from './EventsFilterToolbar';
import { EventsTable } from './EventsTable';
import { EventDrawer } from './EventDrawer';
import { PixelLayersIcon } from '../pixel/PixelIcons';
import { ALL_EVENTS } from './eventsData';
import type { SecurityEventRecord, EventsFilterState, EventDecision, ExecutionStatus } from './eventsTypes';
import { apiClient, type ApiEventItem, type ApiAuditVerifyResponse, ApiError } from '../../api/client';

interface EventsViewProps {
  onRefreshGlobal?: () => void;
  isRefreshingGlobal?: boolean;
}

export const EventsView: React.FC<EventsViewProps> = ({
  onRefreshGlobal,
  isRefreshingGlobal = false,
}) => {
  // Filter state
  const [filters, setFilters] = useState<EventsFilterState>({
    searchQuery: '',
    decision: 'All',
    agent: 'All',
    tool: 'All',
    riskRange: 'All',
    execution: 'All',
    policy: 'All',
  });

  // Table state
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(8);
  const [sortOrder, setSortOrder] = useState<'desc' | 'asc'>('desc');
  const [dateRange, setDateRange] = useState('Last 7 Days');
  const [localRefreshing, setLocalRefreshing] = useState(false);
  const [eventsList, setEventsList] = useState<SecurityEventRecord[]>([]);
  const [isLive, setIsLive] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [apiError, setApiError] = useState<string | null>(null);
  const [showDemoDataset, setShowDemoDataset] = useState(false);

  // Audit Hash Chain Verification State
  const [isVerifyingAudit, setIsVerifyingAudit] = useState(false);
  const [auditVerifyResult, setAuditVerifyResult] = useState<ApiAuditVerifyResponse | null>(null);
  const [auditVerifyError, setAuditVerifyError] = useState<string | null>(null);

  const handleVerifyAudit = async () => {
    setIsVerifyingAudit(true);
    setAuditVerifyResult(null);
    setAuditVerifyError(null);
    try {
      const res = await apiClient.verifyAuditIntegrity();
      setAuditVerifyResult(res);
    } catch (err: unknown) {
      if (err instanceof ApiError) {
        if (err.status === 403) {
          setAuditVerifyError('Verification Forbidden (403): Global administrator privilege required to verify audit hash chain.');
        } else if (err.status === 401) {
          setAuditVerifyError('Authentication Required (401): Please sign in to verify audit integrity.');
        } else {
          setAuditVerifyError(`Audit verification failed (${err.status}): ${err.message}`);
        }
      } else {
        setAuditVerifyError('Failed to verify audit hash chain: Network or server error.');
      }
    } finally {
      setIsVerifyingAudit(false);
    }
  };

  // Selected event for detail drawer
  const [selectedEvent, setSelectedEvent] = useState<SecurityEventRecord | null>(null);
  const [isDrawerClosing, setIsDrawerClosing] = useState(false);
  const closeTimerRef = useRef<number | null>(null);

  // Clear any pending close timer when the view unmounts
  useEffect(() => {
    return () => {
      if (closeTimerRef.current !== null) {
        window.clearTimeout(closeTimerRef.current);
      }
    };
  }, []);

  const cancelCloseTimer = () => {
    if (closeTimerRef.current !== null) {
      window.clearTimeout(closeTimerRef.current);
      closeTimerRef.current = null;
    }
  };

  const mapApiEventToRecord = (apiEvt: ApiEventItem): SecurityEventRecord => {
    const rawTime = Date.parse(apiEvt.timestamp) || Date.now();
    const d: EventDecision =
      apiEvt.decision === 'ALLOW'
        ? 'Allowed'
        : apiEvt.decision === 'REVIEW'
        ? 'Review'
        : 'Blocked';
    const ex: ExecutionStatus =
      apiEvt.execution_status === 'executed'
        ? 'Executed'
        : apiEvt.execution_status === 'error'
        ? 'Not Executed'
        : 'Not Executed';

    return {
      id: `EVT-${apiEvt.id}`,
      timestamp: apiEvt.timestamp ? new Date(apiEvt.timestamp).toLocaleTimeString() : 'Just now',
      timestampRaw: rawTime,
      agent: apiEvt.agent,
      tool: apiEvt.tool,
      decision: d,
      riskScore: Math.round(apiEvt.risk_score || 0),
      execution: ex,
      policy: apiEvt.policy_version_hash
        ? `Policy (${apiEvt.policy_version_hash.slice(0, 7)})`
        : 'Enforced Policy v1',
      actionSummary: `Agent ${apiEvt.agent} invoked ${apiEvt.tool}`,
      callerIp: '127.0.0.1 (Internal Runtime)',
      targetResource: apiEvt.tool,
      argumentsPayload: apiEvt.arguments,
      riskFactors: apiEvt.rules_triggered || [],
      policyMatchedRule: apiEvt.reasons?.[0] || 'Standard Policy Rule',
      decisionRationale: apiEvt.reasons?.join(', ') || 'Evaluated by PolicyEngine',
    };
  };

  const loadEvents = async () => {
    setIsLoading(true);
    setApiError(null);
    try {
      const res = await apiClient.getEvents({ limit: 100 });
      if (res && Array.isArray(res.events)) {
        const mapped = res.events.map(mapApiEventToRecord);
        setEventsList(mapped);
        setIsLive(true);
      } else {
        setEventsList([]);
        setIsLive(true);
      }
    } catch {
      setEventsList([]);
      setIsLive(false);
      setApiError('Unable to load security events from AgentShield API.');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadEvents();
  }, []);

  // Open (or swap) the event drawer with an enter animation
  const handleSelectEvent = (evt: SecurityEventRecord) => {
    cancelCloseTimer();
    setIsDrawerClosing(false);
    setSelectedEvent(evt);
  };

  // Play the exit animation, then unmount the drawer
  const handleCloseDrawer = () => {
    cancelCloseTimer();
    setIsDrawerClosing(true);
    closeTimerRef.current = window.setTimeout(() => {
      setSelectedEvent(null);
      setIsDrawerClosing(false);
      closeTimerRef.current = null;
    }, 220);
  };

  // Active filter count
  const activeFilterCount = useMemo(() => {
    let count = 0;
    if (filters.searchQuery.trim()) count++;
    if (filters.decision !== 'All') count++;
    if (filters.agent !== 'All') count++;
    if (filters.tool !== 'All') count++;
    if (filters.riskRange !== 'All') count++;
    if (filters.execution !== 'All') count++;
    if (filters.policy !== 'All') count++;
    return count;
  }, [filters]);

  const handleFilterChange = <K extends keyof EventsFilterState>(
    key: K,
    value: EventsFilterState[K]
  ) => {
    setFilters((prev) => ({ ...prev, [key]: value }));
    setCurrentPage(1);
  };

  const handleClearAll = () => {
    setFilters({
      searchQuery: '',
      decision: 'All',
      agent: 'All',
      tool: 'All',
      riskRange: 'All',
      execution: 'All',
      policy: 'All',
    });
    setCurrentPage(1);
  };

  // Filtered dataset
  const activeDataset = showDemoDataset ? ALL_EVENTS : eventsList;

  const availableAgents = useMemo(() => {
    return Array.from(new Set(activeDataset.map((e) => e.agent).filter(Boolean)));
  }, [activeDataset]);

  const availableTools = useMemo(() => {
    return Array.from(new Set(activeDataset.map((e) => e.tool).filter(Boolean)));
  }, [activeDataset]);

  const availablePolicies = useMemo(() => {
    return Array.from(new Set(activeDataset.map((e) => e.policy).filter(Boolean)));
  }, [activeDataset]);

  const filteredEvents = useMemo(() => {
    return activeDataset.filter((evt) => {
      // 1. Search query
      if (filters.searchQuery.trim()) {
        const query = filters.searchQuery.toLowerCase();
        const matchesId = evt.id.toLowerCase().includes(query);
        const matchesAgent = evt.agent.toLowerCase().includes(query);
        const matchesTool = evt.tool.toLowerCase().includes(query);
        const matchesPolicy = evt.policy.toLowerCase().includes(query);
        if (!matchesId && !matchesAgent && !matchesTool && !matchesPolicy) {
          return false;
        }
      }

      // 2. Decision
      if (filters.decision !== 'All' && evt.decision !== filters.decision) {
        return false;
      }

      // 3. Agent
      if (filters.agent !== 'All' && evt.agent !== filters.agent) {
        return false;
      }

      // 4. Tool
      if (filters.tool !== 'All' && evt.tool !== filters.tool) {
        return false;
      }

      // 5. Risk Range
      if (filters.riskRange !== 'All') {
        if (filters.riskRange === 'Low (0-30)' && (evt.riskScore < 0 || evt.riskScore > 30)) {
          return false;
        }
        if (filters.riskRange === 'Medium (31-70)' && (evt.riskScore < 31 || evt.riskScore > 70)) {
          return false;
        }
        if (filters.riskRange === 'High (71-100)' && (evt.riskScore < 71 || evt.riskScore > 100)) {
          return false;
        }
      }

      // 6. Execution
      if (filters.execution !== 'All' && evt.execution !== filters.execution) {
        return false;
      }

      // 7. Policy
      if (filters.policy !== 'All' && evt.policy !== filters.policy) {
        return false;
      }

      return true;
    });
  }, [activeDataset, filters]);

  // Sorted dataset
  const sortedEvents = useMemo(() => {
    const list = [...filteredEvents];
    list.sort((a, b) => {
      if (sortOrder === 'desc') {
        return b.timestampRaw - a.timestampRaw;
      } else {
        return a.timestampRaw - b.timestampRaw;
      }
    });
    return list;
  }, [filteredEvents, sortOrder]);

  // Paginated dataset
  const paginatedEvents = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return sortedEvents.slice(start, start + pageSize);
  }, [sortedEvents, currentPage, pageSize]);

  const displayTotalCount = sortedEvents.length;

  const handleExport = (format: 'csv' | 'json') => {
    const dataToExport = sortedEvents;
    if (format === 'json') {
      const blob = new Blob([JSON.stringify(dataToExport, null, 2)], {
        type: 'application/json',
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `agentshield_events_${Date.now()}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } else {
      const headers = ['Timestamp', 'Event ID', 'Agent', 'Tool', 'Decision', 'Risk Score', 'Execution', 'Policy'];
      const rows = dataToExport.map((e) => [
        `"${e.timestamp}"`,
        `"${e.id}"`,
        `"${e.agent}"`,
        `"${e.tool}"`,
        `"${e.decision}"`,
        e.riskScore,
        `"${e.execution}"`,
        `"${e.policy}"`,
      ]);
      const csvContent = [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
      const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `agentshield_events_${Date.now()}.csv`;
      a.click();
      URL.revokeObjectURL(url);
    }
  };

  const handleRefresh = async () => {
    setLocalRefreshing(true);
    if (onRefreshGlobal) onRefreshGlobal();
    await loadEvents();
    setLocalRefreshing(false);
  };

  return (
    <main className="flex-1 px-5 py-3 md:px-6 md:py-3.5 max-w-[1536px] w-full mx-auto flex flex-col justify-between">
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-3.5 items-start">
        {/* LEFT WORKSPACE */}
        <div
          className={`min-w-0 transition-all duration-300 ${
            selectedEvent ? 'lg:col-span-8' : 'lg:col-span-12'
          }`}
        >
          {/* Status Indicator Banner */}
          <div className="flex items-center justify-between pb-1.5 flex-wrap gap-2">
            <span
              className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-md text-[11px] font-semibold border ${
                showDemoDataset
                  ? 'bg-[#403413] text-[#facc15] border-[#6b551c]'
                  : isLive
                  ? 'bg-[#153e28] text-[#4ade80] border-[#1b6d39]'
                  : 'bg-[#4a1c25] text-[#f87171] border-[#782836]'
              }`}
            >
              <span
                className={`w-1.5 h-1.5 rounded-full ${
                  showDemoDataset ? 'bg-[#facc15]' : isLive ? 'bg-[#4ade80]' : 'bg-[#f87171]'
                }`}
              />
              {showDemoDataset
                ? 'REFERENCE / DEMO DATASET (Static Fixtures)'
                : isLive
                ? `LIVE TELEMETRY (${eventsList.length} Events)`
                : 'API DISCONNECTED'}
            </span>

            <button
              onClick={() => setShowDemoDataset((prev) => !prev)}
              className="text-[11px] font-mono px-2 py-0.5 rounded bg-[#1e1a3d] hover:bg-[#2b2559] border border-[#3e3478] text-[#c084fc] transition-colors cursor-pointer"
            >
              {showDemoDataset ? '← Switch to Live Events' : 'View Sample Reference Dataset'}
            </button>
          </div>

          {/* API Error Notification */}
          {apiError && (
            <div className="mb-3 p-3 bg-[#4a1c25]/50 border border-[#782836] rounded-lg text-xs flex items-center justify-between shadow-sm">
              <span className="text-[#f87171] font-mono flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-[#f87171] animate-pulse" />
                {apiError}
              </span>
              <button
                onClick={loadEvents}
                className="px-2.5 py-1 bg-[#4a1c25] hover:bg-[#5e232e] text-[#f87171] hover:text-white border border-[#782836] rounded text-[11px] font-semibold transition-colors cursor-pointer"
              >
                Retry
              </button>
            </div>
          )}

          {/* Empty State Banner if no events and not loading */}
          {!showDemoDataset && eventsList.length === 0 && !isLoading && !apiError && (
            <div className="mb-3 p-4 bg-[#16142e] border border-[#2b2559] rounded-lg text-center pixel-corners">
              <div className="w-8 h-8 rounded-full bg-[#26204d] text-[#c4bbf0] flex items-center justify-center mx-auto mb-2">
                <PixelLayersIcon size={18} />
              </div>
              <h4 className="text-white text-sm font-semibold">No Security Events Recorded</h4>
              <p className="text-xs text-[#8e87bf] mt-1 max-w-md mx-auto">
                Your agents haven't generated any tool proposals yet. Run an agent with the AgentShield Python SDK to begin streaming real-time security events.
              </p>
              <div className="mt-2.5 flex items-center justify-center gap-2">
                <button
                  onClick={() => setShowDemoDataset(true)}
                  className="px-2.5 py-1 bg-[#231e47] hover:bg-[#302a5c] text-[#c084fc] border border-[#403775] rounded text-xs font-mono cursor-pointer"
                >
                  Inspect Sample Event Format
                </button>
              </div>
            </div>
          )}

          {/* 1. EVENTS PAGE HEADER */}
          <EventsPageHeader
            onRefresh={handleRefresh}
            isRefreshing={localRefreshing || isRefreshingGlobal}
            onExport={handleExport}
            dateRange={dateRange}
            onDateRangeChange={setDateRange}
            onVerifyAudit={handleVerifyAudit}
            isVerifyingAudit={isVerifyingAudit}
          />

          {/* AUDIT HASH CHAIN VERIFICATION STATUS BANNER */}
          {isVerifyingAudit && (
            <div className="mb-3 p-3 bg-[#1e1a3d] border border-[#6d3ee8] rounded-xl text-xs font-mono flex items-center gap-3 text-[#c4bbf0] shadow-sm animate-pulse">
              <span className="w-2.5 h-2.5 rounded-full bg-[#a855f7] animate-ping" />
              <span>Cryptographic Verification In Progress: Recomputing SHA-256 hash chain over all persisted audit events...</span>
            </div>
          )}

          {auditVerifyResult && (
            <div
              className={`mb-3 p-3.5 rounded-xl border text-xs font-mono flex items-start justify-between gap-3 shadow-md ${
                auditVerifyResult.valid
                  ? 'bg-[#153e28]/90 border-[#22c55e] text-[#bbf7d0]'
                  : 'bg-[#4a1c25]/90 border-[#ef4444] text-[#fca5a5]'
              }`}
            >
              <div className="space-y-1">
                <div className="font-bold flex items-center gap-2 text-[13px]">
                  <span
                    className={`w-2 h-2 rounded-full ${
                      auditVerifyResult.valid ? 'bg-[#22c55e]' : 'bg-[#ef4444]'
                    }`}
                  />
                  {auditVerifyResult.valid
                    ? 'Audit Hash-Chain Verified: Cryptographic Integrity Confirmed'
                    : 'Audit Integrity Failure: Tampering or Sequence Corruption Detected!'}
                </div>
                <div className="text-[11.5px] opacity-90">
                  {auditVerifyResult.valid ? (
                    <span>
                      SHA-256 integrity verified across all {auditVerifyResult.total_records} audit records. Zero sequence gaps or altered digests detected.
                    </span>
                  ) : (
                    <span>
                      Total records checked: {auditVerifyResult.total_records}. Error: {auditVerifyResult.error || 'Hash mismatch'}.
                      {auditVerifyResult.corrupted_record_id !== undefined && auditVerifyResult.corrupted_record_id !== null && (
                        <span className="font-semibold text-white ml-1">
                          Corrupted record ID: {auditVerifyResult.corrupted_record_id}
                        </span>
                      )}
                    </span>
                  )}
                </div>
              </div>
              <button
                onClick={() => setAuditVerifyResult(null)}
                className="px-2 py-1 bg-black/30 hover:bg-black/50 border border-white/20 rounded text-[10px] text-white transition-colors cursor-pointer"
              >
                Dismiss
              </button>
            </div>
          )}

          {auditVerifyError && (
            <div className="mb-3 p-3.5 bg-[#401a24] border border-[#f87171] rounded-xl text-xs font-mono flex items-start justify-between gap-3 text-[#fecaca] shadow-md">
              <div className="space-y-1">
                <div className="font-bold flex items-center gap-2 text-[13px] text-[#f87171]">
                  <span className="w-2 h-2 rounded-full bg-[#f87171]" />
                  Audit Verification Unavailable
                </div>
                <div className="text-[11.5px] text-[#fca5a5]">{auditVerifyError}</div>
              </div>
              <button
                onClick={() => setAuditVerifyError(null)}
                className="px-2 py-1 bg-black/30 hover:bg-black/50 border border-white/20 rounded text-[10px] text-white transition-colors cursor-pointer"
              >
                Dismiss
              </button>
            </div>
          )}

          {/* 2. KPI CARDS SECTION */}
          <EventsKpiSection events={activeDataset} />

          {/* 3. FILTER AND SEARCH TOOLBAR */}
          <EventsFilterToolbar
            filters={filters}
            onFilterChange={handleFilterChange}
            onClearAll={handleClearAll}
            activeFilterCount={activeFilterCount}
            availableAgents={availableAgents}
            availableTools={availableTools}
            availablePolicies={availablePolicies}
          />

          {/* 4. EVENTS TABLE & PAGINATION */}
          <EventsTable
            events={paginatedEvents}
            totalCount={displayTotalCount}
            currentPage={currentPage}
            pageSize={pageSize}
            onPageChange={setCurrentPage}
            onPageSizeChange={(newSize) => {
              setPageSize(newSize);
              setCurrentPage(1);
            }}
            onSelectEvent={handleSelectEvent}
            onFilterByAgent={(agent) => handleFilterChange('agent', agent)}
            onFilterByTool={(tool) => handleFilterChange('tool', tool)}
            sortOrder={sortOrder}
            onToggleSort={() => setSortOrder((prev) => (prev === 'desc' ? 'asc' : 'desc'))}
          />
        </div>

        {/* RIGHT WORKSPACE: ANIMATED EVENT DETAILS PANEL */}
        {selectedEvent && (
          <div
            key={selectedEvent.id}
            className={`hidden lg:block lg:col-span-4 sticky top-[76px] pt-2 ${
              isDrawerClosing ? 'portal-shell-exit' : 'portal-shell-enter'
            }`}
          >
            <EventDrawer
              variant="panel"
              event={selectedEvent}
              onClose={handleCloseDrawer}
            />
          </div>
        )}
      </div>

      {/* MOBILE / TABLET ANIMATED EVENT DRAWER */}
      <EventDrawer
        key={selectedEvent?.id ?? 'event-drawer'}
        variant="drawer"
        event={selectedEvent}
        onClose={handleCloseDrawer}
        isClosing={isDrawerClosing}
      />
    </main>
  );
};
