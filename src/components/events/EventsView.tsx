import React, { useState, useMemo, useEffect, useRef } from 'react';
import { EventsPageHeader } from './EventsPageHeader';
import { EventsKpiSection } from './EventsKpiSection';
import { EventsFilterToolbar } from './EventsFilterToolbar';
import { EventsTable } from './EventsTable';
import { EventDrawer } from './EventDrawer';
import { ALL_EVENTS } from './eventsData';
import type { SecurityEventRecord, EventsFilterState, EventDecision, ExecutionStatus } from './eventsTypes';
import { apiClient, type ApiEventItem } from '../../api/client';

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
  const [eventsList, setEventsList] = useState<SecurityEventRecord[]>(ALL_EVENTS);
  const [isLive, setIsLive] = useState(false);

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
    try {
      const res = await apiClient.getEvents({ limit: 100 });
      if (res && Array.isArray(res.events) && res.events.length > 0) {
        const mapped = res.events.map(mapApiEventToRecord);
        setEventsList(mapped);
        setIsLive(true);
      } else {
        setEventsList(ALL_EVENTS);
        setIsLive(false);
      }
    } catch {
      // Offline or network error: fall back to rich demo dataset
      setEventsList(ALL_EVENTS);
      setIsLive(false);
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
  const filteredEvents = useMemo(() => {
    return eventsList.filter((evt) => {
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
  }, [eventsList, filters]);

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
          <div className="flex items-center justify-between pb-1.5">
            <span
              className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-md text-[11px] font-semibold border ${
                isLive
                  ? 'bg-[#153e28] text-[#4ade80] border-[#1b6d39]'
                  : 'bg-[#2b2559] text-[#c084fc] border-[#3e3478]'
              }`}
            >
              <span className={`w-1.5 h-1.5 rounded-full ${isLive ? 'bg-[#4ade80]' : 'bg-[#c084fc]'}`} />
              {isLive ? 'LIVE TELEMETRY (Connected)' : 'DEMO MODE (Offline Dataset)'}
            </span>
          </div>

          {/* 1. EVENTS PAGE HEADER */}
          <EventsPageHeader
            onRefresh={handleRefresh}
            isRefreshing={localRefreshing || isRefreshingGlobal}
            onExport={handleExport}
            dateRange={dateRange}
            onDateRangeChange={setDateRange}
          />

          {/* 2. KPI CARDS SECTION */}
          <EventsKpiSection />

          {/* 3. FILTER AND SEARCH TOOLBAR */}
          <EventsFilterToolbar
            filters={filters}
            onFilterChange={handleFilterChange}
            onClearAll={handleClearAll}
            activeFilterCount={activeFilterCount}
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
