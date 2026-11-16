import { useState, useEffect, useCallback } from 'react';
import { Sidebar } from './components/Sidebar';
import { TopNavigation } from './components/TopNavigation';
import { DashboardHeader } from './components/DashboardHeader';
import { KpiSection } from './components/KpiSection';
import { SecurityActivityChart, type DayData } from './components/SecurityActivityChart';
import { DecisionDistribution } from './components/DecisionDistribution';
import { RiskOverview } from './components/RiskOverview';
import { ActiveAgentsTable } from './components/ActiveAgentsTable';
import { AttentionRequired } from './components/AttentionRequired';
import { RecentEventsList } from './components/RecentEventsList';
import { PixelAlertToast } from './components/PixelAlertToast';
import { CommandPalette } from './components/CommandPalette';
import { AgentDetailModal, EventDetailModal } from './components/Modals';
import { EventsView } from './components/events/EventsView';
import { ReviewView } from './components/review/ReviewView';
import { PoliciesView } from './components/policies/PoliciesView';
import { BenchmarksView } from './components/benchmarks/BenchmarksView';
import type { Agent, SecurityEvent, AttentionItem, AlertNotification, DecisionType } from './types';
import { apiClient, type ApiOverviewStats, type ApiEventItem } from './api/client';

export function App() {
  const getInitialTab = () => {
    if (typeof window !== 'undefined') {
      const params = new URLSearchParams(window.location.search);
      const tabParam = params.get('tab');
      if (tabParam) {
        if (tabParam.toLowerCase() === 'overview') return 'Overview';
        if (tabParam.toLowerCase() === 'events') return 'Events';
        if (tabParam.toLowerCase() === 'review') return 'Review';
        if (tabParam.toLowerCase() === 'policies') return 'Policies';
        if (tabParam.toLowerCase() === 'benchmarks') return 'Benchmarks';
      }
      const hash = window.location.hash.replace('#', '').toLowerCase();
      if (hash === 'overview') return 'Overview';
      if (hash === 'events') return 'Events';
      if (hash === 'review') return 'Review';
      if (hash === 'policies') return 'Policies';
      if (hash === 'benchmarks') return 'Benchmarks';
    }
    return 'Overview'; // Default to Overview tab
  };

  const [currentTab, setCurrentTab] = useState(getInitialTab);
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const [isSidebarCollapsed, setIsSidebarCollapsed] = useState(false);
  const [isSearchOpen, setIsSearchOpen] = useState(false);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [apiError, setApiError] = useState<string | null>(null);

  // Live dashboard state
  const [overviewStats, setOverviewStats] = useState<ApiOverviewStats | null>(null);
  const [liveEvents, setLiveEvents] = useState<SecurityEvent[] | null>(null);
  const [liveAgents, setLiveAgents] = useState<Agent[] | null>(null);
  const [activityData, setActivityData] = useState<DayData[] | null>(null);
  const [riskCounts, setRiskCounts] = useState<{ critical: number; high: number; medium: number; low: number } | null>(null);

  const handleSelectTab = (tab: string) => {
    setCurrentTab(tab);
    if (typeof window !== 'undefined') {
      const url = new URL(window.location.href);
      url.searchParams.set('tab', tab.toLowerCase());
      window.history.replaceState(null, '', url.toString());
    }
  };

  // Selected modals
  const [selectedAgent, setSelectedAgent] = useState<Agent | null>(null);
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);

  // Active Alert Notification
  const [activeAlert, setActiveAlert] = useState<AlertNotification | null>(null);

  // Derive daily activity chart from real event timestamps
  const computeActivityFromEvents = (items: ApiEventItem[]): DayData[] | null => {
    if (!items || items.length === 0) return null;
    const days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
    const buckets = new Map<string, { allowed: number; review: number; blocked: number }>();
    days.forEach((d) => buckets.set(d, { allowed: 0, review: 0, blocked: 0 }));

    items.forEach((item) => {
      const date = new Date(item.timestamp);
      if (!isNaN(date.getTime())) {
        const dName = days[date.getDay()];
        const entry = buckets.get(dName) || { allowed: 0, review: 0, blocked: 0 };
        if (item.decision === 'ALLOW') entry.allowed++;
        else if (item.decision === 'REVIEW') entry.review++;
        else entry.blocked++;
        buckets.set(dName, entry);
      }
    });

    const orderedDays = ['Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun', 'Mon'];
    return orderedDays.map((day) => ({
      day,
      allowed: buckets.get(day)?.allowed || 0,
      review: buckets.get(day)?.review || 0,
      blocked: buckets.get(day)?.blocked || 0,
    }));
  };

  const fetchDashboardData = useCallback(async () => {
    setIsLoading(true);
    setApiError(null);
    try {
      const [statsRes, eventsRes, agentsRes, policiesRes] = await Promise.allSettled([
        apiClient.getOverview(),
        apiClient.getEvents({ limit: 100 }),
        apiClient.getAgents(),
        apiClient.getPolicies(),
      ]);

      let anySuccess = false;

      if (statsRes.status === 'fulfilled' && statsRes.value) {
        setOverviewStats(statsRes.value);
        anySuccess = true;
      }

      const rawEvents: ApiEventItem[] =
        eventsRes.status === 'fulfilled' && eventsRes.value?.events
          ? eventsRes.value.events
          : [];

      if (eventsRes.status === 'fulfilled') {
        anySuccess = true;
        const mapped: SecurityEvent[] = rawEvents.slice(0, 4).map((e) => {
          const dec: DecisionType =
            e.decision === 'ALLOW' ? 'Allowed' : e.decision === 'REVIEW' ? 'Review' : 'Blocked';
          return {
            id: `evt-${e.id}`,
            agent: e.agent,
            action: e.tool,
            decision: dec,
            riskScore: Math.round(e.risk_score || 0),
            timestamp: e.timestamp ? new Date(e.timestamp).toLocaleTimeString() : 'Recently',
            payloadSummary: JSON.stringify(e.arguments || {}),
            reason: e.reasons?.[0] || 'Enforced by runtime security policy.',
          };
        });
        setLiveEvents(mapped);

        const derived = computeActivityFromEvents(rawEvents);
        setActivityData(derived);

        const critical = rawEvents.filter((e) => (e.risk_score || 0) >= 81).length;
        const high = rawEvents.filter((e) => (e.risk_score || 0) >= 61 && (e.risk_score || 0) <= 80).length;
        const medium = rawEvents.filter((e) => (e.risk_score || 0) >= 31 && (e.risk_score || 0) <= 60).length;
        const low = rawEvents.filter((e) => (e.risk_score || 0) <= 30).length;
        setRiskCounts({ critical, high, medium, low });
      }

      const paused =
        agentsRes.status === 'fulfilled' && agentsRes.value?.paused_agents
          ? agentsRes.value.paused_agents
          : [];

      if (agentsRes.status === 'fulfilled') {
        anySuccess = true;
      }

      const agentMap = new Map<string, { total: number; blocked: number; lastTime: string; policy: string }>();
      rawEvents.forEach((e) => {
        if (!e.agent) return;
        const cur = agentMap.get(e.agent) || {
          total: 0,
          blocked: 0,
          lastTime: e.timestamp,
          policy: e.policy_version_hash ? `Policy (${e.policy_version_hash.slice(0, 7)})` : 'Enforced Policy',
        };
        cur.total += 1;
        if (e.decision === 'BLOCK') cur.blocked += 1;
        agentMap.set(e.agent, cur);
      });

      if (policiesRes.status === 'fulfilled' && policiesRes.value?.agents) {
        anySuccess = true;
        policiesRes.value.agents.forEach((a) => {
          if (!agentMap.has(a.name)) {
            agentMap.set(a.name, {
              total: 0,
              blocked: 0,
              lastTime: '',
              policy: 'Assigned Policy',
            });
          }
        });
      }

      const serverDiscovered =
        agentsRes.status === 'fulfilled' && Array.isArray(agentsRes.value?.agents)
          ? agentsRes.value.agents
          : null;

      let discoveredAgents: Agent[] = [];
      if (serverDiscovered && serverDiscovered.length > 0) {
        discoveredAgents = serverDiscovered.map((a) => ({
          id: a.name,
          name: a.name,
          status: a.is_paused ? 'Paused' : 'Active',
          policy: 'Enforced Policy',
          events7d: a.total_events,
          blockedCount: a.blocked_count,
          blockedRate: a.total_events > 0 ? `${((a.blocked_count / a.total_events) * 100).toFixed(1)}%` : '0.0%',
          runtime: 'Agent Runtime',
          lastActive: a.last_active ? new Date(a.last_active).toLocaleTimeString() : 'No recent activity',
          description: `Autonomous agent '${a.name}' under AgentShield runtime protection.`,
        }));
      } else {
        discoveredAgents = Array.from(agentMap.entries()).map(([name, data]) => ({
          id: name,
          name,
          status: paused.includes(name) ? 'Paused' : 'Active',
          policy: data.policy,
          events7d: data.total,
          blockedCount: data.blocked,
          blockedRate: data.total > 0 ? `${((data.blocked / data.total) * 100).toFixed(1)}%` : '0.0%',
          runtime: 'Agent Runtime',
          lastActive: data.lastTime ? new Date(data.lastTime).toLocaleTimeString() : 'No recent activity',
          description: `Autonomous agent '${name}' under AgentShield runtime protection.`,
        }));
      }

      setLiveAgents(discoveredAgents);

      if (!anySuccess) {
        setApiError('Unable to connect to AgentShield API. Check server status.');
      }
    } catch {
      setApiError('Unable to connect to AgentShield API. Check server status.');
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchDashboardData();
  }, [fetchDashboardData]);

  // Global CMD + K shortcut
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setIsSearchOpen((prev) => !prev);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  const handleRefresh = async () => {
    setIsRefreshing(true);
    await fetchDashboardData();
    setIsRefreshing(false);
    setActiveAlert({
      id: `alert-${Date.now()}`,
      agent: 'email-agent',
      reason: 'Outbound volume threshold exceeded under Restricted v1 policy.',
      riskScore: 68,
      severity: 'warning',
      timestamp: 'Just now',
    });
  };

  const handleAttentionSelect = (item: AttentionItem) => {
    if (item.id === 'paused-agent') {
      setSelectedAgent({
        id: 'email-agent',
        name: 'email-agent',
        status: 'Paused',
        policy: 'Restricted v1',
        events7d: 421,
        blockedCount: 53,
        blockedRate: '12.6%',
        runtime: 'Python Autogen v0.4',
        lastActive: '34m ago',
        description: 'Outbound dispatch agent paused due to high risk score anomaly.',
      });
    } else {
      setSelectedEvent({
        id: `attn-${item.id}`,
        agent: 'ops-agent',
        action: item.text,
        decision: item.severity === 'red' ? 'Blocked' : 'Review',
        riskScore: item.severity === 'red' ? 87 : 68,
        timestamp: 'Recently',
        reason: item.details,
      });
    }
  };

  return (
    <div className="min-h-screen bg-[#0e0d21] text-[#e2e1f0] flex">
      {/* 1. LEFT COLLAPSIBLE SIDEBAR */}
      <Sidebar
        currentTab={currentTab}
        onSelectTab={handleSelectTab}
        isCollapsed={isSidebarCollapsed}
        onToggleCollapse={() => setIsSidebarCollapsed(!isSidebarCollapsed)}
        isOpenMobile={isMobileMenuOpen}
        onCloseMobile={() => setIsMobileMenuOpen(false)}
      />

      {/* 2. MAIN VIEW CONTAINER */}
      <div
        className={`flex-1 flex flex-col min-w-0 transition-all duration-300 ease-in-out ${
          isSidebarCollapsed ? 'lg:pl-[72px]' : 'lg:pl-[272px]'
        }`}
      >
        {/* Top Navigation */}
        <TopNavigation
          title={currentTab === 'Policies' ? 'Policies & Agents' : currentTab}
          onOpenSearch={() => setIsSearchOpen(true)}
          onToggleMobileMenu={() => setIsMobileMenuOpen(true)}
          isCollapsed={isSidebarCollapsed}
          onToggleCollapse={() => setIsSidebarCollapsed(!isSidebarCollapsed)}
        />

        {/* Tab Body View */}
        {currentTab === 'Benchmarks' ? (
          <BenchmarksView />
        ) : currentTab === 'Policies' ? (
          <PoliciesView />
        ) : currentTab === 'Review' ? (
          <ReviewView
            onRefreshGlobal={handleRefresh}
            isRefreshingGlobal={isRefreshing}
          />
        ) : currentTab === 'Events' ? (
          <EventsView
            onRefreshGlobal={handleRefresh}
            isRefreshingGlobal={isRefreshing}
          />
        ) : (
          <main className="flex-1 px-5 py-2.5 md:px-6 md:py-3 max-w-[1536px] w-full mx-auto flex flex-col gap-3">
            {/* Header Section: Greeting + Pixel Backdrop + Actions */}
            <DashboardHeader
              onRefresh={handleRefresh}
              isRefreshing={isRefreshing}
            />

            {/* API Error Notification */}
            {apiError && (
              <div className="p-3 bg-[#4a1c25]/50 border border-[#782836] rounded-lg text-xs flex items-center justify-between shadow-sm">
                <span className="text-[#f87171] font-mono flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-[#f87171] animate-pulse" />
                  {apiError}
                </span>
                <button
                  onClick={handleRefresh}
                  className="px-2.5 py-1 bg-[#4a1c25] hover:bg-[#5e232e] text-[#f87171] hover:text-white border border-[#782836] rounded text-[11px] font-semibold transition-colors cursor-pointer"
                >
                  Retry Connection
                </button>
              </div>
            )}

            {/* KPI Section: 4 Metric Cards with Sparklines */}
            <KpiSection
              stats={
                overviewStats
                  ? {
                      total: overviewStats.total_evaluated,
                      allowed: overviewStats.allow_count,
                      review: overviewStats.review_count,
                      blocked: overviewStats.block_count,
                    }
                  : null
              }
              isLoading={isLoading}
            />

            {/* Middle Analytics Grid: 3 Panels */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-3 items-stretch">
              <div className="lg:col-span-6 xl:col-span-6 flex flex-col">
                <SecurityActivityChart activityData={activityData} />
              </div>
              <div className="lg:col-span-3 xl:col-span-3 flex flex-col">
                <DecisionDistribution
                  counts={
                    overviewStats
                      ? {
                          allowed: overviewStats.allow_count,
                          review: overviewStats.review_count,
                          blocked: overviewStats.block_count,
                        }
                      : null
                  }
                />
              </div>
              <div className="lg:col-span-3 xl:col-span-3 flex flex-col">
                <RiskOverview counts={riskCounts} />
              </div>
            </div>

            {/* Bottom Grid: 3 Panels */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-3 items-stretch">
              <div className="lg:col-span-6 xl:col-span-6 flex flex-col">
                <ActiveAgentsTable
                  agents={liveAgents || []}
                  onSelectAgent={setSelectedAgent}
                  onViewAll={() => setIsSearchOpen(true)}
                />
              </div>
              <div className="lg:col-span-3 xl:col-span-3 flex flex-col">
                <AttentionRequired
                  onSelectItem={handleAttentionSelect}
                  pendingReviewsCount={overviewStats?.pending_reviews_count ?? 0}
                  pausedAgents={overviewStats?.paused_agents ?? []}
                  highRiskCount={riskCounts ? riskCounts.critical + riskCounts.high : 0}
                />
              </div>
              <div className="lg:col-span-3 xl:col-span-3 flex flex-col">
                <RecentEventsList
                  events={liveEvents || []}
                  onSelectEvent={setSelectedEvent}
                  onViewAll={() => setIsSearchOpen(true)}
                />
              </div>
            </div>
          </main>
        )}
      </div>

      {/* 3. INTERACTIVE PIXEL ALERT TOAST */}
      <PixelAlertToast
        alert={activeAlert}
        onDismiss={() => setActiveAlert(null)}
        onViewEvent={(alert) => {
          setSelectedEvent({
            id: alert.id,
            agent: alert.agent,
            action: 'anomaly_investigation',
            decision: alert.severity === 'critical' ? 'Blocked' : 'Review',
            riskScore: alert.riskScore,
            timestamp: alert.timestamp,
            reason: alert.reason,
            payloadSummary: `Payload inspection flagged for ${alert.agent}.\nAnomaly pattern detected in outbound packets.`,
          });
          setActiveAlert(null);
        }}
      />

      {/* 4. COMMAND PALETTE (CMD + K) */}
      <CommandPalette
        isOpen={isSearchOpen}
        onClose={() => setIsSearchOpen(false)}
        onSelectAction={(actionName) => {
          console.log('Action selected:', actionName);
        }}
      />

      {/* 5. AGENT DETAIL MODAL */}
      <AgentDetailModal
        agent={selectedAgent}
        onClose={() => setSelectedAgent(null)}
      />

      {/* 6. EVENT DETAIL MODAL */}
      <EventDetailModal
        event={selectedEvent}
        onClose={() => setSelectedEvent(null)}
      />
    </div>
  );
}

export default App;
