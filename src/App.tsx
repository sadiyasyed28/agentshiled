import { useState, useEffect, useCallback, useRef } from 'react';
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
import { LoginModal } from './components/LoginModal';
import { SystemHealthModal } from './components/SystemHealthModal';
import { SecuritySettingsModal } from './components/SecuritySettingsModal';
import {
  type HealthStatusType,
  computeHealthStatus,
  deriveSecurityNotifications,
  mapServerAgentToModel,
} from './health';
import type {
  Agent,
  SecurityEvent,
  AttentionItem,
  AlertNotification,
  DecisionType,
  SecurityNotificationItem,
  AgentStatus,
} from './types';
import {
  apiClient,
  ENV_API_URLS,
  type ApiOverviewStats,
  type ApiEventItem,
  type ApiSessionResponse,
  type ApiHealthResponse,
  type ApiReadinessResponse,
  type ApiTelemetryStatusResponse,
  ApiError,
} from './api/client';

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

  // Authentication session state
  const [session, setSession] = useState<ApiSessionResponse | null>(null);
  const [isLoginModalOpen, setIsLoginModalOpen] = useState(false);

  // Operational System Health state
  const [isHealthModalOpen, setIsHealthModalOpen] = useState(false);
  const [isSecuritySettingsOpen, setIsSecuritySettingsOpen] = useState(false);
  const [healthStatus, setHealthStatus] = useState<HealthStatusType>('Loading');
  const [appVersion, setAppVersion] = useState<string>('0.2.0');
  const [appEnvironment, setAppEnvironment] = useState<string>('Staging');

  // Live dashboard state
  const [overviewStats, setOverviewStats] = useState<ApiOverviewStats | null>(null);
  const [liveEvents, setLiveEvents] = useState<SecurityEvent[] | null>(null);
  const [liveAgents, setLiveAgents] = useState<Agent[] | null>(null);
  const [activityData, setActivityData] = useState<DayData[] | null>(null);
  const [riskCounts, setRiskCounts] = useState<{ critical: number; high: number; medium: number; low: number } | null>(null);
  const [notifications, setNotifications] = useState<SecurityNotificationItem[]>([]);

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
  const dismissedAlertIdsRef = useRef<Set<string>>(new Set());

  const handleClearNotifications = () => {
    notifications.forEach((n) => dismissedAlertIdsRef.current.add(n.id));
    setNotifications([]);
    setActiveAlert(null);
  };

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
      const [statsRes, eventsRes, agentsRes, policiesRes, healthRes, readinessRes, telemetryRes, alertsRes] =
        await Promise.allSettled([
          apiClient.getOverview(),
          apiClient.getEvents({ limit: 100 }),
          apiClient.getAgents(),
          apiClient.getPolicies(),
          apiClient.getHealth(),
          apiClient.getReadiness(),
          apiClient.getTelemetryStatus(),
          apiClient.getSecurityAlerts({ limit: 10 }),
        ]);

      let anySuccess = false;

      // Real Operational Health & Diagnostics
      let newHealth: ApiHealthResponse | null = null;
      let newReadiness: ApiReadinessResponse | null = null;
      let newTelemetry: ApiTelemetryStatusResponse | null = null;
      let healthSuccess = false;

      if (healthRes.status === 'fulfilled' && healthRes.value) {
        newHealth = healthRes.value;
        if (newHealth.version) {
          setAppVersion(newHealth.version);
        }
        healthSuccess = true;
      }

      if (readinessRes.status === 'fulfilled' && readinessRes.value) {
        newReadiness = readinessRes.value;
        healthSuccess = true;
      } else if (readinessRes.status === 'rejected') {
        const reason = readinessRes.reason;
        if (reason instanceof ApiError && reason.status === 503) {
          const data = reason.data as Record<string, unknown> | undefined;
          newReadiness = ((data?.detail || data) as ApiReadinessResponse | undefined) || null;
          healthSuccess = true;
        }
      }

      if (telemetryRes.status === 'fulfilled' && telemetryRes.value) {
        newTelemetry = telemetryRes.value;
        healthSuccess = true;
      }

      if (!healthSuccess) {
        setHealthStatus('Unavailable');
      } else {
        const computed = computeHealthStatus(newHealth, newReadiness, newTelemetry, false);
        setHealthStatus(computed);
      }

      if (statsRes.status === 'fulfilled' && statsRes.value) {
        setOverviewStats(statsRes.value);
        if (statsRes.value.is_read_only) {
          setAppEnvironment('Staging (Read-Only)');
        } else {
          setAppEnvironment('Staging');
        }
        anySuccess = true;
      }

      // Build Honest Security Notifications
      const rawAlerts =
        alertsRes.status === 'fulfilled' && Array.isArray(alertsRes.value?.alerts)
          ? alertsRes.value.alerts
          : [];
      const pendingReviews = statsRes.status === 'fulfilled' ? statsRes.value?.pending_reviews_count : 0;
      const pausedList = statsRes.status === 'fulfilled' ? statsRes.value?.paused_agents : [];

      const derivedNotifications = deriveSecurityNotifications(rawAlerts, pendingReviews, pausedList)
        .filter((notif) => !dismissedAlertIdsRef.current.has(notif.id));
      derivedNotifications.forEach((notif) => {
        if (notif.id.startsWith('alert-')) {
          notif.onAction = () => handleSelectTab('Events');
        } else if (notif.id === 'notif-pending-reviews') {
          notif.onAction = () => handleSelectTab('Review');
        } else if (notif.id === 'notif-paused-agents') {
          notif.onAction = () => handleSelectTab('Policies');
        }
      });
      setNotifications(derivedNotifications);

      // Honest Alert Toast trigger for unacknowledged alerts or high-risk blocks
      const unackAlert = rawAlerts.find(
        (a) =>
          !dismissedAlertIdsRef.current.has(`alert-${a.alert_id}`) &&
          (a.severity?.toLowerCase() === 'critical' || a.severity?.toLowerCase() === 'high')
      );
      if (unackAlert && !activeAlert) {
        setActiveAlert({
          id: `alert-${unackAlert.alert_id}`,
          agent: unackAlert.agent_id || 'system',
          severity: unackAlert.severity?.toLowerCase() === 'critical' ? 'critical' : 'warning',
          riskScore: 85,
          timestamp: unackAlert.timestamp ? new Date(unackAlert.timestamp).toLocaleTimeString() : 'Just now',
          reason: unackAlert.description || unackAlert.title || 'Security alert raised',
        });
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

        if (!unackAlert && !activeAlert && rawEvents.length > 0) {
          const highRiskBlocked = rawEvents.find(
            (e) => e.decision === 'BLOCK' && (e.risk_score || 0) >= 80 && !dismissedAlertIdsRef.current.has(`evt-${e.id}`)
          );
          if (highRiskBlocked) {
            setActiveAlert({
              id: `evt-${highRiskBlocked.id}`,
              agent: highRiskBlocked.agent,
              severity: 'critical',
              riskScore: Math.round(highRiskBlocked.risk_score || 85),
              timestamp: highRiskBlocked.timestamp ? new Date(highRiskBlocked.timestamp).toLocaleTimeString() : 'Recently',
              reason: highRiskBlocked.reasons?.[0] || `Action blocked: high-risk invocation of ${highRiskBlocked.tool}`,
            });
          }
        }
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
        const policyAgents = policiesRes.status === 'fulfilled' ? policiesRes.value?.agents : undefined;
        discoveredAgents = serverDiscovered.map((a) => mapServerAgentToModel(a, policyAgents));
      } else {
        discoveredAgents = Array.from(agentMap.entries()).map(([name, data]) => ({
          id: name,
          name,
          status: (paused.includes(name) ? 'Paused' : 'Active') as AgentStatus,
          policy: data.policy,
          events7d: data.total,
          blockedCount: data.blocked,
          blockedRate: data.total > 0 ? `${((data.blocked / data.total) * 100).toFixed(1)}%` : '0.0%',
          runtime: undefined,
          lastActive: data.lastTime ? new Date(data.lastTime).toLocaleString() : undefined,
          description: undefined,
        }));
      }

      setLiveAgents(discoveredAgents);

      if (!anySuccess) {
        setApiError('Unable to connect to AgentShield API. Check server status.');
        setHealthStatus('Unavailable');
        setNotifications([]);
      }
    } catch {
      setApiError('Unable to connect to AgentShield API. Check server status.');
      setHealthStatus('Unavailable');
      setNotifications([]);
    } finally {
      setIsLoading(false);
    }
  }, []);

  const checkSession = useCallback(async () => {
    try {
      const res = await apiClient.getSession();
      setSession(res);
      return res;
    } catch {
      setSession({ authenticated: false, read_only: false, admin_configured: false });
      return null;
    }
  }, []);

  useEffect(() => {
    const unsub = apiClient.onAuthChange((newSession) => {
      setSession(newSession);
    });
    checkSession();
    fetchDashboardData();

    // Lightweight periodic refresh for active alerts and live status
    const interval = window.setInterval(() => {
      if (typeof document !== 'undefined' && document.visibilityState === 'visible') {
        fetchDashboardData();
      }
    }, 15000);

    return () => {
      unsub();
      window.clearInterval(interval);
    };
  }, [checkSession, fetchDashboardData]);

  const handleLoginSuccess = async (newSession: ApiSessionResponse) => {
    setSession(newSession);
    setIsLoginModalOpen(false);
    await fetchDashboardData();
  };

  const handleLogout = async () => {
    try {
      await apiClient.logout();
    } finally {
      setSession({
        authenticated: false,
        read_only: session?.read_only || false,
        admin_configured: session?.admin_configured || false,
      });
      await fetchDashboardData();
    }
  };

  const handleSelectEnvironment = useCallback((newEnv: string) => {
    setAppEnvironment(newEnv);
    const targetUrl = ENV_API_URLS[newEnv] ?? '';
    apiClient.setBaseUrl(targetUrl);
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
    await Promise.allSettled([checkSession(), fetchDashboardData()]);
    setIsRefreshing(false);
  };

  const handleAttentionSelect = (item: AttentionItem) => {
    if (item.id === 'review-actions') {
      handleSelectTab('Review');
    } else if (item.id === 'paused-agent') {
      const pausedAgent = liveAgents?.find((a) => a.status === 'Paused');
      if (pausedAgent) {
        setSelectedAgent(pausedAgent);
      } else {
        handleSelectTab('Policies');
      }
    } else if (item.id === 'high-risk') {
      const highestRisk = liveEvents?.find((e) => e.riskScore >= 61);
      if (highestRisk) {
        setSelectedEvent(highestRisk);
      } else {
        handleSelectTab('Events');
      }
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
        pendingReviewsCount={overviewStats?.pending_reviews_count ?? 0}
        environment={appEnvironment}
        version={appVersion}
        isReadOnly={overviewStats?.is_read_only ?? false}
        onSelectEnvironment={handleSelectEnvironment}
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
          session={session}
          onOpenLogin={() => setIsLoginModalOpen(true)}
          onLogout={handleLogout}
          onOpenSecuritySettings={() => setIsSecuritySettingsOpen(true)}
          healthStatus={healthStatus}
          onOpenHealth={() => setIsHealthModalOpen(true)}
          notifications={notifications}
          onClearNotifications={handleClearNotifications}
        />

        {/* Tab Body View */}
        {currentTab === 'Benchmarks' ? (
          <BenchmarksView />
        ) : currentTab === 'Policies' ? (
          <PoliciesView
            session={session}
            onOpenLogin={() => setIsLoginModalOpen(true)}
          />
        ) : currentTab === 'Review' ? (
          <ReviewView
            onRefreshGlobal={handleRefresh}
            isRefreshingGlobal={isRefreshing}
            session={session}
            onOpenLogin={() => setIsLoginModalOpen(true)}
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
        onDismiss={() => {
          if (activeAlert) {
            dismissedAlertIdsRef.current.add(activeAlert.id);
          }
          setActiveAlert(null);
        }}
        onViewEvent={(alert) => {
          dismissedAlertIdsRef.current.add(alert.id);
          setActiveAlert(null);
          handleSelectTab('Events');
        }}
      />

      {/* 4. COMMAND PALETTE (CMD + K) */}
      <CommandPalette
        isOpen={isSearchOpen}
        onClose={() => setIsSearchOpen(false)}
        onNavigateTab={handleSelectTab}
        onOpenHealth={() => setIsHealthModalOpen(true)}
        onRefresh={handleRefresh}
        onOpenLogin={() => setIsLoginModalOpen(true)}
        onLogout={handleLogout}
        onOpenSecuritySettings={() => setIsSecuritySettingsOpen(true)}
        session={session}
        agents={liveAgents}
        events={liveEvents}
        onSelectAgent={setSelectedAgent}
        onSelectEvent={setSelectedEvent}
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

      {/* 7. ADMIN LOGIN MODAL */}
      <LoginModal
        isOpen={isLoginModalOpen}
        onClose={() => setIsLoginModalOpen(false)}
        onSuccess={handleLoginSuccess}
      />

      {/* 8. SYSTEM HEALTH DIAGNOSTICS MODAL */}
      <SystemHealthModal
        isOpen={isHealthModalOpen}
        onClose={() => setIsHealthModalOpen(false)}
        onHealthLoaded={(status, version) => {
          if (status) setHealthStatus(status);
          if (version) setAppVersion(version);
        }}
      />

      {/* 9. SECURITY SETTINGS & API KEYS MODAL */}
      <SecuritySettingsModal
        isOpen={isSecuritySettingsOpen}
        onClose={() => setIsSecuritySettingsOpen(false)}
        session={session}
        onOpenLogin={() => setIsLoginModalOpen(true)}
      />
    </div>
  );
}

export default App;
