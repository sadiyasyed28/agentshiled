import React, { useState, useMemo, useEffect, useRef } from 'react';
import { PolicyPageHeader } from './PolicyPageHeader';
import { PolicyKpiSection } from './PolicyKpiSection';
import { PolicyToolbar } from './PolicyToolbar';
import { PolicyTable } from './PolicyTable';
import { PolicyDetailPanel } from './PolicyDetailPanel';
import { PolicyModal } from './PolicyModal';
import { AgentsTableView } from './AgentsTableView';
import { INITIAL_POLICIES } from './policyData';
import type { SecurityPolicy, PolicyFilterState } from './policyTypes';
import { apiClient, type ApiSessionResponse, ApiError } from '../../api/client';

interface PoliciesViewProps {
  session?: ApiSessionResponse | null;
  onOpenLogin?: () => void;
}

export const PoliciesView: React.FC<PoliciesViewProps> = ({
  session,
  onOpenLogin,
}) => {
  const [policies, setPolicies] = useState<SecurityPolicy[]>(INITIAL_POLICIES);
  const [isLive, setIsLive] = useState(false);
  const [pausedAgents, setPausedAgents] = useState<string[]>([]);
  const [versionHash, setVersionHash] = useState<string | null>(null);
  const [knownTools, setKnownTools] = useState<string[]>([]);

  // Starts closed so the policy portal only appears on demand
  const [selectedPolicy, setSelectedPolicy] = useState<SecurityPolicy | null>(null);
  const [isDetailClosing, setIsDetailClosing] = useState(false);
  const closeTimerRef = useRef<number | null>(null);

  const [activeMainTab, setActiveMainTab] = useState<'Policies' | 'Agents'>('Policies');

  // Filters
  const [filters, setFilters] = useState<PolicyFilterState>({
    searchQuery: '',
    status: 'All',
    assignedAgent: 'All',
  });

  // Modal state
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [policyToEdit, setPolicyToEdit] = useState<SecurityPolicy | null>(null);

  // Mobile detail drawer
  const [isMobileDetailOpen, setIsMobileDetailOpen] = useState(false);

  // Notification toast
  const [toastMessage, setToastMessage] = useState<string | null>(null);

  const showToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 3500);
  };

  const loadData = async () => {
    try {
      const [policiesRes, agentsRes] = await Promise.allSettled([
        apiClient.getPolicies(),
        apiClient.getAgents(),
      ]);

      if (agentsRes.status === 'fulfilled' && agentsRes.value?.paused_agents) {
        setPausedAgents(agentsRes.value.paused_agents);
      }

      if (policiesRes.status === 'fulfilled' && policiesRes.value?.policies) {
        const pRes = policiesRes.value;
        if (pRes.version_hash) setVersionHash(pRes.version_hash);
        if (pRes.known_tools) setKnownTools(pRes.known_tools);
        const mapped: SecurityPolicy[] = pRes.policies.map((p, idx) => ({
          id: `pol-${idx + 1}`,
          name: p.name,
          version: pRes.version_hash ? pRes.version_hash.slice(0, 8) : 'v1.0.0',
          status: 'Active',
          description: p.description,
          assignedAgentNames: pRes.agents.map((a) => a.name),
          lastUpdated: 'Live Policy',
          lastUpdatedTimestamp: Date.now(),
          rules: {
            allowedTools: pRes.known_tools || [],
            argumentLimits: { maxItemsPerRequest: 100, maxFileSize: '50 MB' },
            allowedHostnames: ['*.internal', 'api.openai.com', 'api.anthropic.com'],
            defaultDeny: true,
            reviewThreshold: 60,
            auditAllActions: true,
          },
          versions: [
            {
              version: pRes.version_hash ? pRes.version_hash.slice(0, 8) : 'v1.0.0',
              date: 'Current Hash',
              author: 'PolicyEngine',
              description: 'Active immutable policy ruleset',
              isCurrent: true,
            },
          ],
          agents: pRes.agents.map((a, i) => ({
            id: `ag-${i + 1}`,
            name: a.name,
            runtime: 'AgentShield Sandbox SDK',
            assignedDate: 'Enforcing',
            status: pausedAgents.includes(a.name) ? 'Paused' : 'Active',
          })),
        }));

        if (mapped.length > 0) {
          setPolicies(mapped);
          setIsLive(true);
        } else {
          setPolicies(INITIAL_POLICIES);
          setIsLive(false);
        }
      } else {
        setPolicies(INITIAL_POLICIES);
        setIsLive(false);
      }
    } catch {
      setPolicies(INITIAL_POLICIES);
      setIsLive(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

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

  // Open (or swap) the policy portal with an enter animation
  const handleSelectPolicy = (pol: SecurityPolicy) => {
    cancelCloseTimer();
    setIsDetailClosing(false);
    setSelectedPolicy(pol);
    setIsMobileDetailOpen(true);
  };

  // Play the exit animation, then unmount the portal
  const handleCloseDetails = () => {
    cancelCloseTimer();
    setIsDetailClosing(true);
    closeTimerRef.current = window.setTimeout(() => {
      setSelectedPolicy(null);
      setIsDetailClosing(false);
      setIsMobileDetailOpen(false);
      closeTimerRef.current = null;
    }, 220);
  };

  const handleFilterChange = <K extends keyof PolicyFilterState>(
    key: K,
    value: PolicyFilterState[K]
  ) => {
    setFilters((prev) => ({ ...prev, [key]: value }));
  };

  const handleResetFilters = () => {
    setFilters({
      searchQuery: '',
      status: 'All',
      assignedAgent: 'All',
    });
  };

  const handleTogglePause = async (agentName: string, currentlyPaused: boolean) => {
    if (!session?.authenticated) {
      showToast('Administrative authentication required to pause or unpause agents.');
      if (onOpenLogin) onOpenLogin();
      return;
    }

    try {
      if (currentlyPaused) {
        await apiClient.unpauseAgent(agentName);
        setPausedAgents((prev) => prev.filter((a) => a !== agentName));
        showToast(`Agent ${agentName} restored to Active on server.`);
      } else {
        await apiClient.pauseAgent(agentName);
        setPausedAgents((prev) => [...prev, agentName]);
        showToast(`Agent ${agentName} paused on server.`);
      }
      await loadData();
    } catch (err: unknown) {
      if (err instanceof ApiError) {
        if (err.status === 403) {
          showToast('Operation Blocked (403): Read-only mode prevents pausing/unpausing agents.');
        } else if (err.status === 401) {
          showToast('Authentication Required (401): Please sign in to pause/unpause agents.');
        } else {
          showToast(`Containment Error (${err.status}): ${err.message}`);
        }
      } else {
        const msg = (err as Error)?.message || 'Failed to update agent status';
        showToast(`Error: ${msg}`);
      }
    }
  };

  // Filtered policies
  const filteredPolicies = useMemo(() => {
    return policies.filter((pol) => {
      // 1. Search Query
      if (filters.searchQuery.trim()) {
        const q = filters.searchQuery.toLowerCase();
        const matchesName = pol.name.toLowerCase().includes(q);
        const matchesDesc = pol.description.toLowerCase().includes(q);
        const matchesVer = pol.version.toLowerCase().includes(q);
        const matchesAgent = pol.assignedAgentNames.some((ag) =>
          ag.toLowerCase().includes(q)
        );
        if (!matchesName && !matchesDesc && !matchesVer && !matchesAgent) {
          return false;
        }
      }

      // 2. Status
      if (filters.status !== 'All' && pol.status !== filters.status) {
        return false;
      }

      // 3. Assigned Agent
      if (
        filters.assignedAgent !== 'All' &&
        !pol.assignedAgentNames.includes(filters.assignedAgent)
      ) {
        return false;
      }

      return true;
    });
  }, [policies, filters]);

  // Counts for KPI section
  const counts = useMemo(() => {
    let active = 0;
    let draft = 0;
    let archived = 0;
    policies.forEach((p) => {
      if (p.status === 'Active') active++;
      else if (p.status === 'Draft') draft++;
      else if (p.status === 'Archived') archived++;
    });
    return {
      total: policies.length,
      active,
      draft,
      archived,
    };
  }, [policies]);

  // Informative policy inspection action
  const handleOpenPolicyInspection = (pol: SecurityPolicy | null) => {
    cancelCloseTimer();
    setIsDetailClosing(false);
    setPolicyToEdit(pol);
    setIsModalOpen(true);
  };

  return (
    <main className="flex-1 px-5 py-3 md:px-6 md:py-3.5 max-w-[1536px] w-full mx-auto flex flex-col justify-between">
      {/* TOAST FEEDBACK */}
      {toastMessage && (
        <div className="fixed top-20 right-8 z-50 px-4 py-2.5 rounded-xl bg-[#221c45] border border-[#6d3ee8] text-white text-xs font-semibold shadow-2xl flex items-center gap-2 animate-in fade-in slide-in-from-top-2 duration-150">
          <span className="w-2 h-2 rounded-full bg-[#22c55e] animate-ping" />
          <span>{toastMessage}</span>
        </div>
      )}

      {/* Status Indicator Banner */}
      <div className="flex items-center justify-between pb-1.5 flex-wrap gap-2">
        <span
          className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-md text-[11px] font-semibold border ${
            isLive
              ? 'bg-[#153e28] text-[#4ade80] border-[#1b6d39]'
              : 'bg-[#2b2559] text-[#c084fc] border-[#3e3478]'
          }`}
        >
          <span className={`w-1.5 h-1.5 rounded-full ${isLive ? 'bg-[#4ade80]' : 'bg-[#c084fc]'}`} />
          {isLive ? 'LIVE POLICIES (Enforced by Engine)' : 'DEMO POLICIES (Offline Dataset)'}
        </span>
        {versionHash && (
          <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-[#1b1739] border border-[#3e3478] text-[#3ddc97]">
            Policy Hash: {versionHash.slice(0, 10)}...
          </span>
        )}
      </div>

      {/* IMMUTABLE POLICY NOTICE BANNER */}
      <div className="mb-3 p-3 bg-[#1e1a3d] border border-[#3e3478] rounded-xl text-xs font-mono text-[#c4bbf0] flex items-center justify-between gap-3 shadow-sm">
        <div className="flex items-center gap-2.5">
          <span className="w-2 h-2 rounded-full bg-[#3ddc97]" />
          <span>
            <strong>Deterministic Policy Engine:</strong> Policies are code-defined immutable constraints verified by SHA-256 hash. Runtime edits are disallowed.
          </span>
        </div>
      </div>

      {/* AUTHENTICATION REQUIRED BANNER */}
      {!session?.authenticated && (
        <div className="mb-3 p-3 bg-[#241740] border border-[#6d3ee8]/60 rounded-xl flex items-center justify-between text-xs shadow-md">
          <div className="flex items-center gap-2.5 text-[#d8b4fe]">
            <span className="w-2 h-2 rounded-full bg-[#facc15] animate-pulse" />
            <span>
              <strong>Administrative Access Required:</strong> Sign in with your admin key to view live enforced policies and pause/unpause agents.
            </span>
          </div>
          {onOpenLogin && (
            <button
              onClick={onOpenLogin}
              className="px-3 py-1 bg-[#6d3ee8] hover:bg-[#7e50f5] text-white rounded-lg font-semibold text-xs transition-colors cursor-pointer flex-shrink-0 shadow-sm"
            >
              Sign In as Admin
            </button>
          )}
        </div>
      )}

      {/* 1. PAGE HEADER */}
      <PolicyPageHeader
        activeMainTab={activeMainTab}
        onSelectMainTab={(tab) => {
          setActiveMainTab(tab);
          if (tab === 'Agents') {
            cancelCloseTimer();
            setSelectedPolicy(null);
            setIsDetailClosing(false);
            setIsMobileDetailOpen(false);
          }
        }}
      />

      {/* 2. BODY CONTENT */}
      {activeMainTab === 'Policies' ? (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-3.5 items-start mt-1">
          {/* LEFT COLUMN: KPIS + TOOLBAR + TABLE */}
          <div
            className={`min-w-0 flex flex-col transition-all duration-300 ${
              selectedPolicy ? 'lg:col-span-8' : 'lg:col-span-12'
            }`}
          >
            {/* KPI CARDS */}
            <PolicyKpiSection
              totalCount={counts.total}
              activeCount={counts.active}
              draftCount={counts.draft}
              archivedCount={counts.archived}
            />

            {/* TOOLBAR */}
            <PolicyToolbar
              filters={filters}
              onFilterChange={handleFilterChange}
              onResetFilters={handleResetFilters}
              onOpenNewPolicy={() => handleOpenPolicyInspection(null)}
            />

            {/* POLICIES TABLE */}
            <PolicyTable
              policies={filteredPolicies}
              selectedPolicy={selectedPolicy}
              onSelectPolicy={handleSelectPolicy}
              onEditPolicy={(pol) => handleOpenPolicyInspection(pol)}
            />
          </div>

          {/* RIGHT COLUMN: ANIMATED POLICY DETAIL PORTAL */}
          {selectedPolicy && (
            <div
              key={selectedPolicy.id}
              className={`hidden lg:block lg:col-span-4 sticky top-[76px] ${
                isDetailClosing ? 'portal-shell-exit' : 'portal-shell-enter'
              }`}
            >
              <PolicyDetailPanel
                policy={selectedPolicy}
                onClose={handleCloseDetails}
                onEditPolicy={(pol) => handleOpenPolicyInspection(pol)}
              />
            </div>
          )}
        </div>
      ) : (
        /* AGENTS TAB VIEW */
        <div className="mt-2">
          <AgentsTableView
            pausedAgentNames={pausedAgents}
            onTogglePause={handleTogglePause}
            onSelectPolicyByName={(pName) => {
              const matched = policies.find((p) => p.name === pName);
              if (matched) {
                handleSelectPolicy(matched);
                setActiveMainTab('Policies');
              }
            }}
          />
        </div>
      )}

      {/* MOBILE DETAIL DRAWER */}
      {isMobileDetailOpen && (
        <div
          className={`fixed inset-0 z-50 lg:hidden flex justify-end bg-black/60 backdrop-blur-xs ${
            isDetailClosing ? 'portal-backdrop-exit' : 'portal-backdrop-enter'
          }`}
        >
          <div className="fixed inset-0" onClick={handleCloseDetails} />
          <div
            className={`relative w-full max-w-md h-full z-10 ${
              isDetailClosing ? 'portal-drawer-exit' : 'portal-drawer-enter'
            }`}
          >
            <PolicyDetailPanel
              policy={selectedPolicy}
              onClose={handleCloseDetails}
              onEditPolicy={(pol) => {
                handleOpenPolicyInspection(pol);
                handleCloseDetails();
              }}
            />
          </div>
        </div>
      )}

      {/* POLICY INSPECTION MODAL */}
      <PolicyModal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        policyToEdit={policyToEdit}
        policyVersionHash={versionHash}
        knownTools={knownTools}
      />
    </main>
  );
};
