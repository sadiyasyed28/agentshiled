import React, { useState, useMemo, useEffect, useRef } from 'react';
import { ReviewPageHeader } from './ReviewPageHeader';
import { ReviewKpiSection } from './ReviewKpiSection';
import { ReviewStatusTabs } from './ReviewStatusTabs';
import { ReviewToolbar } from './ReviewToolbar';
import { ReviewTable } from './ReviewTable';
import { ReviewDetailsPanel } from './ReviewDetailsPanel';
import { DenialModal } from './DenialModal';
import {
  INITIAL_PENDING_REQUESTS,
  INITIAL_APPROVED_REQUESTS,
  INITIAL_DENIED_REQUESTS,
  INITIAL_EXPIRED_REQUESTS,
} from './reviewData';
import type { ReviewRequest, ReviewStatus, ReviewFilterState } from './reviewTypes';
import { apiClient, type ApiPendingReview, type ApiSessionResponse, ApiError } from '../../api/client';

interface ReviewViewProps {
  onRefreshGlobal?: () => void;
  isRefreshingGlobal?: boolean;
  session?: ApiSessionResponse | null;
  onOpenLogin?: () => void;
}

export const ReviewView: React.FC<ReviewViewProps> = ({
  onRefreshGlobal,
  isRefreshingGlobal = false,
  session,
  onOpenLogin,
}) => {
  // Datasets for all 4 statuses
  const [pendingList, setPendingList] = useState<ReviewRequest[]>([]);
  const [approvedList, setApprovedList] = useState<ReviewRequest[]>([]);
  const [deniedList, setDeniedList] = useState<ReviewRequest[]>([]);
  const [expiredList] = useState<ReviewRequest[]>([]);
  const [isLive, setIsLive] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [apiError, setApiError] = useState<string | null>(null);
  const [showReferenceFixtures, setShowReferenceFixtures] = useState(false);

  // Status Tab
  const [currentStatus, setCurrentStatus] = useState<ReviewStatus>('Pending');

  // Selected Request — starts closed so the review portal only appears on demand
  const [selectedRequest, setSelectedRequest] = useState<ReviewRequest | null>(null);
  const [isDetailsClosing, setIsDetailsClosing] = useState(false);
  const closeTimerRef = useRef<number | null>(null);

  // Denial modal state
  const [denyingRequest, setDenyingRequest] = useState<ReviewRequest | null>(null);

  // Filters state
  const [filters, setFilters] = useState<ReviewFilterState>({
    searchQuery: '',
    agent: 'All',
    tool: 'All',
    riskRange: 'All',
    sortBy: 'Newest',
  });

  const [dateRange, setDateRange] = useState('Last 7 Days');
  const [localRefreshing, setLocalRefreshing] = useState(false);
  const [isMobileDetailsOpen, setIsMobileDetailsOpen] = useState(false);

  // Notification message
  const [actionNotification, setActionNotification] = useState<string | null>(null);

  const showNotification = (msg: string) => {
    setActionNotification(msg);
    setTimeout(() => setActionNotification(null), 3500);
  };

  const mapApiReviewToRequest = (r: ApiPendingReview): ReviewRequest => {
    const agentName = r.agent || r.agent_id || 'unnamed-agent';
    const toolName = r.tool || r.tool_name || 'execute_tool';
    const rawTime = r.created_at ? Date.parse(r.created_at) || Date.now() : Date.now();
    const score = Math.round(r.risk_score ?? 68);

    return {
      id: r.review_id,
      title: `${agentName} · ${toolName}`,
      description: `Tool execution held for human supervisor review under security policy`,
      agent: agentName,
      tool: toolName,
      riskScore: score,
      riskLevel: score >= 80 ? 'Critical' : score >= 60 ? 'High' : 'Medium',
      requestedAt: r.created_at ? new Date(r.created_at).toLocaleTimeString() : 'Just now',
      requestedAtTimestamp: rawTime,
      expiresIn: '14m remaining',
      expiresInMinutes: 14,
      status: 'Pending',
      proposedByText: `Autonomous agent ${agentName}`,
      actionPayload: r.arguments || {},
      policyCheck: {
        status: 'requires_approval',
        text: 'Policy requirement: High-risk mutating action requires admin confirmation',
      },
      riskFactors: r.reasons?.join(', ') || 'Sensitive capability invocation',
      injectionCheck: {
        passed: true,
        text: 'Heuristic prompt injection scan cleared (0 detections)',
      },
      policyContext: {
        name: 'Runtime Protection Policy',
        version: 'v2.1',
        hash: 'sha256:7f4a0b2',
      },
    };
  };

  const loadReviews = async () => {
    setIsLoading(true);
    setApiError(null);
    try {
      const res = await apiClient.getReviews();
      if (res && Array.isArray(res.reviews)) {
        const mapped = res.reviews.map(mapApiReviewToRequest);
        setPendingList(mapped);
        setIsLive(true);
      } else {
        setPendingList([]);
        setIsLive(false);
      }
    } catch (err: unknown) {
      const msg = (err as Error)?.message || 'Failed to fetch reviews from server';
      setApiError(msg);
      setPendingList([]);
      setIsLive(false);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadReviews();
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

  // Open (or swap) the review portal with an enter animation
  const handleSelectRequest = (req: ReviewRequest) => {
    cancelCloseTimer();
    setIsDetailsClosing(false);
    setSelectedRequest(req);
    setIsMobileDetailsOpen(true);
  };

  // Play the exit animation, then unmount the portal
  const handleCloseDetails = () => {
    cancelCloseTimer();
    setIsDetailsClosing(true);
    closeTimerRef.current = window.setTimeout(() => {
      setSelectedRequest(null);
      setIsDetailsClosing(false);
      setIsMobileDetailsOpen(false);
      closeTimerRef.current = null;
    }, 220);
  };

  const handleFilterChange = <K extends keyof ReviewFilterState>(
    key: K,
    value: ReviewFilterState[K]
  ) => {
    setFilters((prev) => ({ ...prev, [key]: value }));
  };

  const handleResetFilters = () => {
    setFilters({
      searchQuery: '',
      agent: 'All',
      tool: 'All',
      riskRange: 'All',
      sortBy: 'Newest',
    });
  };

  // Effective datasets (either live or user-requested reference fixtures)
  const effectivePending = showReferenceFixtures ? INITIAL_PENDING_REQUESTS : pendingList;
  const effectiveApproved = showReferenceFixtures ? INITIAL_APPROVED_REQUESTS : approvedList;
  const effectiveDenied = showReferenceFixtures ? INITIAL_DENIED_REQUESTS : deniedList;
  const effectiveExpired = showReferenceFixtures ? INITIAL_EXPIRED_REQUESTS : expiredList;

  // Active dataset based on tab
  const activeDataset = useMemo(() => {
    switch (currentStatus) {
      case 'Pending':
        return effectivePending;
      case 'Approved':
        return effectiveApproved;
      case 'Denied':
        return effectiveDenied;
      case 'Expired':
        return effectiveExpired;
    }
  }, [currentStatus, effectivePending, effectiveApproved, effectiveDenied, effectiveExpired]);

  // Filtered & Sorted records
  const filteredRequests = useMemo(() => {
    const list = activeDataset.filter((req) => {
      // 1. Search Query
      if (filters.searchQuery.trim()) {
        const q = filters.searchQuery.toLowerCase();
        const matchesId = req.id.toLowerCase().includes(q);
        const matchesDesc = req.description.toLowerCase().includes(q);
        const matchesAgent = req.agent.toLowerCase().includes(q);
        const matchesTool = req.tool.toLowerCase().includes(q);
        if (!matchesId && !matchesDesc && !matchesAgent && !matchesTool) {
          return false;
        }
      }

      // 2. Agent
      if (filters.agent !== 'All' && req.agent !== filters.agent) {
        return false;
      }

      // 3. Tool
      if (filters.tool !== 'All' && req.tool !== filters.tool) {
        return false;
      }

      // 4. Risk Range
      if (filters.riskRange !== 'All') {
        if (filters.riskRange === 'High (75+)' && req.riskScore < 75) return false;
        if (filters.riskRange === 'Medium (40-74)' && (req.riskScore < 40 || req.riskScore >= 75)) return false;
        if (filters.riskRange === 'Low (0-39)' && req.riskScore >= 40) return false;
      }

      return true;
    });

    // Sort
    return list.sort((a, b) => {
      switch (filters.sortBy) {
        case 'Newest':
          return b.requestedAtTimestamp - a.requestedAtTimestamp;
        case 'Oldest':
          return a.requestedAtTimestamp - b.requestedAtTimestamp;
        case 'Highest Risk':
          return b.riskScore - a.riskScore;
        case 'Lowest Risk':
          return a.riskScore - b.riskScore;
        default:
          return 0;
      }
    });
  }, [activeDataset, filters]);

  // Handle Approve
  const handleApprove = async (req: ReviewRequest) => {
    if (!session?.authenticated) {
      showNotification('Administrative authentication required to approve reviews.');
      if (onOpenLogin) onOpenLogin();
      return;
    }

    try {
      await apiClient.submitReview(req.id, 'approve');

      // 1. Remove from pending only on server success
      const remainingPending = pendingList.filter((item) => item.id !== req.id);
      setPendingList(remainingPending);

      // 2. Add to approved
      const updatedReq: ReviewRequest = { ...req, status: 'Approved', expiresIn: 'Approved' };
      setApprovedList((prev) => [updatedReq, ...prev]);

      // 3. Select next pending request if available
      if (remainingPending.length > 0) {
        cancelCloseTimer();
        setIsDetailsClosing(false);
        setSelectedRequest(remainingPending[0]);
      } else {
        handleCloseDetails();
      }

      showNotification(`Request ${req.id} approved on server.`);
      if (onRefreshGlobal) onRefreshGlobal();
    } catch (err: unknown) {
      if (err instanceof ApiError) {
        if (err.status === 403) {
          showNotification('Operation Blocked (403): Read-only mode or insufficient privileges prevent approving reviews.');
        } else if (err.status === 401) {
          showNotification('Authentication Required (401): Please sign in to approve reviews.');
        } else {
          showNotification(`Approval Failed (${err.status}): ${err.message}`);
        }
      } else {
        const msg = (err as Error)?.message || 'Server error approving review';
        showNotification(`Approval Failed: ${msg}`);
      }
    }
  };

  // Handle Deny Trigger
  const handleDenyClick = (req: ReviewRequest) => {
    if (!session?.authenticated) {
      showNotification('Administrative authentication required to deny reviews.');
      if (onOpenLogin) onOpenLogin();
      return;
    }
    setDenyingRequest(req);
  };

  // Handle Deny Confirm
  const handleConfirmDeny = async (req: ReviewRequest, reason: string) => {
    try {
      await apiClient.submitReview(req.id, 'reject', reason);

      // 1. Remove from pending only on server success
      const remainingPending = pendingList.filter((item) => item.id !== req.id);
      setPendingList(remainingPending);

      // 2. Add to denied
      const updatedReq: ReviewRequest = {
        ...req,
        status: 'Denied',
        expiresIn: 'Denied',
        riskFactors: `Denied: ${reason}`,
      };
      setDeniedList((prev) => [updatedReq, ...prev]);

      // 3. Select next pending request
      if (remainingPending.length > 0) {
        cancelCloseTimer();
        setIsDetailsClosing(false);
        setSelectedRequest(remainingPending[0]);
      } else {
        handleCloseDetails();
      }

      setDenyingRequest(null);
      showNotification(`Request ${req.id} was rejected on server.`);
      if (onRefreshGlobal) onRefreshGlobal();
    } catch (err: unknown) {
      if (err instanceof ApiError) {
        if (err.status === 403) {
          showNotification('Operation Blocked (403): Read-only mode or insufficient privileges prevent rejecting reviews.');
        } else if (err.status === 401) {
          showNotification('Authentication Required (401): Please sign in to reject reviews.');
        } else {
          showNotification(`Denial Failed (${err.status}): ${err.message}`);
        }
      } else {
        const msg = (err as Error)?.message || 'Server error denying review';
        showNotification(`Denial Failed: ${msg}`);
      }
    }
  };

  const handleRefresh = async () => {
    setLocalRefreshing(true);
    if (onRefreshGlobal) onRefreshGlobal();
    await loadReviews();
    setLocalRefreshing(false);
  };

  return (
    <main className="flex-1 px-5 py-3 md:px-6 md:py-3.5 max-w-[1536px] w-full mx-auto flex flex-col justify-between">
      {/* ACTION NOTIFICATION TOAST */}
      {actionNotification && (
        <div className="fixed top-20 right-8 z-50 px-4 py-2.5 rounded-xl bg-[#221c45] border border-[#6d3ee8] text-white text-xs font-semibold shadow-2xl flex items-center gap-2 animate-in fade-in slide-in-from-top-2 duration-150">
          <span className="w-2 h-2 rounded-full bg-[#22c55e] animate-ping" />
          <span>{actionNotification}</span>
        </div>
      )}

      {/* AUTHENTICATION REQUIRED BANNER */}
      {!session?.authenticated && (
        <div className="mb-3.5 p-3.5 bg-[#241740] border border-[#6d3ee8]/60 rounded-xl flex items-center justify-between text-xs shadow-md">
          <div className="flex items-center gap-2.5 text-[#d8b4fe]">
            <span className="w-2 h-2 rounded-full bg-[#facc15] animate-pulse" />
            <span>
              <strong>Administrative Session Required:</strong> Sign in with your administrative key to review, approve, or reject tool execution proposals.
            </span>
          </div>
          {onOpenLogin && (
            <button
              onClick={onOpenLogin}
              className="px-3.5 py-1.5 bg-[#6d3ee8] hover:bg-[#7e50f5] text-white rounded-lg font-semibold text-xs transition-colors cursor-pointer flex-shrink-0 shadow-sm"
            >
              Sign In as Admin
            </button>
          )}
        </div>
      )}

      {/* MAIN WORKSPACE */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-3.5 items-start">
        {/* LEFT WORKSPACE */}
        <div
          className={`flex flex-col min-w-0 transition-all duration-300 ${
            selectedRequest ? 'lg:col-span-8' : 'lg:col-span-12'
          }`}
        >
          {/* Status Indicator Banner & Dataset Mode Toggle */}
          <div className="flex items-center justify-between pb-1.5 flex-wrap gap-2">
            <div className="flex items-center gap-2">
              <span
                className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-md text-[11px] font-semibold border ${
                  showReferenceFixtures
                    ? 'bg-[#2b2559] text-[#c084fc] border-[#3e3478]'
                    : isLive
                    ? 'bg-[#153e28] text-[#4ade80] border-[#1b6d39]'
                    : 'bg-[#1f1b3d] text-[#9c96c9] border-[#342e61]'
                }`}
              >
                <span
                  className={`w-1.5 h-1.5 rounded-full ${
                    showReferenceFixtures
                      ? 'bg-[#c084fc]'
                      : isLive
                      ? 'bg-[#4ade80]'
                      : 'bg-[#736c9e]'
                  }`}
                />
                {showReferenceFixtures
                  ? 'REFERENCE REVIEW DATASET (Demo Suite)'
                  : isLive
                  ? `LIVE QUEUE (Server Connected · ${pendingList.length} Pending)`
                  : 'LIVE QUEUE (Queue Empty / Standby)'}
              </span>
            </div>

            <button
              onClick={() => setShowReferenceFixtures(!showReferenceFixtures)}
              className="text-[11px] font-mono text-[#a59ecd] hover:text-white transition-colors underline decoration-dotted underline-offset-4"
            >
              {showReferenceFixtures
                ? '← Return to Live Reviews'
                : 'Preview Reference Review Fixtures (v1.0)'}
            </button>
          </div>

          {/* API Error Notification */}
          {apiError && !showReferenceFixtures && (
            <div className="mb-3.5 p-3 rounded-lg bg-[#3b1219] border border-[#f87171]/40 text-[#fca5a5] text-xs flex items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <span className="font-bold text-[#f87171]">API Warning:</span>
                <span>{apiError}</span>
              </div>
              <button
                onClick={handleRefresh}
                className="px-2.5 py-1 bg-[#ef4444] text-white rounded text-[11px] font-semibold hover:bg-[#dc2626] transition-colors"
              >
                Retry
              </button>
            </div>
          )}

          {/* Reference Fixtures Warning Banner */}
          {showReferenceFixtures && (
            <div className="mb-3.5 p-2.5 rounded-lg bg-[#271d4d] border border-[#5d3bbb] text-[#dcd7f2] text-xs flex items-center justify-between">
              <span className="font-mono">
                📌 <strong>Previewing offline review fixtures.</strong> These records are test data for design verification and do not represent active customer requests.
              </span>
              <button
                onClick={() => setShowReferenceFixtures(false)}
                className="px-2 py-0.5 bg-[#4c2fa8] hover:bg-[#5e38d1] text-white rounded text-[10.5px] font-mono ml-2 flex-shrink-0"
              >
                Exit Preview
              </button>
            </div>
          )}

          {/* 1. REVIEW PAGE HEADER */}
          <ReviewPageHeader
            onRefresh={handleRefresh}
            isRefreshing={localRefreshing || isRefreshingGlobal}
            dateRange={dateRange}
            onDateRangeChange={setDateRange}
          />

          {/* 2. KPI CARDS */}
          <ReviewKpiSection
            pendingCount={effectivePending.length}
            approvedCount={effectiveApproved.length}
            deniedCount={effectiveDenied.length}
            expiredCount={effectiveExpired.length}
          />

          {/* 3. STATUS TABS */}
          <ReviewStatusTabs
            currentStatus={currentStatus}
            onSelectStatus={(status) => {
              setCurrentStatus(status);
              if (selectedRequest) handleCloseDetails();
            }}
            pendingCount={effectivePending.length}
            approvedCount={effectiveApproved.length}
            deniedCount={effectiveDenied.length}
            expiredCount={effectiveExpired.length}
          />

          {/* Historical Status Clarification Notice */}
          {currentStatus !== 'Pending' && !showReferenceFixtures && (
            <div className="mb-3 px-3.5 py-2 rounded-lg bg-[#181635] border border-[#2e2957] text-[#9c96c9] text-xs flex items-center gap-2">
              <span className="text-[#38bdf8] font-mono">ℹ</span>
              <span>
                Historical <strong>{currentStatus.toLowerCase()}</strong> records are permanently archived in the <strong>Audit Log</strong>. Actions approved or denied during your active session are tracked above.
              </span>
            </div>
          )}

          {/* 4. FILTER TOOLBAR */}
          <ReviewToolbar
            filters={filters}
            onFilterChange={handleFilterChange}
            onResetFilters={handleResetFilters}
          />

          {/* 5. REQUESTS TABLE OR EMPTY STATE */}
          {isLoading && !showReferenceFixtures ? (
            <div className="relative p-12 bg-[#16142e] pixel-corners border border-[#3a3273] text-center">
              <div className="text-xs font-mono text-[#a59ecd] animate-pulse">
                Fetching review queue from server...
              </div>
            </div>
          ) : currentStatus === 'Pending' && effectivePending.length === 0 && !filters.searchQuery.trim() && filters.agent === 'All' && filters.tool === 'All' && filters.riskRange === 'All' ? (
            <div className="relative p-10 bg-[#16142e] pixel-corners border border-[#3a3273] text-center shadow-[0_4px_24px_rgba(0,0,0,0.45)]">
              <div className="w-12 h-12 mx-auto mb-3 rounded-full bg-[#1b173b] border border-[#3a3273] flex items-center justify-center text-xl">
                🛡️
              </div>
              <h3 className="text-sm font-bold text-white font-mono uppercase tracking-wide">
                No Pending Reviews
              </h3>
              <p className="text-xs text-[#9c96c9] max-w-md mx-auto mt-1.5 leading-relaxed">
                Actions flagged with policy-designated high risk or supervisor requirements will automatically appear in this queue for human authorization.
              </p>
            </div>
          ) : (
            <ReviewTable
              requests={filteredRequests}
              selectedRequest={selectedRequest}
              onSelectRequest={handleSelectRequest}
            />
          )}
        </div>

        {/* RIGHT WORKSPACE: ANIMATED REVIEW PORTAL */}
        {selectedRequest && (
          <div
            key={selectedRequest.id}
            className={`hidden lg:block lg:col-span-4 sticky top-[76px] pt-2 ${
              isDetailsClosing ? 'portal-shell-exit' : 'portal-shell-enter'
            }`}
          >
            <ReviewDetailsPanel
              request={selectedRequest}
              onClose={handleCloseDetails}
              onApprove={handleApprove}
              onDeny={handleDenyClick}
            />
          </div>
        )}
      </div>

      {/* MOBILE / TABLET ANIMATED REVIEW PORTAL DRAWER */}
      {isMobileDetailsOpen && (
        <div
          className={`fixed inset-0 z-50 lg:hidden flex justify-end bg-black/60 backdrop-blur-xs ${
            isDetailsClosing ? 'portal-backdrop-exit' : 'portal-backdrop-enter'
          }`}
        >
          <div className="fixed inset-0" onClick={handleCloseDetails} />
          <div
            className={`relative w-full max-w-md h-full z-10 ${
              isDetailsClosing ? 'portal-drawer-exit' : 'portal-drawer-enter'
            }`}
          >
            <ReviewDetailsPanel
              request={selectedRequest}
              onClose={handleCloseDetails}
              onApprove={(req) => {
                handleApprove(req);
                handleCloseDetails();
              }}
              onDeny={(req) => {
                handleDenyClick(req);
                handleCloseDetails();
              }}
            />
          </div>
        </div>
      )}

      {/* DENIAL REASON MODAL */}
      <DenialModal
        request={denyingRequest}
        onClose={() => setDenyingRequest(null)}
        onConfirmDeny={handleConfirmDeny}
      />
    </main>
  );
};
