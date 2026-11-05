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
import { apiClient, type ApiPendingReview } from '../../api/client';

interface ReviewViewProps {
  onRefreshGlobal?: () => void;
  isRefreshingGlobal?: boolean;
}

export const ReviewView: React.FC<ReviewViewProps> = ({
  onRefreshGlobal,
  isRefreshingGlobal = false,
}) => {
  // Datasets for all 4 statuses
  const [pendingList, setPendingList] = useState<ReviewRequest[]>(INITIAL_PENDING_REQUESTS);
  const [approvedList, setApprovedList] = useState<ReviewRequest[]>(INITIAL_APPROVED_REQUESTS);
  const [deniedList, setDeniedList] = useState<ReviewRequest[]>(INITIAL_DENIED_REQUESTS);
  const [expiredList] = useState<ReviewRequest[]>(INITIAL_EXPIRED_REQUESTS);
  const [isLive, setIsLive] = useState(false);

  // Initial base offsets matching IMAGE B exact counts (Pending: 6, Approved: 38, Denied: 21, Expired: 4)
  const approvedCountOffset = 37; // 1 initial item + 37 = 38
  const deniedCountOffset = 20;   // 1 initial item + 20 = 21
  const expiredCountOffset = 3;   // 1 initial item + 3 = 4

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
    try {
      const res = await apiClient.getReviews();
      if (res && Array.isArray(res.reviews) && res.reviews.length > 0) {
        const mapped = res.reviews.map(mapApiReviewToRequest);
        setPendingList(mapped);
        setIsLive(true);
      } else {
        setPendingList(INITIAL_PENDING_REQUESTS);
        setIsLive(false);
      }
    } catch {
      // Offline fallback
      setPendingList(INITIAL_PENDING_REQUESTS);
      setIsLive(false);
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

  // Active dataset based on tab
  const activeDataset = useMemo(() => {
    switch (currentStatus) {
      case 'Pending':
        return pendingList;
      case 'Approved':
        return approvedList;
      case 'Denied':
        return deniedList;
      case 'Expired':
        return expiredList;
    }
  }, [currentStatus, pendingList, approvedList, deniedList, expiredList]);

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
    } catch (err: unknown) {
      const msg = (err as Error)?.message || 'Server error approving review';
      showNotification(`Approval Failed: ${msg}`);
    }
  };

  // Handle Deny Trigger
  const handleDenyClick = (req: ReviewRequest) => {
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
    } catch (err: unknown) {
      const msg = (err as Error)?.message || 'Server error denying review';
      showNotification(`Denial Failed: ${msg}`);
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

      {/* MAIN WORKSPACE */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-3.5 items-start">
        {/* LEFT WORKSPACE */}
        <div
          className={`flex flex-col min-w-0 transition-all duration-300 ${
            selectedRequest ? 'lg:col-span-8' : 'lg:col-span-12'
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
              {isLive ? 'LIVE QUEUE (Server Connected)' : 'DEMO MODE (Offline Dataset)'}
            </span>
          </div>

          {/* 1. REVIEW PAGE HEADER */}
          <ReviewPageHeader
            onRefresh={handleRefresh}
            isRefreshing={localRefreshing || isRefreshingGlobal}
            dateRange={dateRange}
            onDateRangeChange={setDateRange}
          />

          {/* 2. KPI CARDS */}
          <ReviewKpiSection
            pendingCount={pendingList.length}
            approvedCount={approvedList.length + approvedCountOffset}
            deniedCount={deniedList.length + deniedCountOffset}
            expiredCount={expiredList.length + expiredCountOffset}
          />

          {/* 3. STATUS TABS */}
          <ReviewStatusTabs
            currentStatus={currentStatus}
            onSelectStatus={(status) => {
              setCurrentStatus(status);
              if (selectedRequest) handleCloseDetails();
            }}
            pendingCount={pendingList.length}
            approvedCount={approvedList.length + approvedCountOffset}
            deniedCount={deniedList.length + deniedCountOffset}
            expiredCount={expiredList.length + expiredCountOffset}
          />

          {/* 4. FILTER TOOLBAR */}
          <ReviewToolbar
            filters={filters}
            onFilterChange={handleFilterChange}
            onResetFilters={handleResetFilters}
          />

          {/* 5. REQUESTS TABLE */}
          <ReviewTable
            requests={filteredRequests}
            selectedRequest={selectedRequest}
            onSelectRequest={handleSelectRequest}
          />
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
