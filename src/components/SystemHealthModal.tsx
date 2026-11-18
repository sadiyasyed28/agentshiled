import React, { useState, useEffect, useCallback } from 'react';
import {
  X,
  Activity,
  Database,
  Radio,
  Server,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Clock,
  RefreshCw,
} from 'lucide-react';
import {
  apiClient,
  type ApiHealthResponse,
  type ApiReadinessResponse,
  type ApiTelemetryStatusResponse,
  ApiError,
} from '../api/client';
import { AnimatedNumber } from './pixel/AnimatedNumber';
import { computeHealthStatus, type HealthStatusType } from '../health';

export { computeHealthStatus, type HealthStatusType };

interface SystemHealthModalProps {
  isOpen: boolean;
  onClose: () => void;
  onHealthLoaded?: (status: HealthStatusType, version?: string) => void;
}

export const SystemHealthModal: React.FC<SystemHealthModalProps> = ({
  isOpen,
  onClose,
  onHealthLoaded,
}) => {
  const [healthData, setHealthData] = useState<ApiHealthResponse | null>(null);
  const [readinessData, setReadinessData] = useState<ApiReadinessResponse | null>(null);
  const [telemetryData, setTelemetryData] = useState<ApiTelemetryStatusResponse | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const fetchHealthDiagnostics = useCallback(async () => {
    setIsLoading(true);
    setErrorMsg(null);
    try {
      const [hRes, rRes, tRes] = await Promise.allSettled([
        apiClient.getHealth(),
        apiClient.getReadiness(),
        apiClient.getTelemetryStatus(),
      ]);

      let anySuccess = false;
      let newHealth: ApiHealthResponse | null = null;
      let newReadiness: ApiReadinessResponse | null = null;
      let newTelemetry: ApiTelemetryStatusResponse | null = null;

      if (hRes.status === 'fulfilled') {
        newHealth = hRes.value;
        setHealthData(newHealth);
        anySuccess = true;
      }

      if (rRes.status === 'fulfilled') {
        newReadiness = rRes.value;
        setReadinessData(newReadiness);
        anySuccess = true;
      } else if (rRes.reason instanceof ApiError && rRes.reason.status === 503) {
        // Degraded returns 503 with structured readiness data
        const data = rRes.reason.data as Record<string, unknown> | undefined;
        const detail = (data?.detail || data) as ApiReadinessResponse | undefined;
        if (detail && typeof detail === 'object') {
          newReadiness = detail;
          setReadinessData(detail);
          anySuccess = true;
        }
      }

      if (tRes.status === 'fulfilled') {
        newTelemetry = tRes.value;
        setTelemetryData(newTelemetry);
        anySuccess = true;
      }

      if (!anySuccess) {
        setErrorMsg('Unable to connect to AgentShield backend health endpoints.');
        onHealthLoaded?.('Unavailable');
      } else {
        // Compute overall status
        const isDbConnected = newReadiness?.database === 'connected';
        const isDegraded =
          newReadiness?.status === 'degraded' ||
          newHealth?.status === 'degraded' ||
          !isDbConnected;
        const totalEvents = newTelemetry?.total_events ?? 0;
        const isAwaitingTelemetry =
          totalEvents === 0 || newTelemetry?.status === 'awaiting_telemetry';

        let derivedStatus: HealthStatusType = 'Healthy';
        if (isDegraded) {
          derivedStatus = isDbConnected ? 'Degraded' : 'Unhealthy';
        } else if (isAwaitingTelemetry) {
          derivedStatus = 'Awaiting telemetry';
        }

        onHealthLoaded?.(derivedStatus, newHealth?.version);
      }
    } catch (err: unknown) {
      const msg = (err as Error)?.message || 'Health diagnostics check failed';
      setErrorMsg(msg);
      onHealthLoaded?.('Unavailable');
    } finally {
      setIsLoading(false);
    }
  }, [onHealthLoaded]);

  useEffect(() => {
    if (isOpen) {
      fetchHealthDiagnostics();
    }
  }, [isOpen, fetchHealthDiagnostics]);

  if (!isOpen) return null;

  // Resolve current overall status
  const getOverallStatus = (): { label: HealthStatusType; color: string; bg: string; border: string } => {
    if (isLoading) {
      return {
        label: 'Loading',
        color: 'text-[#938ec0]',
        bg: 'bg-[#221e45]',
        border: 'border-[#3e3678]',
      };
    }
    if (errorMsg || (!healthData && !readinessData)) {
      return {
        label: 'Unavailable',
        color: 'text-[#ef4444]',
        bg: 'bg-[#4a1c25]',
        border: 'border-[#782836]',
      };
    }

    const isDbConnected = readinessData?.database === 'connected';
    if (!isDbConnected) {
      return {
        label: 'Unhealthy',
        color: 'text-[#ef4444]',
        bg: 'bg-[#4a1c25]',
        border: 'border-[#782836]',
      };
    }

    if (readinessData?.status === 'degraded' || healthData?.status === 'degraded') {
      return {
        label: 'Degraded',
        color: 'text-[#facc15]',
        bg: 'bg-[#403413]',
        border: 'border-[#6b551c]',
      };
    }

    const totalEvents = telemetryData?.total_events ?? 0;
    if (totalEvents === 0 || telemetryData?.status === 'awaiting_telemetry') {
      return {
        label: 'Awaiting telemetry',
        color: 'text-[#c084fc]',
        bg: 'bg-[#2b1f59]',
        border: 'border-[#4a2e70]',
      };
    }

    return {
      label: 'Healthy',
      color: 'text-[#4ade80]',
      bg: 'bg-[#153e28]',
      border: 'border-[#226742]',
    };
  };

  const statusInfo = getOverallStatus();

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm animate-in fade-in duration-150">
      <div
        className="relative w-full max-w-xl p-6 bg-[#181636] border border-[#40387d] rounded-2xl shadow-2xl max-h-[92vh] overflow-y-auto"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Close Button */}
        <button
          onClick={onClose}
          className="absolute top-4 right-4 p-1 text-[#8b84bd] hover:text-white transition-colors cursor-pointer"
          aria-label="Close health dialog"
        >
          <X size={18} />
        </button>

        {/* Modal Header */}
        <div className="flex items-center gap-3 mb-4 pb-3 border-b border-[#25204c]">
          <div className="w-10 h-10 rounded-xl bg-[#261f52] border border-[#3e3478] flex items-center justify-center text-[#c084fc] flex-shrink-0 shadow-sm">
            <Activity size={22} />
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <h3 className="text-base font-bold text-white tracking-tight font-mono">
                System Health & Operational Status
              </h3>
              <span
                className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md text-[11px] font-mono font-bold border ${statusInfo.bg} ${statusInfo.color} ${statusInfo.border}`}
              >
                <span className="w-1.5 h-1.5 rounded-full bg-current animate-pulse" />
                {statusInfo.label}
              </span>
            </div>
            <p className="text-[11.5px] text-[#958ec4] mt-0.5 truncate">
              Live telemetry and dependency checks from FastAPI runtime endpoints
            </p>
          </div>
        </div>

        {/* Error Notification if any */}
        {errorMsg && (
          <div className="mb-4 p-3 bg-[#4a1c25]/90 border border-[#782836] rounded-xl text-xs text-[#f87171] font-mono flex items-start gap-2 shadow-sm">
            <AlertTriangle size={15} className="flex-shrink-0 mt-0.5" />
            <div className="flex-1">
              <p className="font-bold">Operational Alert</p>
              <p className="text-[11px] text-[#fca5a5] mt-0.5 leading-relaxed">{errorMsg}</p>
            </div>
          </div>
        )}

        {/* SECTION 1: Core Engine & Runtime Mode */}
        <div className="mb-4">
          <div className="flex items-center gap-1.5 mb-2 text-[11px] font-bold uppercase tracking-wider text-[#8b84bd]">
            <Server size={13} className="text-[#a29bcf]" />
            <span>Runtime Engine</span>
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs">
            <div className="p-2.5 bg-[#1b1739] rounded-xl border border-[#2e265c]">
              <span className="text-[10.5px] text-[#8680b5] block">Engine</span>
              <span className="font-semibold text-white mt-0.5 block truncate">
                {healthData?.engine || (isLoading ? '--' : 'AgentShield')}
              </span>
            </div>
            <div className="p-2.5 bg-[#1b1739] rounded-xl border border-[#2e265c]">
              <span className="text-[10.5px] text-[#8680b5] block">Version</span>
              <span className="font-semibold text-[#c084fc] font-mono mt-0.5 block">
                {healthData?.version ? `v${healthData.version}` : (isLoading ? '--' : 'v0.2.0')}
              </span>
            </div>
            <div className="p-2.5 bg-[#1b1739] rounded-xl border border-[#2e265c]">
              <span className="text-[10.5px] text-[#8680b5] block">Operating Mode</span>
              <span
                className={`font-semibold mt-0.5 block text-[11.5px] ${
                  healthData?.read_only ? 'text-[#facc15]' : 'text-[#4ade80]'
                }`}
              >
                {healthData?.read_only ? 'Read-Only (Demo)' : 'Interactive'}
              </span>
            </div>
            <div className="p-2.5 bg-[#1b1739] rounded-xl border border-[#2e265c]">
              <span className="text-[10.5px] text-[#8680b5] block">Storage Backend</span>
              <span className="font-semibold text-white mt-0.5 block font-mono capitalize">
                {readinessData?.storage_backend || (isLoading ? '--' : 'sqlite')}
              </span>
            </div>
          </div>
        </div>

        {/* SECTION 2: Infrastructure Dependencies (only exposed backend fields) */}
        <div className="mb-4">
          <div className="flex items-center gap-1.5 mb-2 text-[11px] font-bold uppercase tracking-wider text-[#8b84bd]">
            <Database size={13} className="text-[#a29bcf]" />
            <span>Infrastructure Readiness</span>
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 text-xs">
            {/* Database Connection */}
            <div className="p-2.5 bg-[#1b1739] rounded-xl border border-[#2e265c] flex items-center justify-between">
              <div>
                <span className="text-[10.5px] text-[#8680b5] block">Database</span>
                <span className="font-semibold text-white mt-0.5 block capitalize">
                  {readinessData?.database || (isLoading ? '--' : 'unknown')}
                </span>
              </div>
              {readinessData?.database === 'connected' ? (
                <CheckCircle2 size={16} className="text-[#4ade80]" />
              ) : (
                <XCircle size={16} className="text-[#ef4444]" />
              )}
            </div>

            {/* Audit Store */}
            {readinessData?.audit_store !== undefined && (
              <div className="p-2.5 bg-[#1b1739] rounded-xl border border-[#2e265c] flex items-center justify-between">
                <div>
                  <span className="text-[10.5px] text-[#8680b5] block">Audit Store</span>
                  <span className="font-semibold text-white mt-0.5 block capitalize">
                    {readinessData.audit_store}
                  </span>
                </div>
                {readinessData.audit_store === 'accessible' ? (
                  <CheckCircle2 size={16} className="text-[#4ade80]" />
                ) : (
                  <XCircle size={16} className="text-[#ef4444]" />
                )}
              </div>
            )}

            {/* Review Store */}
            {readinessData?.review_store !== undefined && (
              <div className="p-2.5 bg-[#1b1739] rounded-xl border border-[#2e265c] flex items-center justify-between">
                <div>
                  <span className="text-[10.5px] text-[#8680b5] block">Review Store</span>
                  <span className="font-semibold text-white mt-0.5 block capitalize">
                    {readinessData.review_store}
                  </span>
                </div>
                {readinessData.review_store === 'accessible' ? (
                  <CheckCircle2 size={16} className="text-[#4ade80]" />
                ) : (
                  <XCircle size={16} className="text-[#ef4444]" />
                )}
              </div>
            )}

            {/* Event Store */}
            {readinessData?.event_store !== undefined && (
              <div className="p-2.5 bg-[#1b1739] rounded-xl border border-[#2e265c] flex items-center justify-between">
                <div>
                  <span className="text-[10.5px] text-[#8680b5] block">Event Store</span>
                  <span className="font-semibold text-white mt-0.5 block capitalize">
                    {readinessData.event_store}
                  </span>
                </div>
                {readinessData.event_store === 'accessible' ? (
                  <CheckCircle2 size={16} className="text-[#4ade80]" />
                ) : (
                  <XCircle size={16} className="text-[#ef4444]" />
                )}
              </div>
            )}

            {/* Circuit Breaker */}
            {readinessData?.circuit_breaker !== undefined && (
              <div className="p-2.5 bg-[#1b1739] rounded-xl border border-[#2e265c] flex items-center justify-between">
                <div>
                  <span className="text-[10.5px] text-[#8680b5] block">Circuit Breaker</span>
                  <span className="font-semibold text-white mt-0.5 block capitalize font-mono text-[11.5px]">
                    {readinessData.circuit_breaker}
                  </span>
                </div>
                {readinessData.circuit_breaker === 'closed' ? (
                  <CheckCircle2 size={16} className="text-[#4ade80]" />
                ) : (
                  <AlertTriangle size={16} className="text-[#facc15]" />
                )}
              </div>
            )}

            {/* Analyst Provider */}
            {readinessData?.analyst_provider !== undefined && (
              <div className="p-2.5 bg-[#1b1739] rounded-xl border border-[#2e265c]">
                <span className="text-[10.5px] text-[#8680b5] block">Analyst Provider</span>
                <span className="font-semibold text-white mt-0.5 block truncate font-mono text-[11px]">
                  {readinessData.analyst_provider}
                </span>
              </div>
            )}
          </div>
        </div>

        {/* SECTION 3: Live Telemetry & Event Throughput */}
        <div className="mb-5">
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-1.5 text-[11px] font-bold uppercase tracking-wider text-[#8b84bd]">
              <Radio size={13} className="text-[#c084fc]" />
              <span>Telemetry Pipeline</span>
            </div>
            <span
              className={`text-[10.5px] font-mono px-2 py-0.5 rounded font-semibold ${
                telemetryData?.status === 'healthy'
                  ? 'bg-[#153e28] text-[#4ade80]'
                  : telemetryData?.status === 'degraded'
                  ? 'bg-[#403413] text-[#facc15]'
                  : 'bg-[#2b1f59] text-[#c084fc]'
              }`}
            >
              {telemetryData?.status === 'awaiting_telemetry' || (telemetryData?.total_events ?? 0) === 0
                ? 'Awaiting telemetry'
                : telemetryData?.status || 'Awaiting telemetry'}
            </span>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs">
            <div className="p-2.5 bg-[#1b1739] rounded-xl border border-[#2e265c]">
              <span className="text-[10.5px] text-[#8680b5] block">Evaluated Events</span>
              <span className="text-base font-bold text-white mt-0.5 block">
                {isLoading ? (
                  '--'
                ) : telemetryData && telemetryData.total_events > 0 ? (
                  <AnimatedNumber value={telemetryData.total_events} />
                ) : (
                  <span className="text-[#c084fc] text-xs font-normal">0 recorded</span>
                )}
              </span>
            </div>
            <div className="p-2.5 bg-[#1b1739] rounded-xl border border-[#2e265c]">
              <span className="text-[10.5px] text-[#8680b5] block">Active Agents</span>
              <span className="text-base font-bold text-white mt-0.5 block">
                {isLoading ? (
                  '--'
                ) : telemetryData ? (
                  <AnimatedNumber value={telemetryData.active_agents_count} />
                ) : (
                  '0'
                )}
              </span>
            </div>
            <div className="p-2.5 bg-[#1b1739] rounded-xl border border-[#2e265c]">
              <span className="text-[10.5px] text-[#8680b5] block">Pending Delivery</span>
              <span className="text-base font-bold text-white mt-0.5 block">
                {isLoading ? (
                  '--'
                ) : telemetryData ? (
                  <AnimatedNumber value={telemetryData.pending_delivery} />
                ) : (
                  '0'
                )}
              </span>
            </div>
            <div className="p-2.5 bg-[#1b1739] rounded-xl border border-[#2e265c]">
              <span className="text-[10.5px] text-[#8680b5] block">Dropped Events</span>
              <span
                className={`text-base font-bold mt-0.5 block ${
                  (telemetryData?.dropped_events ?? 0) > 0 ? 'text-[#ef4444]' : 'text-white'
                }`}
              >
                {isLoading ? (
                  '--'
                ) : telemetryData ? (
                  <AnimatedNumber value={telemetryData.dropped_events} />
                ) : (
                  '0'
                )}
              </span>
            </div>
          </div>

          <div className="mt-2 p-2.5 bg-[#1e1a3f] rounded-xl border border-[#312a5e] text-xs flex items-center justify-between">
            <span className="text-[11px] text-[#8680b5] flex items-center gap-1.5">
              <Clock size={13} className="text-[#a29bcf]" />
              Last Successful Transmission:
            </span>
            <span className="font-mono text-[11px] text-white">
              {telemetryData?.last_successful_transmission
                ? new Date(telemetryData.last_successful_transmission).toLocaleTimeString()
                : telemetryData?.last_event_timestamp
                ? new Date(telemetryData.last_event_timestamp).toLocaleTimeString()
                : 'Awaiting first event'}
            </span>
          </div>
        </div>

        {/* Footer Actions */}
        <div className="flex items-center justify-between pt-3 border-t border-[#25204c]">
          <button
            onClick={fetchHealthDiagnostics}
            disabled={isLoading}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-[#c0bbe6] hover:text-white bg-[#221e45] hover:bg-[#2c2759] border border-[#3b3370] rounded-xl transition-colors disabled:opacity-50 cursor-pointer"
          >
            <RefreshCw size={13} className={isLoading ? 'animate-spin text-[#c084fc]' : ''} />
            <span>Refresh Diagnostics</span>
          </button>
          <button
            onClick={onClose}
            className="px-4 py-1.5 text-xs font-semibold text-white bg-[#6d3ee8] hover:bg-[#7e50f5] rounded-xl transition-colors cursor-pointer"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
