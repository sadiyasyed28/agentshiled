import React, { useState, useEffect } from 'react';
import { BenchmarkPageHeader } from './BenchmarkPageHeader';
import { BenchmarkKpiSection } from './BenchmarkKpiSection';
import { BaselineVsProtectedPanel } from './BaselineVsProtectedPanel';
import { DecisionDistributionPanel } from './DecisionDistributionPanel';
import { CategoryResultsPanel } from './CategoryResultsPanel';
import { BenchmarkRunsTable } from './BenchmarkRunsTable';
import { RunBenchmarkModal } from './RunBenchmarkModal';
import { ViewDatasetModal } from './ViewDatasetModal';
import { ViewAllRunsModal } from './ViewAllRunsModal';
import { INITIAL_BENCHMARK_RUNS } from './benchmarkData';
import { mapSimulationHistoryToRuns, EMPTY_BENCHMARK_RUN } from './mapSimulationHistory';
import type { BenchmarkRunRecord } from './benchmarkTypes';
import { apiClient } from '../../api/client';

export const BenchmarksView: React.FC = () => {
  const [liveRuns, setLiveRuns] = useState<BenchmarkRunRecord[]>([]);
  const [selectedRunId, setSelectedRunId] = useState<string | null>(null);
  const [activeDatasetMode, setActiveDatasetMode] = useState<'live' | 'reference'>('live');
  const [isLoading, setIsLoading] = useState(true);
  const [apiError, setApiError] = useState<string | null>(null);

  // Modals
  const [isRunModalOpen, setIsRunModalOpen] = useState(false);
  const [isDatasetModalOpen, setIsDatasetModalOpen] = useState(false);
  const [isViewAllModalOpen, setIsViewAllModalOpen] = useState(false);

  const fetchHistory = async () => {
    setIsLoading(true);
    setApiError(null);
    try {
      const history = await apiClient.getSimulationHistory(50);
      if (history && history.length > 0) {
        const mappedRuns = mapSimulationHistoryToRuns(history);
        setLiveRuns(mappedRuns);
        if (mappedRuns.length > 0 && !selectedRunId) {
          setSelectedRunId(mappedRuns[0].id);
        }
      } else {
        setLiveRuns([]);
      }
    } catch (err: unknown) {
      const msg = (err as Error)?.message || 'Failed to fetch simulation history from server';
      setApiError(msg);
      setLiveRuns([]);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchHistory();
  }, []);

  // Active runs based on mode
  const activeRuns = activeDatasetMode === 'reference' ? INITIAL_BENCHMARK_RUNS : liveRuns;

  // Current active run record
  const currentRun: BenchmarkRunRecord =
    activeRuns.find((r) => r.id === selectedRunId) ||
    activeRuns[0] ||
    EMPTY_BENCHMARK_RUN;

  const handleCompleteNewRun = (newRun: BenchmarkRunRecord) => {
    setLiveRuns((prev) => [newRun, ...prev]);
    setSelectedRunId(newRun.id);
    setActiveDatasetMode('live');
  };

  const handleSelectRun = (run: BenchmarkRunRecord) => {
    setSelectedRunId(run.id);
  };

  return (
    <main className="flex-1 px-5 py-3 md:px-6 md:py-3.5 max-w-[1536px] w-full mx-auto flex flex-col justify-between">
      <div className="flex flex-col gap-3.5">
        {/* DATASET SELECTION & MODE CONTROLS */}
        <div className="flex items-center justify-between pb-1 flex-wrap gap-2">
          <div className="flex items-center gap-1.5 p-1 bg-[#16142e] pixel-corners border border-[#3a3273]">
            <button
              onClick={() => {
                setActiveDatasetMode('live');
                if (liveRuns.length > 0) setSelectedRunId(liveRuns[0].id);
              }}
              className={`px-3 py-1 text-xs font-mono font-semibold transition-colors rounded ${
                activeDatasetMode === 'live'
                  ? 'bg-[#6d3ee8] text-white shadow-sm'
                  : 'text-[#9c96c9] hover:text-white'
              }`}
            >
              Live Simulations ({liveRuns.length})
            </button>
            <button
              onClick={() => {
                setActiveDatasetMode('reference');
                setSelectedRunId(INITIAL_BENCHMARK_RUNS[0].id);
              }}
              className={`px-3 py-1 text-xs font-mono font-semibold transition-colors rounded ${
                activeDatasetMode === 'reference'
                  ? 'bg-[#6d3ee8] text-white shadow-sm'
                  : 'text-[#9c96c9] hover:text-white'
              }`}
            >
              Reference Research Baseline (v1.0)
            </button>
          </div>

          <span
            className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-[11px] font-mono font-semibold border ${
              activeDatasetMode === 'reference'
                ? 'bg-[#2b2559] text-[#c084fc] border-[#3e3478]'
                : liveRuns.length > 0
                ? 'bg-[#153e28] text-[#4ade80] border-[#1b6d39]'
                : 'bg-[#1b173b] text-[#8b87a8] border-[#3a3273]'
            }`}
          >
            <span
              className={`w-1.5 h-1.5 rounded-full ${
                activeDatasetMode === 'reference'
                  ? 'bg-[#c084fc]'
                  : liveRuns.length > 0
                  ? 'bg-[#4ade80]'
                  : 'bg-[#8b87a8]'
              }`}
            />
            {activeDatasetMode === 'reference'
              ? 'REFERENCE RESEARCH SUITE (32 Static Cases)'
              : liveRuns.length > 0
              ? `LIVE SIMULATIONS (${liveRuns.length} Runs Available)`
              : 'LIVE SIMULATOR (No Runs Recorded)'}
          </span>
        </div>

        {/* API ERROR ALERT */}
        {apiError && activeDatasetMode === 'live' && (
          <div className="p-3 rounded-lg bg-[#3b1219] border border-[#f87171]/40 text-[#fca5a5] text-xs flex items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <span className="font-bold text-[#f87171]">Simulator API Error:</span>
              <span>{apiError}</span>
            </div>
            <button
              onClick={fetchHistory}
              className="px-2.5 py-1 bg-[#ef4444] text-white rounded text-[11px] font-semibold hover:bg-[#dc2626] transition-colors"
            >
              Retry
            </button>
          </div>
        )}

        {/* REFERENCE DATASET DISCLAIMER BANNER */}
        {activeDatasetMode === 'reference' && (
          <div className="p-3 rounded-lg bg-[#271d4d] border border-[#5d3bbb] text-[#dcd7f2] text-xs flex items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <span className="font-mono text-sm">🧪</span>
              <span className="font-mono">
                <strong>Reference Benchmark Suite (v1.0):</strong> Displaying static research baseline metrics (32 test cases, 16 benign, 16 malicious). These benchmark numbers are reference controls and do not modify or reflect active tenant execution metrics.
              </span>
            </div>
            <button
              onClick={() => {
                setActiveDatasetMode('live');
                if (liveRuns.length > 0) setSelectedRunId(liveRuns[0].id);
              }}
              className="px-2.5 py-1 bg-[#4c2fa8] hover:bg-[#5e38d1] text-white rounded text-[11px] font-mono flex-shrink-0"
            >
              Back to Live Data
            </button>
          </div>
        )}

        {/* 1. BENCHMARKS PAGE HEADER */}
        <BenchmarkPageHeader
          onRunBenchmark={() => setIsRunModalOpen(true)}
          onViewDataset={() => setIsDatasetModalOpen(true)}
        />

        {/* LOADING STATE */}
        {isLoading && activeDatasetMode === 'live' ? (
          <div className="p-12 text-center bg-[#16142e] pixel-corners border border-[#3a3273]">
            <div className="text-xs font-mono text-[#a59ecd] animate-pulse">
              Loading simulation history from server...
            </div>
          </div>
        ) : activeDatasetMode === 'live' && liveRuns.length === 0 ? (
          /* EMPTY STATE FOR LIVE SIMULATIONS */
          <div className="p-10 text-center bg-[#16142e] pixel-corners border border-[#3a3273] shadow-[0_4px_24px_rgba(0,0,0,0.45)]">
            <div className="w-14 h-14 mx-auto mb-3 rounded-full bg-[#1b173b] border border-[#3a3273] flex items-center justify-center text-2xl">
              ⚔️
            </div>
            <h3 className="text-sm font-bold text-white font-mono uppercase tracking-wide">
              No Live Simulation Runs Recorded
            </h3>
            <p className="text-xs text-[#9c96c9] max-w-lg mx-auto mt-2 leading-relaxed">
              Execute adversarial and benign scenario attacks against the active AgentShield policy engine to record actual bypass rates, false positives, and protection metrics.
            </p>
            <div className="flex items-center justify-center gap-3 mt-5">
              <button
                onClick={() => setIsRunModalOpen(true)}
                className="px-4 py-2 bg-[#6d3ee8] hover:bg-[#5b2fd4] text-white text-xs font-bold font-mono rounded-lg transition-colors shadow-lg"
              >
                ▶ Run Benchmark Simulation
              </button>
              <button
                onClick={() => {
                  setActiveDatasetMode('reference');
                  setSelectedRunId(INITIAL_BENCHMARK_RUNS[0].id);
                }}
                className="px-4 py-2 bg-[#221c45] hover:bg-[#2c2459] border border-[#443885] text-[#dcd7f2] text-xs font-mono rounded-lg transition-colors"
              >
                Inspect Reference Research Baseline (32 cases)
              </button>
            </div>
          </div>
        ) : (
          /* BENCHMARK ANALYTICS CARDS & PANELS */
          <>
            {/* 2. FIVE KPI CARDS */}
            <BenchmarkKpiSection currentRun={currentRun} />

            {/* 3. TOP ANALYTICS GRID (Baseline vs Protected & Decision Distribution) */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-3.5 items-stretch">
              <div className="lg:col-span-7 flex flex-col">
                <BaselineVsProtectedPanel currentRun={currentRun} />
              </div>
              <div className="lg:col-span-5 flex flex-col">
                <DecisionDistributionPanel currentRun={currentRun} />
              </div>
            </div>

            {/* 4. BOTTOM ANALYTICS GRID (Category Results & Benchmark Runs Table) */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-3.5 items-stretch">
              <div className="lg:col-span-6 flex flex-col">
                <CategoryResultsPanel currentRun={currentRun} />
              </div>
              <div className="lg:col-span-6 flex flex-col">
                <BenchmarkRunsTable
                  runs={activeRuns.slice(0, 3)}
                  selectedRunId={currentRun.id}
                  onSelectRun={handleSelectRun}
                  onViewAll={() => setIsViewAllModalOpen(true)}
                />
              </div>
            </div>
          </>
        )}
      </div>

      {/* MODALS */}
      <RunBenchmarkModal
        isOpen={isRunModalOpen}
        onClose={() => setIsRunModalOpen(false)}
        onCompleteRun={handleCompleteNewRun}
      />

      <ViewDatasetModal
        isOpen={isDatasetModalOpen}
        onClose={() => setIsDatasetModalOpen(false)}
      />

      <ViewAllRunsModal
        isOpen={isViewAllModalOpen}
        runs={activeRuns}
        selectedRunId={currentRun.id}
        onSelectRun={handleSelectRun}
        onClose={() => setIsViewAllModalOpen(false)}
      />
    </main>
  );
};
