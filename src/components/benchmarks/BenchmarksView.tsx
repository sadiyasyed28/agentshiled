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
import type { BenchmarkRunRecord } from './benchmarkTypes';
import { apiClient } from '../../api/client';

export const BenchmarksView: React.FC = () => {
  const [runs, setRuns] = useState<BenchmarkRunRecord[]>(INITIAL_BENCHMARK_RUNS);
  const [selectedRunId, setSelectedRunId] = useState<string>(INITIAL_BENCHMARK_RUNS[0].id);

  // Modals
  const [isRunModalOpen, setIsRunModalOpen] = useState(false);
  const [isDatasetModalOpen, setIsDatasetModalOpen] = useState(false);
  const [isViewAllModalOpen, setIsViewAllModalOpen] = useState(false);

  useEffect(() => {
    const fetchHistory = async () => {
      try {
        const history = await apiClient.getSimulationHistory(20);
        if (history && history.length > 0) {
          // If past simulation runs exist, group them by run_id or create run records
          // Keeping default benchmarks visible for rich baseline display
        }
      } catch {
        // Offline demo fallback preserved
      }
    };
    fetchHistory();
  }, []);

  // Current active run record
  const currentRun = runs.find((r) => r.id === selectedRunId) || runs[0];

  const handleCompleteNewRun = (newRun: BenchmarkRunRecord) => {
    setRuns((prev) => [newRun, ...prev]);
    setSelectedRunId(newRun.id);
  };

  const handleSelectRun = (run: BenchmarkRunRecord) => {
    setSelectedRunId(run.id);
  };

  return (
    <main className="flex-1 px-5 py-3 md:px-6 md:py-3.5 max-w-[1536px] w-full mx-auto flex flex-col justify-between">
      <div className="flex flex-col gap-3.5">
        {/* 1. BENCHMARKS PAGE HEADER */}
        <BenchmarkPageHeader
          onRunBenchmark={() => setIsRunModalOpen(true)}
          onViewDataset={() => setIsDatasetModalOpen(true)}
        />

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
              runs={runs.slice(0, 3)}
              selectedRunId={selectedRunId}
              onSelectRun={handleSelectRun}
              onViewAll={() => setIsViewAllModalOpen(true)}
            />
          </div>
        </div>
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
        runs={runs}
        selectedRunId={selectedRunId}
        onSelectRun={handleSelectRun}
        onClose={() => setIsViewAllModalOpen(false)}
      />
    </main>
  );
};
