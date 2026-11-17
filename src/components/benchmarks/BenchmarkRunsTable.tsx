import React from 'react';
import { PixelClockOutlineIcon } from '../pixel/PixelIcons';
import { AnimatedNumber } from '../pixel/AnimatedNumber';
import type { BenchmarkRunRecord } from './benchmarkTypes';

interface BenchmarkRunsTableProps {
  runs: BenchmarkRunRecord[];
  selectedRunId: string;
  onSelectRun: (run: BenchmarkRunRecord) => void;
  onViewAll: () => void;
}

export const BenchmarkRunsTable: React.FC<BenchmarkRunsTableProps> = ({
  runs,
  selectedRunId,
  onSelectRun,
  onViewAll,
}) => {
  return (
    <div className="relative p-[1.5px] bg-[#3a3273] hover:bg-[#453c85] pixel-corners shadow-[0_4px_16px_rgba(0,0,0,0.4)] transition-colors duration-150 h-full flex flex-col">
      <div className="w-full h-full bg-[#16142e] pixel-corners p-4 md:p-4.5 flex flex-col justify-between">
        {/* PANEL HEADER */}
        <div className="flex items-center justify-between pb-3 border-b border-[#292254]">
          <div className="flex items-center gap-2">
            <PixelClockOutlineIcon size={18} />
            <span className="text-sm font-bold text-white tracking-wide">
              Benchmark Runs
            </span>
          </div>

          <button
            onClick={onViewAll}
            className="text-xs font-semibold text-[#b8aee6] hover:text-white transition-colors flex items-center gap-1 cursor-pointer"
          >
            <span>View All</span>
            <span className="text-sm">→</span>
          </button>
        </div>

        {/* RUNS TABLE */}
        <div className="flex-1 overflow-x-auto py-2">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-[#292254] text-[#8e87be] font-semibold">
                <th className="pb-2.5 font-medium">Run ID</th>
                <th className="pb-2.5 font-medium">Dataset</th>
                <th className="pb-2.5 font-medium">Policy Version</th>
                <th className="pb-2.5 font-medium text-center">Total</th>
                <th className="pb-2.5 font-medium text-center">Blocked</th>
                <th className="pb-2.5 font-medium text-center">FP</th>
                <th className="pb-2.5 font-medium text-center">Bypasses</th>
                <th className="pb-2.5 font-medium text-right pr-1">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#231e47]">
              {runs.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-6 text-center text-xs font-mono text-[#8e87be]">
                    No benchmark runs recorded
                  </td>
                </tr>
              ) : (
                runs.map((run) => {
                  const isSelected = run.id === selectedRunId;

                return (
                  <tr
                    key={run.id}
                    onClick={() => onSelectRun(run)}
                    className={`cursor-pointer transition-colors duration-150 group ${
                      isSelected
                        ? 'bg-[#261f52] outline outline-2 outline-[#6d3ee8]'
                        : 'hover:bg-[#1c183b]'
                    }`}
                  >
                    {/* Run ID */}
                    <td className="py-2.5 pl-2 font-mono font-bold text-white">
                      {run.id}
                    </td>

                    {/* Dataset */}
                    <td className="py-2.5 text-[#dedaf4]">
                      {run.dataset}
                    </td>

                    {/* Policy Version */}
                    <td className="py-2.5 text-[#c4bbf0] font-medium">
                      {run.policyVersion}
                    </td>

                    {/* Total */}
                    <td className="py-2.5 text-center font-mono font-bold text-white">
                      <AnimatedNumber value={run.total} />
                    </td>

                    {/* Blocked */}
                    <td className="py-2.5 text-center font-mono font-bold text-[#f87171]">
                      <AnimatedNumber value={run.blocked} />
                    </td>

                    {/* FP */}
                    <td className="py-2.5 text-center font-mono font-bold text-[#fde047]">
                      <AnimatedNumber value={run.fp} />
                    </td>

                    {/* Bypasses */}
                    <td className="py-2.5 text-center font-mono font-bold text-[#4ade80]">
                      <AnimatedNumber value={run.bypasses} />
                    </td>

                    {/* Status */}
                    <td className="py-2.5 text-right pr-2">
                      <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-md bg-[#15803d]/30 border border-[#22c55e] text-[#4ade80] text-[11px] font-bold">
                        <span>✓</span>
                        <span>{run.status}</span>
                      </span>
                    </td>
                  </tr>
                );
              })
            )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
