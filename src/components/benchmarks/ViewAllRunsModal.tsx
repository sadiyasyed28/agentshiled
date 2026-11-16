import React from 'react';
import { X } from 'lucide-react';
import { PixelClockOutlineIcon } from '../pixel/PixelIcons';
import type { BenchmarkRunRecord } from './benchmarkTypes';

interface ViewAllRunsModalProps {
  isOpen: boolean;
  runs: BenchmarkRunRecord[];
  selectedRunId: string;
  onSelectRun: (run: BenchmarkRunRecord) => void;
  onClose: () => void;
}

export const ViewAllRunsModal: React.FC<ViewAllRunsModalProps> = ({
  isOpen,
  runs,
  selectedRunId,
  onSelectRun,
  onClose,
}) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
      <div className="relative w-full max-w-3xl p-[2px] bg-[#3a3273] pixel-corners shadow-2xl">
        <div className="w-full bg-[#16142e] pixel-corners p-5 flex flex-col">
          {/* HEADER */}
          <div className="flex items-center justify-between pb-3.5 border-b border-[#292254]">
            <div className="flex items-center gap-2.5">
              <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-[#25204d] border border-[#443a7b]">
                <PixelClockOutlineIcon size={16} />
              </div>
              <div>
                <h3 className="text-base font-bold text-white tracking-wide">
                  Benchmark Run History
                </h3>
                <p className="text-xs text-[#9d97c7]">
                  All recorded runtime security benchmark executions
                </p>
              </div>
            </div>

            <button
              onClick={onClose}
              className="w-8 h-8 rounded-lg text-[#958fbe] hover:text-white hover:bg-[#25204c] flex items-center justify-center transition-colors cursor-pointer"
            >
              <X size={18} />
            </button>
          </div>

          {/* RUNS LIST */}
          <div className="py-3 overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-[#292254] text-[#8e87be]">
                  <th className="pb-2.5 font-medium">Run ID</th>
                  <th className="pb-2.5 font-medium">Date & Time</th>
                  <th className="pb-2.5 font-medium">Dataset</th>
                  <th className="pb-2.5 font-medium">Policy Version</th>
                  <th className="pb-2.5 font-medium text-center">Total</th>
                  <th className="pb-2.5 font-medium text-center">Blocked</th>
                  <th className="pb-2.5 font-medium text-center">FP</th>
                  <th className="pb-2.5 font-medium text-center">Bypasses</th>
                  <th className="pb-2.5 font-medium text-right pr-2">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#231e47]">
                {runs.length === 0 ? (
                  <tr>
                    <td colSpan={9} className="py-8 text-center text-xs font-mono text-[#8e87be]">
                      No benchmark runs recorded in history
                    </td>
                  </tr>
                ) : (
                  runs.map((run) => {
                    const isSelected = run.id === selectedRunId;

                  return (
                    <tr
                      key={run.id}
                      onClick={() => {
                        onSelectRun(run);
                        onClose();
                      }}
                      className={`cursor-pointer transition-colors duration-150 ${
                        isSelected
                          ? 'bg-[#261f52] outline outline-2 outline-[#6d3ee8]'
                          : 'hover:bg-[#1c183b]'
                      }`}
                    >
                      <td className="py-3 pl-2 font-mono font-bold text-white">
                        {run.id}
                      </td>
                      <td className="py-3 text-[#9d97c7]">
                        {run.timestamp}
                      </td>
                      <td className="py-3 text-[#dedaf4]">
                        {run.dataset}
                      </td>
                      <td className="py-3 text-[#c4bbf0] font-medium">
                        {run.policyVersion}
                      </td>
                      <td className="py-3 text-center font-mono font-bold text-white">
                        {run.total}
                      </td>
                      <td className="py-3 text-center font-mono font-bold text-[#f87171]">
                        {run.blocked}
                      </td>
                      <td className="py-3 text-center font-mono font-bold text-[#fde047]">
                        {run.fp}
                      </td>
                      <td className="py-3 text-center font-mono font-bold text-[#4ade80]">
                        {run.bypasses}
                      </td>
                      <td className="py-3 text-right pr-2">
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

          <div className="pt-3 border-t border-[#292254] flex items-center justify-end">
            <button
              onClick={onClose}
              className="px-4 py-1.5 rounded-lg bg-[#221d47] hover:bg-[#2e275f] text-white text-xs font-semibold cursor-pointer"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

