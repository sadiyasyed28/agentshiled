import React, { useState } from 'react';
import { Search, ExternalLink, Shield } from 'lucide-react';
import { ALL_ASSIGNED_AGENTS_SUMMARY } from './policyData';
import { PixelRobotIcon } from '../pixel/PixelIcons';
import { AnimatedNumber } from './../pixel/AnimatedNumber';

interface AgentsTableViewProps {
  onSelectPolicyByName: (policyName: string) => void;
  pausedAgentNames?: string[];
  onTogglePause?: (agentName: string, currentlyPaused: boolean) => void;
}

export const AgentsTableView: React.FC<AgentsTableViewProps> = ({
  onSelectPolicyByName,
  pausedAgentNames = [],
  onTogglePause,
}) => {
  const [search, setSearch] = useState('');

  const agentsWithLiveStatus = ALL_ASSIGNED_AGENTS_SUMMARY.map((ag) => {
    const isPaused = pausedAgentNames.includes(ag.name);
    return {
      ...ag,
      status: isPaused ? ('Paused' as const) : ag.status,
    };
  });

  const filteredAgents = agentsWithLiveStatus.filter((ag) => {
    if (!search.trim()) return true;
    const q = search.toLowerCase();
    return (
      ag.name.toLowerCase().includes(q) ||
      ag.policy.toLowerCase().includes(q) ||
      ag.runtime.toLowerCase().includes(q)
    );
  });

  return (
    <div className="flex flex-col gap-3.5">
      {/* SEARCH BAR */}
      <div className="flex items-center justify-between">
        <div className="relative w-72">
          <Search
            size={14}
            className="absolute left-3 top-1/2 -translate-y-1/2 text-[#8b84bc] pointer-events-none"
          />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search agents, policies, runtimes..."
            className="w-full h-9 pl-9 pr-3 bg-[#171530] border border-[#3b3472] rounded-xl text-xs text-white placeholder-[#7f78ab] focus:outline-none focus:border-[#6d3ee8]"
          />
        </div>

        <div className="text-xs text-[#9c96c9]">
          Showing <span className="text-white font-mono font-bold"><AnimatedNumber value={filteredAgents.length} /></span> active agents
        </div>
      </div>

      {/* AGENTS TABLE */}
      <div className="relative p-[1.5px] bg-[#3a3273] pixel-corners shadow-[0_4px_24px_rgba(0,0,0,0.45)]">
        <div className="w-full bg-[#16142e] pixel-corners flex flex-col overflow-x-auto">
          <table className="w-full text-left border-collapse min-w-[700px]">
            <thead>
              <tr className="border-b border-[#292352] text-[#dcd7f2] text-xs font-semibold select-none bg-[#16142e]">
                <th className="py-3 px-4">Agent Identity</th>
                <th className="py-3 px-3">Enforced Policy</th>
                <th className="py-3 px-3">Status</th>
                <th className="py-3 px-3">Runtime</th>
                <th className="py-3 px-3">Allowed Tools</th>
                <th className="py-3 px-3 text-right">Events (7d)</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#221e45] text-xs">
              {filteredAgents.map((ag) => (
                <tr key={ag.id} className="hover:bg-[#1c183b] transition-colors">
                  <td className="py-3 px-4">
                    <div className="flex items-center gap-2.5">
                      <div className="text-[#a5b4fc]">
                        <PixelRobotIcon size={18} />
                      </div>
                      <span className="font-bold text-white text-[13px]">{ag.name}</span>
                    </div>
                  </td>

                  <td className="py-3 px-3">
                    <button
                      onClick={() => onSelectPolicyByName(ag.policy)}
                      className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-[#231b4b] border border-[#503d98] text-[#c4bbf0] font-semibold text-xs hover:border-[#7c66dc] transition-colors cursor-pointer"
                    >
                      <Shield size={12} className="text-[#a78bfa]" />
                      <span>{ag.policy}</span>
                      <ExternalLink size={10} />
                    </button>
                  </td>

                  <td className="py-3 px-3">
                    {onTogglePause ? (
                      <button
                        onClick={() => onTogglePause(ag.name, ag.status === 'Paused')}
                        title={ag.status === 'Active' ? 'Click to pause agent' : 'Click to unpause agent'}
                        className={`inline-flex items-center px-2 py-0.5 rounded-md text-[11px] font-semibold cursor-pointer transition-all hover:scale-105 ${
                          ag.status === 'Active'
                            ? 'bg-[#15803d]/30 border border-[#22c55e] text-[#4ade80] hover:bg-[#15803d]/50'
                            : 'bg-[#a16207]/30 border border-[#eab308] text-[#fde047] hover:bg-[#a16207]/50'
                        }`}
                      >
                        {ag.status}
                      </button>
                    ) : (
                      <span
                        className={`inline-flex items-center px-2 py-0.5 rounded-md text-[11px] font-semibold ${
                          ag.status === 'Active'
                            ? 'bg-[#15803d]/30 border border-[#22c55e] text-[#4ade80]'
                            : 'bg-[#a16207]/30 border border-[#eab308] text-[#fde047]'
                        }`}
                      >
                        {ag.status}
                      </span>
                    )}
                  </td>

                  <td className="py-3 px-3 text-[#9c96c9] font-medium text-[12px]">
                    {ag.runtime}
                  </td>

                  <td className="py-3 px-3 font-mono text-[11.5px] text-[#cdc7ea]">
                    {ag.tools.join(', ')}
                  </td>

                  <td className="py-3 px-3 text-right font-mono font-bold text-white text-[12px]">
                    <AnimatedNumber value={ag.eventsCount} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
