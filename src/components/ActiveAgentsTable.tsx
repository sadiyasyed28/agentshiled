import React from 'react';
import { PixelUsersIcon, PixelRobotIcon } from './pixel/PixelIcons';
import { PixelCard } from './pixel/PixelCard';
import { AnimatedNumber } from './pixel/AnimatedNumber';
import { ArrowRight } from 'lucide-react';
import type { Agent } from '../types';

interface ActiveAgentsTableProps {
  onSelectAgent: (agent: Agent) => void;
  onViewAll: () => void;
  agents?: Agent[];
}

export const ActiveAgentsTable: React.FC<ActiveAgentsTableProps> = ({
  onSelectAgent,
  onViewAll,
  agents: customAgents,
}) => {
  const agents = customAgents || [];

  return (
    <PixelCard className="h-full flex-1" innerClassName="p-3.5 justify-between h-full">
      {/* Header */}
      <div className="flex items-center justify-between pb-2 border-b border-[#25204c]">
        <div className="flex items-center gap-1.5">
          <div className="flex items-center justify-center text-[#c084fc]">
            <PixelUsersIcon size={16} />
          </div>
          <h3 className="text-[13.5px] font-bold text-white tracking-tight">
            Active Agents
          </h3>
          <span className="text-[11px] font-mono text-[#847ea8]">({agents.length})</span>
        </div>

        <button
          onClick={onViewAll}
          className="flex items-center gap-1 text-[11.5px] font-semibold text-[#8b84bd] hover:text-[#c4bbf0] transition-colors group"
        >
          <span>View All</span>
          <ArrowRight size={12} className="group-hover:translate-x-0.5 transition-transform" />
        </button>
      </div>

      {/* Table or Empty State */}
      <div className="w-full overflow-x-auto my-auto py-1">
        {agents.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-7 text-center">
            <div className="w-9 h-9 rounded-lg bg-[#2b1f59] text-[#c084fc] flex items-center justify-center mb-2 shadow-xs">
              <PixelRobotIcon size={20} />
            </div>
            <span className="text-[13px] font-semibold text-white">No Agents Discovered Yet</span>
            <span className="text-[11.5px] text-[#847ea8] mt-1 max-w-[340px] leading-relaxed">
              Wrap your agent's tools with <code className="text-[#c084fc] bg-[#1a163a] px-1 py-0.5 rounded font-mono text-[10.5px]">@shield.protect_tool</code> or adapter to discover active agents.
            </span>
          </div>
        ) : (
          <table className="w-full text-left text-xs border-collapse">
          <thead>
            <tr className="text-[#7d77a8] text-[11px] font-medium border-b border-[#231e47]">
              <th className="pb-2 font-medium">Agent</th>
              <th className="pb-2 font-medium">Status</th>
              <th className="pb-2 font-medium">Policy</th>
              <th className="pb-2 font-medium text-right pr-2">Events (7d)</th>
              <th className="pb-2 font-medium text-right">Blocked</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#231e47]/60">
            {agents.map((agent) => (
              <tr
                key={agent.id}
                onClick={() => onSelectAgent(agent)}
                className="cursor-pointer hover:bg-[#201d44] transition-colors group"
              >
                {/* Agent Name with Robot Icon */}
                <td className="py-2 pr-2">
                  <div className="flex items-center gap-2">
                    <div className="w-5 h-5 flex-shrink-0 flex items-center justify-center">
                      <PixelRobotIcon size={16} />
                    </div>
                    <span className="font-semibold text-white group-hover:text-[#c4bbf0] transition-colors font-mono text-[12px]">
                      {agent.name}
                    </span>
                  </div>
                </td>

                {/* Status Badge */}
                <td className="py-2 pr-2">
                  {agent.status === 'Active' ? (
                    <span className="inline-flex items-center px-2 py-0.5 text-[10.5px] font-bold rounded-md bg-[#134927] text-[#4ade80] border border-[#1b6d39]">
                      Active
                    </span>
                  ) : (
                    <span className="inline-flex items-center px-2 py-0.5 text-[10.5px] font-bold rounded-md bg-[#25233c] text-[#8e89b3] border border-[#373359]">
                      Paused
                    </span>
                  )}
                </td>

                {/* Policy */}
                <td className="py-2 pr-2 text-[#9a94cb] font-medium text-[12px]">
                  {agent.policy}
                </td>

                {/* Events Count */}
                <td className="py-2 pr-2 text-right text-white font-semibold tabular-nums text-[12px]">
                  <AnimatedNumber value={agent.events7d} />
                </td>

                {/* Blocked Count & Rate */}
                <td className="py-2 text-right text-[#9a94cb] font-medium tabular-nums text-[12px]">
                  <AnimatedNumber value={agent.blockedCount} /> (
                  <AnimatedNumber value={parseFloat(agent.blockedRate)} decimals={1} suffix="%" />)
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        )}
      </div>
    </PixelCard>
  );
};
