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
  const defaultAgents: Agent[] = [
    {
      id: 'research-agent',
      name: 'research-agent',
      status: 'Active',
      policy: 'Research v2',
      events7d: 1248,
      blockedCount: 142,
      blockedRate: '11.4%',
      runtime: 'Python LangChain v0.2',
      lastActive: 'Just now',
      description: 'Web crawler and market intelligence gathering autonomous agent.',
    },
    {
      id: 'ops-agent',
      name: 'ops-agent',
      status: 'Active',
      policy: 'Operations v1',
      events7d: 973,
      blockedCount: 118,
      blockedRate: '12.1%',
      runtime: 'Go Agent Daemon v1.4',
      lastActive: '2m ago',
      description: 'Infrastructure automation and server health diagnostics.',
    },
    {
      id: 'data-agent',
      name: 'data-agent',
      status: 'Active',
      policy: 'Data Access v3',
      events7d: 840,
      blockedCount: 116,
      blockedRate: '13.8%',
      runtime: 'Node.js Agent SDK v3.1',
      lastActive: '8m ago',
      description: 'Internal analytical data query agent with read-only sandbox.',
    },
    {
      id: 'email-agent',
      name: 'email-agent',
      status: 'Paused',
      policy: 'Restricted v1',
      events7d: 421,
      blockedCount: 53,
      blockedRate: '12.6%',
      runtime: 'Python Autogen v0.4',
      lastActive: '34m ago',
      description: 'Outbound dispatch agent paused due to high risk score anomaly.',
    },
  ];

  const agents = customAgents && customAgents.length > 0 ? customAgents : defaultAgents;

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
        </div>

        <button
          onClick={onViewAll}
          className="flex items-center gap-1 text-[11.5px] font-semibold text-[#8b84bd] hover:text-[#c4bbf0] transition-colors group"
        >
          <span>View All</span>
          <ArrowRight size={12} className="group-hover:translate-x-0.5 transition-transform" />
        </button>
      </div>

      {/* Table */}
      <div className="w-full overflow-x-auto my-auto py-1">
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
      </div>
    </PixelCard>
  );
};
