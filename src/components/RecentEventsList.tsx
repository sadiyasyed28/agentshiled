import React from 'react';
import {
  PixelLayersIcon,
  PixelCheckCircleIcon,
  PixelCrossShieldIcon,
  PixelClockCircleIcon,
} from './pixel/PixelIcons';
import { PixelCard } from './pixel/PixelCard';
import { AnimatedNumber } from './pixel/AnimatedNumber';
import { ArrowRight } from 'lucide-react';
import type { SecurityEvent } from '../types';

interface RecentEventsListProps {
  onSelectEvent: (event: SecurityEvent) => void;
  onViewAll: () => void;
  events?: SecurityEvent[];
}

export const RecentEventsList: React.FC<RecentEventsListProps> = ({
  onSelectEvent,
  onViewAll,
  events: customEvents,
}) => {
  const defaultEvents: SecurityEvent[] = [
    {
      id: 'evt-1',
      agent: 'research-agent',
      action: 'read_web',
      decision: 'Allowed',
      riskScore: 12,
      timestamp: '2 min ago',
      payloadSummary: 'GET https://arxiv.org/html/2401.001 - Status 200 OK',
      reason: 'Standard read-only query matching approved research pattern.',
    },
    {
      id: 'evt-2',
      agent: 'email-agent',
      action: 'send_email',
      decision: 'Blocked',
      riskScore: 87,
      timestamp: '7 min ago',
      payloadSummary: 'POST smtp://relay.corp.internal - Target: external_dump@unknown.net',
      reason: 'Unauthorized external data exfiltration attempt blocked by egress firewall.',
    },
    {
      id: 'evt-3',
      agent: 'ops-agent',
      action: 'list_files',
      decision: 'Review',
      riskScore: 68,
      timestamp: '12 min ago',
      payloadSummary: 'LS -la /var/run/secrets/kubernetes.io/serviceaccount',
      reason: 'Sensitive token directory inspection requested; flagged for supervisor review.',
    },
    {
      id: 'evt-4',
      agent: 'data-agent',
      action: 'query_db',
      decision: 'Allowed',
      riskScore: 24,
      timestamp: '18 min ago',
      payloadSummary: 'SELECT COUNT(*) FROM telemetry_logs WHERE created_at > NOW() - 1h',
      reason: 'Authorized read telemetry aggregate query executed within memory quota.',
    },
  ];

  const events = customEvents && customEvents.length > 0 ? customEvents : defaultEvents;

  const getStatusIcon = (decision: SecurityEvent['decision']) => {
    switch (decision) {
      case 'Allowed':
        return <PixelCheckCircleIcon size={16} />;
      case 'Blocked':
        return <PixelCrossShieldIcon size={16} />;
      case 'Review':
        return <PixelClockCircleIcon size={16} />;
    }
  };

  return (
    <PixelCard className="h-full flex-1" innerClassName="p-3.5 justify-between h-full">
      {/* Header */}
      <div className="flex items-center justify-between pb-2 border-b border-[#25204c]">
        <div className="flex items-center gap-1.5">
          <div className="flex items-center justify-center text-[#c084fc]">
            <PixelLayersIcon size={16} />
          </div>
          <h3 className="text-[13.5px] font-bold text-white tracking-tight">
            Recent Events
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

      {/* Event Items */}
      <div className="flex flex-col justify-between gap-1.5 my-auto py-1">
        {events.slice(0, 4).map((evt) => (
          <button
            key={evt.id}
            onClick={() => onSelectEvent(evt)}
            className="flex items-center justify-between w-full py-1.5 px-2 rounded-lg text-left hover:bg-[#201d44] transition-colors group"
          >
            {/* Left: Status Icon + Event Name & Subtitle */}
            <div className="flex items-center gap-2.5">
              <div className="flex-shrink-0 flex items-center justify-center">
                {getStatusIcon(evt.decision)}
              </div>
              <div className="flex flex-col">
                <span className="text-[12px] font-semibold text-white group-hover:text-[#c4bbf0] transition-colors">
                  {evt.agent} · {evt.action}
                </span>
                <span className="text-[11px] text-[#8680b5] font-medium">
                  {evt.decision} · Risk <AnimatedNumber value={evt.riskScore} />
                </span>
              </div>
            </div>

            {/* Right: Timestamp */}
            <span className="text-[11px] text-[#7d77a8] font-medium whitespace-nowrap pl-2">
              {evt.timestamp}
            </span>
          </button>
        ))}
      </div>
    </PixelCard>
  );
};
