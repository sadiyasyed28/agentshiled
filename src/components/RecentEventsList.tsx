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
  const events = customEvents || [];

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
          <span className="text-[11px] font-mono text-[#847ea8]">({events.length})</span>
        </div>

        <button
          onClick={onViewAll}
          className="flex items-center gap-1 text-[11.5px] font-semibold text-[#8b84bd] hover:text-[#c4bbf0] transition-colors group"
        >
          <span>View All</span>
          <ArrowRight size={12} className="group-hover:translate-x-0.5 transition-transform" />
        </button>
      </div>

      {/* Event Items or Empty State */}
      <div className="flex flex-col justify-between gap-1.5 my-auto py-1">
        {events.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-7 text-center">
            <div className="w-8 h-8 rounded-lg bg-[#2b1f59] text-[#c084fc] flex items-center justify-center mb-2 shadow-xs">
              <PixelLayersIcon size={18} />
            </div>
            <span className="text-[13px] font-semibold text-white">No Recent Events</span>
            <span className="text-[11.5px] text-[#847ea8] mt-1 max-w-[280px]">
              Live security decisions will appear here as your agents invoke tools.
            </span>
          </div>
        ) : (
          events.slice(0, 4).map((evt) => (
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
          ))
        )}
      </div>
    </PixelCard>
  );
};
