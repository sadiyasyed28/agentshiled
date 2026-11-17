import React from 'react';
import {
  PixelLayersIcon,
  PixelCheckCircleIcon,
  PixelClockCircleIcon,
  PixelCrossShieldIcon,
} from './pixel/PixelIcons';
import { PixelSparkline } from './pixel/PixelSparkline';
import { PixelCard } from './pixel/PixelCard';
import { AnimatedNumber } from './pixel/AnimatedNumber';

export interface KpiStats {
  total?: number;
  allowed?: number;
  review?: number;
  blocked?: number;
}

interface KpiSectionProps {
  stats?: KpiStats | null;
  isLoading?: boolean;
}

export const KpiSection: React.FC<KpiSectionProps> = ({ stats, isLoading = false }) => {
  const totalEvents = stats?.total ?? 0;
  const allowedEvents = stats?.allowed ?? 0;
  const reviewEvents = stats?.review ?? 0;
  const blockedEvents = stats?.blocked ?? 0;

  const hasActivity = totalEvents > 0;
  const allowPct = hasActivity ? Math.round((allowedEvents / totalEvents) * 100) : 0;
  const reviewPct = hasActivity ? Math.round((reviewEvents / totalEvents) * 100) : 0;
  const blockPct = hasActivity ? Math.round((blockedEvents / totalEvents) * 100) : 0;

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
      {/* Card 1: Total Events */}
      <PixelCard innerClassName="p-4 justify-between h-[112px]">
        <div className="flex items-center justify-between">
          <div className="flex items-center justify-center w-8.5 h-8.5 rounded-lg bg-[#2b1f59] text-[#c084fc] shadow-xs">
            <PixelLayersIcon size={19} />
          </div>
          {hasActivity ? (
            <span className="flex items-center gap-1 px-2 py-0.5 text-[11px] font-bold text-[#c7bff5] bg-[#292254] border border-[#3e3478] rounded-md">
              <span className="text-[10px]">●</span> LIVE
            </span>
          ) : (
            <span className="flex items-center gap-1 px-2 py-0.5 text-[11px] font-medium text-[#938ec0]/60 bg-[#1c1837] border border-[#2e265c] rounded-md">
              0 recorded
            </span>
          )}
        </div>
        <div className="mt-2">
          <div className="text-[28px] font-bold text-white tracking-tight leading-none">
            {isLoading ? <span className="text-white/40">--</span> : <AnimatedNumber value={totalEvents} />}
          </div>
          <div className="text-[12.5px] font-medium text-[#938ec0] mt-1">
            Total Events
          </div>
        </div>
      </PixelCard>

      {/* Card 2: Allowed */}
      <PixelCard innerClassName="p-4 justify-between h-[112px]">
        <div className="flex items-center justify-between">
          <div className="flex items-center justify-center w-8.5 h-8.5 rounded-lg bg-[#153e28] text-[#4ade80] shadow-xs">
            <PixelCheckCircleIcon size={19} />
          </div>
          {hasActivity ? (
            <span className="flex items-center gap-1 px-2 py-0.5 text-[11px] font-bold text-[#4ade80] bg-[#153e28]/80 border border-[#226742] rounded-md">
              <AnimatedNumber value={allowPct} suffix="%" />
            </span>
          ) : (
            <span className="flex items-center gap-1 px-2 py-0.5 text-[11px] font-medium text-[#938ec0]/60 bg-[#1c1837] border border-[#2e265c] rounded-md">
              0%
            </span>
          )}
        </div>
        <div className="flex items-end justify-between mt-2">
          <div>
            <div className="text-[28px] font-bold text-white tracking-tight leading-none">
              {isLoading ? <span className="text-white/40">--</span> : <AnimatedNumber value={allowedEvents} />}
            </div>
            <div className="text-[12.5px] font-medium text-[#938ec0] mt-1">
              Allowed
            </div>
          </div>
          <div className="pb-0.5 pr-1">
            <PixelSparkline
              color="green"
              data={hasActivity ? [Math.max(0, allowedEvents - 2), allowedEvents, allowedEvents] : [0, 0, 0]}
              width={96}
              height={30}
            />
          </div>
        </div>
      </PixelCard>

      {/* Card 3: Review */}
      <PixelCard innerClassName="p-4 justify-between h-[112px]">
        <div className="flex items-center justify-between">
          <div className="flex items-center justify-center w-8.5 h-8.5 rounded-lg bg-[#403413] text-[#facc15] shadow-xs">
            <PixelClockCircleIcon size={19} />
          </div>
          {hasActivity ? (
            <span className="flex items-center gap-1 px-2 py-0.5 text-[11px] font-bold text-[#facc15] bg-[#403413]/80 border border-[#6b551c] rounded-md">
              <AnimatedNumber value={reviewPct} suffix="%" />
            </span>
          ) : (
            <span className="flex items-center gap-1 px-2 py-0.5 text-[11px] font-medium text-[#938ec0]/60 bg-[#1c1837] border border-[#2e265c] rounded-md">
              0%
            </span>
          )}
        </div>
        <div className="flex items-end justify-between mt-2">
          <div>
            <div className="text-[28px] font-bold text-white tracking-tight leading-none">
              {isLoading ? <span className="text-white/40">--</span> : <AnimatedNumber value={reviewEvents} />}
            </div>
            <div className="text-[12.5px] font-medium text-[#938ec0] mt-1">
              Review
            </div>
          </div>
          <div className="pb-0.5 pr-1">
            <PixelSparkline
              color="yellow"
              data={hasActivity ? [Math.max(0, reviewEvents - 1), reviewEvents, reviewEvents] : [0, 0, 0]}
              width={96}
              height={30}
            />
          </div>
        </div>
      </PixelCard>

      {/* Card 4: Blocked */}
      <PixelCard innerClassName="p-4 justify-between h-[112px]">
        <div className="flex items-center justify-between">
          <div className="flex items-center justify-center w-8.5 h-8.5 rounded-lg bg-[#4a1c25] text-[#f87171] shadow-xs">
            <PixelCrossShieldIcon size={19} />
          </div>
          {hasActivity ? (
            <span className="flex items-center gap-1 px-2 py-0.5 text-[11px] font-bold text-[#f87171] bg-[#4a1c25]/80 border border-[#782836] rounded-md">
              <AnimatedNumber value={blockPct} suffix="%" />
            </span>
          ) : (
            <span className="flex items-center gap-1 px-2 py-0.5 text-[11px] font-medium text-[#938ec0]/60 bg-[#1c1837] border border-[#2e265c] rounded-md">
              0%
            </span>
          )}
        </div>
        <div className="flex items-end justify-between mt-2">
          <div>
            <div className="text-[28px] font-bold text-white tracking-tight leading-none">
              {isLoading ? <span className="text-white/40">--</span> : <AnimatedNumber value={blockedEvents} />}
            </div>
            <div className="text-[12.5px] font-medium text-[#938ec0] mt-1">
              Blocked
            </div>
          </div>
          <div className="pb-0.5 pr-1">
            <PixelSparkline
              color="red"
              data={hasActivity ? [Math.max(0, blockedEvents - 1), blockedEvents, blockedEvents] : [0, 0, 0]}
              width={96}
              height={30}
            />
          </div>
        </div>
      </PixelCard>
    </div>
  );
};
