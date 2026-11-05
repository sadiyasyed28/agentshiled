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
}

export const KpiSection: React.FC<KpiSectionProps> = ({ stats }) => {
  const totalEvents = stats?.total ?? 3842;
  const allowedEvents = stats?.allowed ?? 2976;
  const reviewEvents = stats?.review ?? 437;
  const blockedEvents = stats?.blocked ?? 429;

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
      {/* Card 1: Total Events (NO sparkline, exactly matching Reference A) */}
      <PixelCard innerClassName="p-4 justify-between h-[112px]">
        <div className="flex items-center justify-between">
          <div className="flex items-center justify-center w-8.5 h-8.5 rounded-lg bg-[#2b1f59] text-[#c084fc] shadow-xs">
            <PixelLayersIcon size={19} />
          </div>
          <span className="flex items-center gap-1 px-2 py-0.5 text-[11px] font-bold text-[#c7bff5] bg-[#292254] border border-[#3e3478] rounded-md">
            <span className="text-[10px]">↑</span> <AnimatedNumber value={12} prefix="+" suffix="%" />
          </span>
        </div>
        <div className="mt-2">
          <div className="text-[28px] font-bold text-white tracking-tight leading-none">
            <AnimatedNumber value={totalEvents} />
          </div>
          <div className="text-[12.5px] font-medium text-[#938ec0] mt-1">
            Total Events
          </div>
        </div>
      </PixelCard>

      {/* Card 2: Allowed (With Green Sparkline) */}
      <PixelCard innerClassName="p-4 justify-between h-[112px]">
        <div className="flex items-center justify-between">
          <div className="flex items-center justify-center w-8.5 h-8.5 rounded-lg bg-[#153e28] text-[#4ade80] shadow-xs">
            <PixelCheckCircleIcon size={19} />
          </div>
          <span className="flex items-center gap-1 px-2 py-0.5 text-[11px] font-bold text-[#c7bff5] bg-[#292254] border border-[#3e3478] rounded-md">
            <span className="text-[10px]">↑</span> <AnimatedNumber value={14} prefix="+" suffix="%" />
          </span>
        </div>
        <div className="flex items-end justify-between mt-2">
          <div>
            <div className="text-[28px] font-bold text-white tracking-tight leading-none">
              <AnimatedNumber value={allowedEvents} />
            </div>
            <div className="text-[12.5px] font-medium text-[#938ec0] mt-1">
              Allowed
            </div>
          </div>
          <div className="pb-0.5 pr-1">
            <PixelSparkline
              color="green"
              data={[240, 270, 250, 320, 390, 380, 490]}
              width={96}
              height={30}
            />
          </div>
        </div>
      </PixelCard>

      {/* Card 3: Review (With Yellow Sparkline) */}
      <PixelCard innerClassName="p-4 justify-between h-[112px]">
        <div className="flex items-center justify-between">
          <div className="flex items-center justify-center w-8.5 h-8.5 rounded-lg bg-[#403413] text-[#facc15] shadow-xs">
            <PixelClockCircleIcon size={19} />
          </div>
          <span className="flex items-center gap-1 px-2 py-0.5 text-[11px] font-bold text-[#c7bff5] bg-[#292254] border border-[#3e3478] rounded-md">
            <span className="text-[10px]">↑</span> <AnimatedNumber value={6} prefix="+" suffix="%" />
          </span>
        </div>
        <div className="flex items-end justify-between mt-2">
          <div>
            <div className="text-[28px] font-bold text-white tracking-tight leading-none">
              <AnimatedNumber value={reviewEvents} />
            </div>
            <div className="text-[12.5px] font-medium text-[#938ec0] mt-1">
              Review
            </div>
          </div>
          <div className="pb-0.5 pr-1">
            <PixelSparkline
              color="yellow"
              data={[45, 50, 48, 55, 60, 52, 65]}
              width={96}
              height={30}
            />
          </div>
        </div>
      </PixelCard>

      {/* Card 4: Blocked (With Red Sparkline) */}
      <PixelCard innerClassName="p-4 justify-between h-[112px]">
        <div className="flex items-center justify-between">
          <div className="flex items-center justify-center w-8.5 h-8.5 rounded-lg bg-[#4a1c25] text-[#f87171] shadow-xs">
            <PixelCrossShieldIcon size={19} />
          </div>
          <span className="flex items-center gap-1 px-2 py-0.5 text-[11px] font-bold text-[#c7bff5] bg-[#292254] border border-[#3e3478] rounded-md">
            <span className="text-[10px]">↑</span> <AnimatedNumber value={18} prefix="+" suffix="%" />
          </span>
        </div>
        <div className="flex items-end justify-between mt-2">
          <div>
            <div className="text-[28px] font-bold text-white tracking-tight leading-none">
              <AnimatedNumber value={blockedEvents} />
            </div>
            <div className="text-[12.5px] font-medium text-[#938ec0] mt-1">
              Blocked
            </div>
          </div>
          <div className="pb-0.5 pr-1">
            <PixelSparkline
              color="red"
              data={[30, 42, 35, 48, 50, 42, 58]}
              width={96}
              height={30}
            />
          </div>
        </div>
      </PixelCard>
    </div>
  );
};
