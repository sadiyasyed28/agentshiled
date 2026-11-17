import React from 'react';
import { PixelSparkline } from '../pixel/PixelSparkline';
import { PixelLayersIcon } from '../pixel/PixelIcons';
import { AnimatedNumber } from '../pixel/AnimatedNumber';

interface EventsKpiSectionProps {
  events?: { decision: string }[];
  stats?: {
    total?: number;
    allowed?: number;
    review?: number;
    blocked?: number;
  } | null;
}

export const EventsKpiSection: React.FC<EventsKpiSectionProps> = ({ events, stats }) => {
  const derivedTotal = events ? events.length : (stats?.total ?? 0);
  const derivedAllowed = events
    ? events.filter((e) => e.decision === 'Allowed' || e.decision === 'ALLOW').length
    : (stats?.allowed ?? 0);
  const derivedReview = events
    ? events.filter((e) => e.decision === 'Review' || e.decision === 'REVIEW').length
    : (stats?.review ?? 0);
  const derivedBlocked = events
    ? events.filter((e) => e.decision === 'Blocked' || e.decision === 'BLOCK').length
    : (stats?.blocked ?? 0);

  const total = derivedTotal;
  const allowed = derivedAllowed;
  const review = derivedReview;
  const blocked = derivedBlocked;

  const hasActivity = total > 0;
  const allowPct = hasActivity ? Number(((allowed / total) * 100).toFixed(1)) : 0;
  const reviewPct = hasActivity ? Number(((review / total) * 100).toFixed(1)) : 0;
  const blockPct = hasActivity ? Number(((blocked / total) * 100).toFixed(1)) : 0;

  const allowedTrend = hasActivity ? [Math.max(0, allowed - 2), allowed, allowed] : [0, 0, 0];
  const reviewTrend = hasActivity ? [Math.max(0, review - 1), review, review] : [0, 0, 0];
  const blockedTrend = hasActivity ? [Math.max(0, blocked - 1), blocked, blocked] : [0, 0, 0];

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5 mb-3.5">
      {/* 1. TOTAL EVENTS */}
      <div className="relative p-[1.5px] bg-[#3a3273] hover:bg-[#4c4294] pixel-corners shadow-[0_4px_16px_rgba(0,0,0,0.4)] transition-colors duration-150">
        <div className="w-full h-full bg-[#16142e] pixel-corners p-4 flex flex-col justify-between min-h-[108px]">
          <div className="flex items-start justify-between">
            {/* Top Left Icon */}
            <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-[#26204d] border border-[#453c7a] text-[#c4bbf0] shadow-sm">
              <PixelLayersIcon size={18} />
            </div>

            {/* Top Right Percentage Badge */}
            <div className="flex items-center gap-1 px-2 py-0.5 rounded-md bg-[#2b1f54] border border-[#533b9c] text-[#d8b4fe] text-xs font-semibold">
              <span>↑</span>
              <AnimatedNumber value={12} prefix="+" suffix="%" />
            </div>
          </div>

          <div className="mt-2.5">
            <div className="text-[26px] font-bold text-white tracking-tight leading-none font-mono">
              <AnimatedNumber value={total} />
            </div>
            <div className="text-xs font-medium text-[#9c96c9] mt-1">
              Total Events
            </div>
          </div>
        </div>
      </div>

      {/* 2. ALLOWED */}
      <div className="relative p-[1.5px] bg-[#3a3273] hover:bg-[#4c4294] pixel-corners shadow-[0_4px_16px_rgba(0,0,0,0.4)] transition-colors duration-150">
        <div className="w-full h-full bg-[#16142e] pixel-corners p-4 flex flex-col justify-between min-h-[108px] overflow-hidden relative">
          <div className="flex items-start justify-between relative z-10">
            {/* Green Check Circle Pixel Icon */}
            <div className="flex items-center justify-center w-8 h-8 rounded-full bg-[#15803d]/30 border border-[#22c55e]/60 shadow-[0_0_10px_rgba(34,197,94,0.25)]">
              <svg width="18" height="18" viewBox="0 0 16 16" fill="none" className="pixelated" shapeRendering="crispEdges">
                <rect x="3" y="1" width="10" height="14" fill="#22c55e" />
                <rect x="1" y="3" width="14" height="10" fill="#22c55e" />
                <rect x="4" y="8" width="2" height="2" fill="#ffffff" />
                <rect x="6" y="10" width="2" height="2" fill="#ffffff" />
                <rect x="8" y="8" width="2" height="2" fill="#ffffff" />
                <rect x="10" y="6" width="2" height="2" fill="#ffffff" />
                <rect x="11" y="5" width="2" height="2" fill="#ffffff" />
              </svg>
            </div>

            {/* Top Right Percentage Badge */}
            <div className="px-2 py-0.5 rounded-md bg-[#1d1a3d] border border-[#39326b] text-[#a59ecd] text-xs font-semibold">
              <AnimatedNumber value={allowPct} decimals={1} suffix="%" />
            </div>
          </div>

          <div className="flex items-end justify-between mt-2.5 relative z-10">
            <div>
              <div className="text-[26px] font-bold text-white tracking-tight leading-none font-mono">
                <AnimatedNumber value={allowed} />
              </div>
              <div className="text-xs font-medium text-[#9c96c9] mt-1">
                Allowed
              </div>
            </div>

            {/* Sparkline on Bottom Right */}
            <div className="opacity-95 -mb-1">
              <PixelSparkline color="green" data={allowedTrend} width={100} height={32} />
            </div>
          </div>
        </div>
      </div>

      {/* 3. REVIEW */}
      <div className="relative p-[1.5px] bg-[#3a3273] hover:bg-[#4c4294] pixel-corners shadow-[0_4px_16px_rgba(0,0,0,0.4)] transition-colors duration-150">
        <div className="w-full h-full bg-[#16142e] pixel-corners p-4 flex flex-col justify-between min-h-[108px] overflow-hidden relative">
          <div className="flex items-start justify-between relative z-10">
            {/* Yellow Clock Circle Pixel Icon */}
            <div className="flex items-center justify-center w-8 h-8 rounded-full bg-[#a16207]/30 border border-[#eab308]/60 shadow-[0_0_10px_rgba(234,179,8,0.25)]">
              <svg width="18" height="18" viewBox="0 0 16 16" fill="none" className="pixelated" shapeRendering="crispEdges">
                <rect x="3" y="1" width="10" height="14" fill="#eab308" />
                <rect x="1" y="3" width="14" height="10" fill="#eab308" />
                <rect x="7" y="4" width="2" height="5" fill="#1b173b" />
                <rect x="8" y="7" width="4" height="2" fill="#1b173b" />
              </svg>
            </div>

            {/* Top Right Percentage Badge */}
            <div className="px-2 py-0.5 rounded-md bg-[#1d1a3d] border border-[#39326b] text-[#a59ecd] text-xs font-semibold">
              <AnimatedNumber value={reviewPct} decimals={1} suffix="%" />
            </div>
          </div>

          <div className="flex items-end justify-between mt-2.5 relative z-10">
            <div>
              <div className="text-[26px] font-bold text-white tracking-tight leading-none font-mono">
                <AnimatedNumber value={review} />
              </div>
              <div className="text-xs font-medium text-[#9c96c9] mt-1">
                Review
              </div>
            </div>

            {/* Sparkline on Bottom Right */}
            <div className="opacity-95 -mb-1">
              <PixelSparkline color="yellow" data={reviewTrend} width={100} height={32} />
            </div>
          </div>
        </div>
      </div>

      {/* 4. BLOCKED */}
      <div className="relative p-[1.5px] bg-[#3a3273] hover:bg-[#4c4294] pixel-corners shadow-[0_4px_16px_rgba(0,0,0,0.4)] transition-colors duration-150">
        <div className="w-full h-full bg-[#16142e] pixel-corners p-4 flex flex-col justify-between min-h-[108px] overflow-hidden relative">
          <div className="flex items-start justify-between relative z-10">
            {/* Red Cross Circle Pixel Icon */}
            <div className="flex items-center justify-center w-8 h-8 rounded-full bg-[#b91c1c]/30 border border-[#ef4444]/60 shadow-[0_0_10px_rgba(239,68,68,0.25)]">
              <svg width="18" height="18" viewBox="0 0 16 16" fill="none" className="pixelated" shapeRendering="crispEdges">
                <rect x="3" y="1" width="10" height="14" fill="#ef4444" />
                <rect x="1" y="3" width="14" height="10" fill="#ef4444" />
                <rect x="4" y="4" width="2" height="2" fill="#ffffff" />
                <rect x="10" y="4" width="2" height="2" fill="#ffffff" />
                <rect x="6" y="6" width="4" height="4" fill="#ffffff" />
                <rect x="4" y="10" width="2" height="2" fill="#ffffff" />
                <rect x="10" y="10" width="2" height="2" fill="#ffffff" />
              </svg>
            </div>

            {/* Top Right Percentage Badge */}
            <div className="px-2 py-0.5 rounded-md bg-[#1d1a3d] border border-[#39326b] text-[#a59ecd] text-xs font-semibold">
              <AnimatedNumber value={blockPct} decimals={1} suffix="%" />
            </div>
          </div>

          <div className="flex items-end justify-between mt-2.5 relative z-10">
            <div>
              <div className="text-[26px] font-bold text-white tracking-tight leading-none font-mono">
                <AnimatedNumber value={blocked} />
              </div>
              <div className="text-xs font-medium text-[#9c96c9] mt-1">
                Blocked
              </div>
            </div>

            {/* Sparkline on Bottom Right */}
            <div className="opacity-95 -mb-1">
              <PixelSparkline color="red" data={blockedTrend} width={100} height={32} />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

