import React from 'react';
import { PixelHourglassIcon } from './ReviewIcons';
import { AnimatedNumber } from '../pixel/AnimatedNumber';

interface ReviewKpiSectionProps {
  pendingCount: number;
  approvedCount: number;
  deniedCount: number;
  expiredCount: number;
}

export const ReviewKpiSection: React.FC<ReviewKpiSectionProps> = ({
  pendingCount,
  approvedCount,
  deniedCount,
  expiredCount,
}) => {
  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-3.5 mb-3.5">
      {/* 1. PENDING REVIEW */}
      <div className="relative p-[1.5px] bg-[#3a3273] hover:bg-[#4c4294] pixel-corners shadow-[0_4px_16px_rgba(0,0,0,0.4)] transition-colors duration-150">
        <div className="w-full h-full bg-[#16142e] pixel-corners p-4 flex flex-col justify-between min-h-[105px]">
          <div className="flex items-start justify-between">
            {/* Amber Clock Circle Pixel Icon */}
            <div className="flex items-center justify-center w-8 h-8 rounded-full bg-[#a16207]/30 border border-[#eab308]/60 shadow-[0_0_10px_rgba(234,179,8,0.25)]">
              <svg width="18" height="18" viewBox="0 0 16 16" fill="none" className="pixelated" shapeRendering="crispEdges">
                <rect x="3" y="1" width="10" height="14" fill="#eab308" />
                <rect x="1" y="3" width="14" height="10" fill="#eab308" />
                <rect x="7" y="4" width="2" height="5" fill="#1b173b" />
                <rect x="8" y="7" width="4" height="2" fill="#1b173b" />
              </svg>
            </div>

            {/* Status indicator */}
            <div className={`flex items-center gap-1 px-2 py-0.5 rounded-md text-[10px] font-mono font-semibold ${
              pendingCount > 0
                ? 'bg-[#332b14] border border-[#71540f] text-[#facc15]'
                : 'bg-[#1b173b] border border-[#3a3273] text-[#8b87a8]'
            }`}>
              <span>{pendingCount > 0 ? 'QUEUE ACTIVE' : 'QUEUE EMPTY'}</span>
            </div>
          </div>

          <div className="mt-2">
            <div className="text-[26px] font-bold text-white tracking-tight leading-none font-mono">
              <AnimatedNumber value={pendingCount} />
            </div>
            <div className="text-xs font-medium text-[#9c96c9] mt-1">
              Pending Review
            </div>
          </div>
        </div>
      </div>

      {/* 2. APPROVED */}
      <div className="relative p-[1.5px] bg-[#3a3273] hover:bg-[#4c4294] pixel-corners shadow-[0_4px_16px_rgba(0,0,0,0.4)] transition-colors duration-150">
        <div className="w-full h-full bg-[#16142e] pixel-corners p-4 flex flex-col justify-between min-h-[105px]">
          <div className="flex items-start justify-between">
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

            {/* Resolved Badge */}
            <div className={`flex items-center gap-1 px-2 py-0.5 rounded-md text-[10px] font-mono font-semibold ${
              approvedCount > 0
                ? 'bg-[#14331b] border border-[#1f6633] text-[#4ade80]'
                : 'bg-[#1b173b] border border-[#3a3273] text-[#8b87a8]'
            }`}>
              <span>{approvedCount > 0 ? 'RESOLVED' : '0 RESOLVED'}</span>
            </div>
          </div>

          <div className="mt-2">
            <div className="text-[26px] font-bold text-white tracking-tight leading-none font-mono">
              <AnimatedNumber value={approvedCount} />
            </div>
            <div className="text-xs font-medium text-[#9c96c9] mt-1">
              Approved
            </div>
          </div>
        </div>
      </div>

      {/* 3. DENIED */}
      <div className="relative p-[1.5px] bg-[#3a3273] hover:bg-[#4c4294] pixel-corners shadow-[0_4px_16px_rgba(0,0,0,0.4)] transition-colors duration-150">
        <div className="w-full h-full bg-[#16142e] pixel-corners p-4 flex flex-col justify-between min-h-[105px]">
          <div className="flex items-start justify-between">
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

            {/* Resolved Badge */}
            <div className={`flex items-center gap-1 px-2 py-0.5 rounded-md text-[10px] font-mono font-semibold ${
              deniedCount > 0
                ? 'bg-[#381616] border border-[#782424] text-[#f87171]'
                : 'bg-[#1b173b] border border-[#3a3273] text-[#8b87a8]'
            }`}>
              <span>{deniedCount > 0 ? 'RESOLVED' : '0 RESOLVED'}</span>
            </div>
          </div>

          <div className="mt-2">
            <div className="text-[26px] font-bold text-white tracking-tight leading-none font-mono">
              <AnimatedNumber value={deniedCount} />
            </div>
            <div className="text-xs font-medium text-[#9c96c9] mt-1">
              Denied
            </div>
          </div>
        </div>
      </div>

      {/* 4. EXPIRED */}
      <div className="relative p-[1.5px] bg-[#3a3273] hover:bg-[#4c4294] pixel-corners shadow-[0_4px_16px_rgba(0,0,0,0.4)] transition-colors duration-150">
        <div className="w-full h-full bg-[#16142e] pixel-corners p-4 flex flex-col justify-between min-h-[105px]">
          <div className="flex items-start justify-between">
            {/* Hourglass Pixel Icon */}
            <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-[#26204d] border border-[#453c7a] text-[#c4bbf0] shadow-sm">
              <PixelHourglassIcon size={18} />
            </div>

            {/* Status indicator */}
            <div className="flex items-center gap-1 px-2 py-0.5 rounded-md bg-[#1b173b] border border-[#3a3273] text-[#8b87a8] text-[10px] font-mono font-semibold">
              <span>{expiredCount > 0 ? 'EXPIRED' : '0 EXPIRED'}</span>
            </div>
          </div>

          <div className="mt-2">
            <div className="text-[26px] font-bold text-white tracking-tight leading-none font-mono">
              <AnimatedNumber value={expiredCount} />
            </div>
            <div className="text-xs font-medium text-[#9c96c9] mt-1">
              Expired
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

