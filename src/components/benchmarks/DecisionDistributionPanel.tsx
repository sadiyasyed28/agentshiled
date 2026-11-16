import React from 'react';
import { PixelStarShieldBadgeIcon } from '../pixel/PixelIcons';
import { AnimatedNumber } from '../pixel/AnimatedNumber';
import type { BenchmarkRunRecord } from './benchmarkTypes';

interface DecisionDistributionPanelProps {
  currentRun: BenchmarkRunRecord;
}

export const DecisionDistributionPanel: React.FC<DecisionDistributionPanelProps> = ({ currentRun }) => {
  const total = currentRun.total;
  const allowed = currentRun.allowedCount;
  const review = currentRun.reviewCount;
  const blocked = currentRun.blockedCount;

  const allowedPct = total > 0 ? (allowed / total) * 100 : 0;
  const reviewPct = total > 0 ? (review / total) * 100 : 0;
  const blockedPct = total > 0 ? (blocked / total) * 100 : 0;

  // SVG Donut metrics
  const radius = 54;
  const circumference = 2 * Math.PI * radius; // ~339.292

  const allowedDash = total > 0 ? (allowed / total) * circumference : 0;
  const reviewDash = total > 0 ? (review / total) * circumference : 0;
  const blockedDash = total > 0 ? (blocked / total) * circumference : 0;

  const allowedOffset = 0;
  const reviewOffset = -allowedDash;
  const blockedOffset = -(allowedDash + reviewDash);

  return (
    <div className="relative p-[1.5px] bg-[#3a3273] hover:bg-[#453c85] pixel-corners shadow-[0_4px_16px_rgba(0,0,0,0.4)] transition-colors duration-150 h-full flex flex-col">
      <div className="w-full h-full bg-[#16142e] pixel-corners p-4 md:p-4.5 flex flex-col justify-between">
        {/* PANEL HEADER */}
        <div className="flex items-center gap-2 pb-3 border-b border-[#292254]">
          <PixelStarShieldBadgeIcon size={18} />
          <span className="text-sm font-bold text-white tracking-wide">
            Decision Distribution (Protected)
          </span>
        </div>

        {/* DONUT & LEGEND SPLIT */}
        <div className="flex-1 flex flex-col sm:flex-row items-center justify-between gap-4 py-2">
          {/* LEFT: DONUT CHART */}
          <div className="relative w-36 h-36 flex items-center justify-center flex-shrink-0">
            <svg
              key={currentRun.id}
              className="w-full h-full transform -rotate-90"
              viewBox="0 0 140 140"
            >
              {/* Background circle track */}
              <circle
                cx="70"
                cy="70"
                r={radius}
                fill="transparent"
                stroke="#1f1b3d"
                strokeWidth="16"
              />

              {/* 1. Allowed Segment (Green) */}
              <circle
                cx="70"
                cy="70"
                r={radius}
                fill="transparent"
                stroke="#22c55e"
                strokeWidth="16"
                strokeDasharray={`${allowedDash} ${circumference}`}
                strokeDashoffset={allowedOffset}
                className="donut-segment"
                style={
                  {
                    '--donut-length': allowedDash,
                    '--donut-gap': circumference,
                  } as React.CSSProperties
                }
              />

              {/* 2. Review Segment (Yellow) */}
              <circle
                cx="70"
                cy="70"
                r={radius}
                fill="transparent"
                stroke="#eab308"
                strokeWidth="16"
                strokeDasharray={`${reviewDash} ${circumference}`}
                strokeDashoffset={reviewOffset}
                className="donut-segment"
                style={
                  {
                    '--donut-length': reviewDash,
                    '--donut-gap': circumference,
                    animationDelay: '160ms',
                  } as React.CSSProperties
                }
              />

              {/* 3. Blocked Segment (Red) */}
              <circle
                cx="70"
                cy="70"
                r={radius}
                fill="transparent"
                stroke="#ef4444"
                strokeWidth="16"
                strokeDasharray={`${blockedDash} ${circumference}`}
                strokeDashoffset={blockedOffset}
                className="donut-segment"
                style={
                  {
                    '--donut-length': blockedDash,
                    '--donut-gap': circumference,
                    animationDelay: '300ms',
                  } as React.CSSProperties
                }
              />
            </svg>

            {/* Donut Center Display */}
            <div className="absolute inset-0 flex flex-col items-center justify-center text-center pointer-events-none">
              <span className="text-[22px] font-bold text-white font-mono leading-none tracking-tight">
                <AnimatedNumber value={total} />
              </span>
              <span className="text-[11px] font-medium text-[#9c96c9] mt-0.5">
                Decisions
              </span>
            </div>
          </div>

          {/* RIGHT: LEGEND TABLE */}
          <div className="flex-1 w-full flex flex-col justify-center space-y-3 pl-2 sm:pl-4">
            {/* Allowed row */}
            <div className="flex items-center justify-between text-xs">
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-xs bg-[#22c55e] shadow-[0_0_6px_rgba(34,197,94,0.4)]" />
                <span className="font-semibold text-white">Allowed</span>
              </div>
              <div className="flex items-center gap-4">
                <span className="font-mono text-[#b8b0e0] w-12 text-right">
                  <AnimatedNumber value={allowedPct} decimals={1} suffix="%" />
                </span>
                <span className="font-mono font-bold text-white w-6 text-right">
                  <AnimatedNumber value={allowed} />
                </span>
              </div>
            </div>

            {/* Review row */}
            <div className="flex items-center justify-between text-xs">
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-xs bg-[#eab308] shadow-[0_0_6px_rgba(234,179,8,0.4)]" />
                <span className="font-semibold text-white">Review</span>
              </div>
              <div className="flex items-center gap-4">
                <span className="font-mono text-[#b8b0e0] w-12 text-right">
                  <AnimatedNumber value={reviewPct} decimals={1} suffix="%" />
                </span>
                <span className="font-mono font-bold text-white w-6 text-right">
                  <AnimatedNumber value={review} />
                </span>
              </div>
            </div>

            {/* Blocked row */}
            <div className="flex items-center justify-between text-xs">
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-xs bg-[#ef4444] shadow-[0_0_6px_rgba(239,68,68,0.4)]" />
                <span className="font-semibold text-white">Blocked</span>
              </div>
              <div className="flex items-center gap-4">
                <span className="font-mono text-[#b8b0e0] w-12 text-right">
                  <AnimatedNumber value={blockedPct} decimals={1} suffix="%" />
                </span>
                <span className="font-mono font-bold text-white w-6 text-right">
                  <AnimatedNumber value={blocked} />
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
