import React from 'react';
import { PixelLayersIcon, PixelInfoIcon } from './pixel/PixelIcons';
import { PixelCard } from './pixel/PixelCard';
import { AnimatedNumber } from './pixel/AnimatedNumber';

export interface DecisionCounts {
  allowed?: number;
  review?: number;
  blocked?: number;
}

interface DecisionDistributionProps {
  counts?: DecisionCounts | null;
}

export const DecisionDistribution: React.FC<DecisionDistributionProps> = ({ counts }) => {
  const allowCount = counts?.allowed ?? 2976;
  const reviewCount = counts?.review ?? 437;
  const blockCount = counts?.blocked ?? 429;
  const total = allowCount + reviewCount + blockCount || 3842;

  const allowPct = Number(((allowCount / total) * 100).toFixed(1));
  const reviewPct = Number(((reviewCount / total) * 100).toFixed(1));
  const blockPct = Number(Math.max(0, 100 - allowPct - reviewPct).toFixed(1));

  const circumference = 276.4;
  const allowLen = Number(((allowPct / 100) * circumference).toFixed(1));
  const reviewLen = Number(((reviewPct / 100) * circumference).toFixed(1));
  const blockLen = Number(((blockPct / 100) * circumference).toFixed(1));

  const items = [
    { label: 'Allowed', percentage: allowPct, count: allowCount, color: '#22c55e' },
    { label: 'Review', percentage: reviewPct, count: reviewCount, color: '#eab308' },
    { label: 'Blocked', percentage: blockPct, count: blockCount, color: '#ef4444' },
  ];

  return (
    <PixelCard className="h-full flex-1" innerClassName="p-3.5 justify-between h-full">
      {/* Header */}
      <div className="flex items-center gap-1.5 pb-2 border-b border-[#25204c]">
        <div className="flex items-center justify-center text-[#a855f7]">
          <PixelLayersIcon size={16} />
        </div>
        <h3 className="text-[13.5px] font-bold text-white tracking-tight">
          Decision Distribution
        </h3>
        <button
          title="Breakdown of security enforcement decisions across all monitored events"
          className="text-[#7d77a8] hover:text-[#c4bbf0] transition-colors ml-0.5"
        >
          <PixelInfoIcon size={13} />
        </button>
      </div>

      {/* Body: Donut on Left, Legend on Right */}
      <div className="flex flex-row items-center justify-center gap-5 my-auto py-2">
        {/* Pixel-Stepped Donut Chart */}
        <div className="relative flex items-center justify-center w-32 h-32 flex-shrink-0">
          <svg
            viewBox="0 0 120 120"
            className="w-full h-full pixelated transform -rotate-90"
            shapeRendering="crispEdges"
          >
            {/* Dark background ring */}
            <circle
              cx="60"
              cy="60"
              r="44"
              fill="none"
              stroke="#211d47"
              strokeWidth="15"
            />

            {/* Allowed Arc: Green */}
            <circle
              cx="60"
              cy="60"
              r="44"
              fill="none"
              stroke="#22c55e"
              strokeWidth="15"
              strokeDasharray={`${allowLen} ${circumference}`}
              strokeDashoffset="0"
              className="donut-segment"
              style={
                {
                  '--donut-length': String(allowLen),
                  '--donut-gap': String(circumference),
                } as React.CSSProperties
              }
            />

            {/* Review Arc: Yellow */}
            <circle
              cx="60"
              cy="60"
              r="44"
              fill="none"
              stroke="#eab308"
              strokeWidth="15"
              strokeDasharray={`${reviewLen} ${circumference}`}
              strokeDashoffset={`-${allowLen}`}
              className="donut-segment"
              style={
                {
                  '--donut-length': String(reviewLen),
                  '--donut-gap': String(circumference),
                  animationDelay: '180ms',
                } as React.CSSProperties
              }
            />

            {/* Blocked Arc: Red */}
            <circle
              cx="60"
              cy="60"
              r="44"
              fill="none"
              stroke="#ef4444"
              strokeWidth="15"
              strokeDasharray={`${blockLen} ${circumference}`}
              strokeDashoffset={`-${(allowLen + reviewLen).toFixed(1)}`}
              className="donut-segment"
              style={
                {
                  '--donut-length': String(blockLen),
                  '--donut-gap': String(circumference),
                  animationDelay: '320ms',
                } as React.CSSProperties
              }
            />

            {/* Stepped pixel rim notches for 16-bit retro texture */}
            <circle
              cx="60"
              cy="60"
              r="52"
              fill="none"
              stroke="#181635"
              strokeWidth="1.5"
              strokeDasharray="3 2"
            />
            <circle
              cx="60"
              cy="60"
              r="36"
              fill="none"
              stroke="#181635"
              strokeWidth="1.5"
              strokeDasharray="3 2"
            />
          </svg>

          {/* Center Label */}
          <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none text-center">
            <span className="text-[18px] font-bold text-white tracking-tight leading-none">
              <AnimatedNumber value={total} />
            </span>
            <span className="text-[9.5px] font-medium text-[#938ec0] mt-0.5">
              Total Events
            </span>
          </div>
        </div>

        {/* Legend on the right */}
        <div className="flex flex-col gap-2.5 flex-1 max-w-[150px]">
          {items.map((item) => (
            <div key={item.label} className="flex items-center justify-between text-xs font-medium">
              <div className="flex items-center gap-2">
                <span
                  className="w-2.5 h-2.5 rounded-xs flex-shrink-0"
                  style={{ backgroundColor: item.color }}
                />
                <span className="text-[#9e98c9] text-[12px]">{item.label}</span>
              </div>
              <div className="flex items-center gap-2.5">
                <span className="text-white text-[12px] font-semibold">
                  <AnimatedNumber value={item.percentage} decimals={1} suffix="%" />
                </span>
                <span className="text-[#7d77a8] text-[11px] tabular-nums">
                  <AnimatedNumber value={item.count} />
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </PixelCard>
  );
};
