import React from 'react';
import { PixelSlidersIcon, PixelInfoIcon } from './pixel/PixelIcons';
import { PixelCard } from './pixel/PixelCard';
import { AnimatedNumber } from './pixel/AnimatedNumber';

export interface RiskTierCounts {
  critical?: number;
  high?: number;
  medium?: number;
  low?: number;
}

interface RiskOverviewProps {
  counts?: RiskTierCounts | null;
}

export const RiskOverview: React.FC<RiskOverviewProps> = ({ counts }) => {
  const critical = counts?.critical ?? 0;
  const high = counts?.high ?? 0;
  const medium = counts?.medium ?? 0;
  const low = counts?.low ?? 0;
  const total = critical + high + medium + low;

  const tiers = [
    {
      name: 'Critical',
      range: '(81–100)',
      percentage: total > 0 ? Number(((critical / total) * 100).toFixed(1)) : 0,
      count: critical,
      color: '#ef4444',
    },
    {
      name: 'High',
      range: '(61–80)',
      percentage: total > 0 ? Number(((high / total) * 100).toFixed(1)) : 0,
      count: high,
      color: '#f97316',
    },
    {
      name: 'Medium',
      range: '(31–60)',
      percentage: total > 0 ? Number(((medium / total) * 100).toFixed(1)) : 0,
      count: medium,
      color: '#eab308',
    },
    {
      name: 'Low',
      range: '(0–30)',
      percentage: total > 0 ? Number(((low / total) * 100).toFixed(1)) : 0,
      count: low,
      color: '#22c55e',
    },
  ];

  return (
    <PixelCard className="h-full flex-1" innerClassName="p-3.5 justify-between h-full">
      {/* Header */}
      <div className="flex items-center gap-1.5 pb-2 border-b border-[#25204c]">
        <div className="flex items-center justify-center text-[#c084fc]">
          <PixelSlidersIcon size={16} />
        </div>
        <h3 className="text-[13.5px] font-bold text-white tracking-tight">
          Risk Overview
        </h3>
        <button
          title="Distribution of actions scored by runtime anomaly risk engine"
          className="text-[#7d77a8] hover:text-[#c4bbf0] transition-colors ml-0.5"
        >
          <PixelInfoIcon size={13} />
        </button>
      </div>

      {/* Rows - tightly spaced, balanced columns */}
      <div className="flex flex-col justify-between gap-2 my-auto py-1.5">
        {tiers.map((tier, index) => (
          <div
            key={tier.name}
            className="py-1 px-1.5 rounded-md hover:bg-[#201d44] transition-colors"
          >
            <div className="flex items-center justify-between text-xs font-medium">
              {/* Color indicator + Name + Range */}
              <div className="flex items-center gap-2">
                <span
                  className="w-2.5 h-2.5 rounded-xs flex-shrink-0"
                  style={{ backgroundColor: tier.color }}
                />
                <span className="text-white font-semibold text-[13px]">
                  {tier.name}
                </span>
                <span className="text-[#847ea8] text-[12px]">
                  {tier.range}
                </span>
              </div>

              {/* Percentage & Count */}
              <div className="flex items-center gap-4">
                <span className="text-white text-[12.5px] font-semibold tabular-nums min-w-[42px] text-right">
                  <AnimatedNumber value={tier.percentage} decimals={1} suffix="%" />
                </span>
                <span className="text-[#847ea8] text-[12px] tabular-nums min-w-[38px] text-right">
                  <AnimatedNumber value={tier.count} />
                </span>
              </div>
            </div>

            {/* Animated distribution bar */}
            <div className="mt-1.5 h-1 rounded-sm bg-[#211d47] overflow-hidden">
              <div
                className="h-full rounded-sm bar-grow"
                style={{
                  width: `${tier.percentage}%`,
                  backgroundColor: tier.color,
                  animationDelay: `${index * 90}ms`,
                }}
              />
            </div>
          </div>
        ))}
      </div>
    </PixelCard>
  );
};
