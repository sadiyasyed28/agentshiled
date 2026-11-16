import React from 'react';
import {
  PixelWarningTriangleIcon,
  PixelClockCircleIcon,
  PixelPauseBarsIcon,
  PixelCrossShieldIcon,
  PixelSlidersIcon,
  PixelCheckCircleIcon,
} from './pixel/PixelIcons';
import { PixelCard } from './pixel/PixelCard';
import { AnimatedNumber } from './pixel/AnimatedNumber';
import { ChevronRight } from 'lucide-react';
import type { AttentionItem } from '../types';

interface AttentionRequiredProps {
  onSelectItem: (item: AttentionItem) => void;
  pendingReviewsCount?: number;
  pausedAgents?: string[];
  highRiskCount?: number;
}

export const AttentionRequired: React.FC<AttentionRequiredProps> = ({
  onSelectItem,
  pendingReviewsCount = 0,
  pausedAgents = [],
  highRiskCount = 0,
}) => {
  const items: AttentionItem[] = [];

  if (pendingReviewsCount > 0) {
    items.push({
      id: 'review-actions',
      iconType: 'review',
      text: `${pendingReviewsCount} action${pendingReviewsCount === 1 ? '' : 's'} awaiting review`,
      count: pendingReviewsCount,
      severity: 'yellow',
      details: 'Human supervisor sign-off required for held tool execution proposals.',
    });
  }

  if (pausedAgents.length > 0) {
    items.push({
      id: 'paused-agent',
      iconType: 'paused',
      text: `${pausedAgents.length} agent${pausedAgents.length === 1 ? ' is' : 's are'} paused`,
      count: pausedAgents.length,
      severity: 'orange',
      details: `Containment policy active for: ${pausedAgents.join(', ')}.`,
    });
  }

  if (highRiskCount > 0) {
    items.push({
      id: 'high-risk',
      iconType: 'risk',
      text: `${highRiskCount} high-risk action${highRiskCount === 1 ? '' : 's'} (≥ 61)`,
      count: highRiskCount,
      severity: 'red',
      details: `${highRiskCount} action${highRiskCount === 1 ? '' : 's'} evaluated with elevated risk scores.`,
    });
  }

  const getIcon = (type: AttentionItem['iconType']) => {
    switch (type) {
      case 'review':
        return <PixelClockCircleIcon size={15} />;
      case 'paused':
        return <PixelPauseBarsIcon size={14} />;
      case 'risk':
        return <PixelCrossShieldIcon size={15} />;
      case 'policy':
        return <PixelSlidersIcon size={15} />;
    }
  };

  const renderAnimatedText = (text: string) => {
    const match = text.match(/(\d[\d,]*)/);
    if (!match || match.index === undefined) return text;

    const numericValue = parseInt(match[0].replace(/,/g, ''), 10);
    const before = text.slice(0, match.index);
    const after = text.slice(match.index + match[0].length);

    return (
      <>
        {before}
        <AnimatedNumber value={numericValue} />
        {after}
      </>
    );
  };

  return (
    <PixelCard className="h-full flex-1" innerClassName="p-3.5 justify-between h-full">
      {/* Header */}
      <div className="flex items-center justify-between pb-2 border-b border-[#25204c]">
        <div className="flex items-center gap-1.5">
          <div className="flex items-center justify-center text-yellow-400">
            <PixelWarningTriangleIcon size={16} />
          </div>
          <h3 className="text-[13.5px] font-bold text-white tracking-tight">
            Attention Required
          </h3>
        </div>

        {/* Badge */}
        <span
          className={`px-1.5 py-0.5 text-[10.5px] font-bold rounded-md ${
            items.length > 0
              ? 'bg-[#6d3ee8] text-white shadow-[0_1px_4px_rgba(109,62,232,0.4)]'
              : 'bg-[#153e28] text-[#4ade80] border border-[#226742]'
          }`}
        >
          <AnimatedNumber value={items.length} />
        </span>
      </div>

      {/* Rows or Clean Empty State */}
      <div className="flex flex-col justify-between gap-1.5 my-auto py-1">
        {items.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-6 text-center">
            <div className="w-8 h-8 rounded-full bg-[#153e28] text-[#4ade80] flex items-center justify-center mb-2 shadow-xs">
              <PixelCheckCircleIcon size={18} />
            </div>
            <span className="text-[13px] font-semibold text-white">All Systems Normal</span>
            <span className="text-[11px] text-[#847ea8] mt-1 max-w-[220px]">
              No active reviews pending and no contained agents.
            </span>
          </div>
        ) : (
          items.map((item) => (
          <button
            key={item.id}
            onClick={() => onSelectItem(item)}
            className="flex items-center justify-between w-full py-2 px-2 rounded-lg text-left hover:bg-[#201d44] transition-colors group"
          >
            <div className="flex items-center gap-2.5">
              <div className="flex-shrink-0 flex items-center justify-center">
                {getIcon(item.iconType)}
              </div>
              <span className="text-white text-[12.5px] font-medium group-hover:text-[#c4bbf0] transition-colors">
                {renderAnimatedText(item.text)}
              </span>
            </div>

            <ChevronRight
              size={14}
              className="text-[#7d77a8] group-hover:text-white group-hover:translate-x-0.5 transition-all"
            />
          </button>
        ))
      )}
      </div>
    </PixelCard>
  );
};
