import React, { useState } from 'react';
import { PixelLightningIcon, PixelInfoIcon } from './pixel/PixelIcons';
import { PixelCard } from './pixel/PixelCard';
import { ChevronDown, Check } from 'lucide-react';

export interface DayData {
  day: string;
  allowed: number;
  review: number;
  blocked: number;
}

interface SecurityActivityChartProps {
  activityData?: DayData[] | null;
}

export const SecurityActivityChart: React.FC<SecurityActivityChartProps> = ({ activityData }) => {
  const [granularity, setGranularity] = useState('Events (Daily)');
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const [hoveredPoint, setHoveredPoint] = useState<DayData | null>(null);

  const defaultData: DayData[] = [
    { day: 'Tue', allowed: 380, review: 85, blocked: 42 },
    { day: 'Wed', allowed: 460, review: 95, blocked: 48 },
    { day: 'Thu', allowed: 390, review: 88, blocked: 40 },
    { day: 'Fri', allowed: 480, review: 105, blocked: 52 },
    { day: 'Sat', allowed: 540, review: 95, blocked: 45 },
    { day: 'Sun', allowed: 570, review: 88, blocked: 40 },
    { day: 'Mon', allowed: 720, review: 125, blocked: 62 },
  ];

  const data = activityData && activityData.length >= 2 ? activityData : defaultData;

  const chartHeight = 135;
  const chartWidth = 460;
  const paddingLeft = 34;
  const paddingRight = 14;
  const paddingTop = 12;
  const paddingBottom = 20;

  const innerWidth = chartWidth - paddingLeft - paddingRight;
  const innerHeight = chartHeight - paddingTop - paddingBottom;
  
  const maxVal = Math.max(
    ...data.map((d) => Math.max(d.allowed, d.review, d.blocked)),
    100
  );
  const maxY = Math.ceil((maxVal * 1.15) / 100) * 100;

  const getY = (val: number) => paddingTop + innerHeight - (val / maxY) * innerHeight;
  const getX = (index: number) => paddingLeft + (index / (data.length - 1)) * innerWidth;

  const buildPath = (key: 'allowed' | 'review' | 'blocked') => {
    return data.map((d, i) => `${i === 0 ? 'M' : 'L'} ${getX(i)} ${getY(d[key])}`).join(' ');
  };

  const allowedPath = buildPath('allowed');
  const reviewPath = buildPath('review');
  const blockedPath = buildPath('blocked');
  const allowedArea = `${allowedPath} L ${getX(data.length - 1)} ${getY(0)} L ${getX(0)} ${getY(0)} Z`;

  return (
    <PixelCard innerClassName="p-3.5 justify-between h-full">
      {/* Top Header */}
      <div className="flex items-center justify-between pb-2 border-b border-[#25204c]">
        <div className="flex items-center gap-1.5">
          <div className="flex items-center justify-center text-yellow-400">
            <PixelLightningIcon size={16} />
          </div>
          <h3 className="text-[13.5px] font-bold text-white tracking-tight">
            Security Activity
          </h3>
          <button
            title="Monitored authorization and policy enforcement volume trends over the past 7 days"
            className="text-[#7d77a8] hover:text-[#c4bbf0] transition-colors ml-0.5"
          >
            <PixelInfoIcon size={13} />
          </button>
        </div>

        {/* View/Granularity Dropdown */}
        <div className="relative">
          <button
            onClick={() => setDropdownOpen(!dropdownOpen)}
            className="flex items-center gap-1.5 px-2.5 py-1 bg-[#1b1838] border border-[#342d63] rounded-lg text-[11.5px] font-semibold text-[#8b84bd] hover:border-[#52479e] hover:text-white transition-colors"
          >
            <span>{granularity}</span>
            <ChevronDown size={12} className={`transition-transform ${dropdownOpen ? 'rotate-180' : ''}`} />
          </button>

          {dropdownOpen && (
            <div className="absolute right-0 mt-1 w-36 p-1 bg-[#191733] border border-[#3e3678] rounded-xl shadow-xl z-50">
              {['Events (Daily)', 'Enforcements', 'Rate Limits'].map((option) => (
                <button
                  key={option}
                  onClick={() => {
                    setGranularity(option);
                    setDropdownOpen(false);
                  }}
                  className={`flex items-center justify-between w-full px-2.5 py-1 rounded-md text-[11px] font-medium transition-colors ${
                    granularity === option
                      ? 'bg-[#6d3ee8] text-white'
                      : 'text-[#aaa4d4] hover:bg-[#25204c] hover:text-white'
                  }`}
                >
                  <span>{option}</span>
                  {granularity === option && <Check size={12} />}
                </button>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* SVG Chart Area */}
      <div className="relative w-full my-auto py-1">
        <svg
          viewBox={`0 0 ${chartWidth} ${chartHeight}`}
          className="w-full h-[135px] overflow-visible"
        >
          <defs>
            {/* Soft green gradient fill for the allowed area under curve */}
            <linearGradient id="allowedGradient" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#22c55e" stopOpacity="0.22" />
              <stop offset="100%" stopColor="#22c55e" stopOpacity="0.0" />
            </linearGradient>
          </defs>

          {/* Horizontal gridlines and Y-axis labels */}
          {[0, 200, 400, 600, 800].map((val) => {
            const y = getY(val);
            return (
              <g key={val}>
                <line
                  x1={paddingLeft}
                  y1={y}
                  x2={chartWidth - paddingRight}
                  y2={y}
                  stroke="#1f1b3f"
                  strokeWidth="1"
                  strokeDasharray="2 3"
                />
                <text
                  x={paddingLeft - 6}
                  y={y + 3}
                  textAnchor="end"
                  fill="#5f5885"
                  fontSize="9.5"
                  fontFamily="monospace"
                >
                  {val}
                </text>
              </g>
            );
          })}

          {/* Area fill under Allowed line */}
          <path d={allowedArea} fill="url(#allowedGradient)" />

          {/* Lines */}
          <path
            d={allowedPath}
            fill="none"
            stroke="#22c55e"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
          <path
            d={reviewPath}
            fill="none"
            stroke="#eab308"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
          <path
            d={blockedPath}
            fill="none"
            stroke="#ef4444"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          />

          {/* Data Points (interactive circles) */}
          {data.map((d, i) => {
            const x = getX(i);
            const yAllowed = getY(d.allowed);
            const yReview = getY(d.review);
            const yBlocked = getY(d.blocked);

            return (
              <g key={d.day}>
                {/* Vertical hover line anchor */}
                <line
                  x1={x}
                  y1={paddingTop}
                  x2={x}
                  y2={paddingTop + innerHeight}
                  stroke={hoveredPoint?.day === d.day ? '#443b78' : 'transparent'}
                  strokeWidth="1"
                  strokeDasharray="2 2"
                />

                {/* Circles for each metric */}
                <circle
                  cx={x}
                  cy={yAllowed}
                  r={hoveredPoint?.day === d.day ? 4 : 2.5}
                  fill="#22c55e"
                  stroke="#16132f"
                  strokeWidth="1.5"
                />
                <circle
                  cx={x}
                  cy={yReview}
                  r={hoveredPoint?.day === d.day ? 4 : 2.5}
                  fill="#eab308"
                  stroke="#16132f"
                  strokeWidth="1.5"
                />
                <circle
                  cx={x}
                  cy={yBlocked}
                  r={hoveredPoint?.day === d.day ? 4 : 2.5}
                  fill="#ef4444"
                  stroke="#16132f"
                  strokeWidth="1.5"
                />

                {/* Transparent hover capture rect */}
                <rect
                  x={x - innerWidth / (data.length * 2)}
                  y={paddingTop}
                  width={innerWidth / data.length}
                  height={innerHeight}
                  fill="transparent"
                  className="cursor-pointer"
                  onMouseEnter={() => setHoveredPoint(d)}
                  onMouseLeave={() => setHoveredPoint(null)}
                />

                {/* Day label on X axis */}
                <text
                  x={x}
                  y={chartHeight - 4}
                  textAnchor="middle"
                  fill={hoveredPoint?.day === d.day ? '#ffffff' : '#736b9e'}
                  fontSize="10"
                  fontWeight={hoveredPoint?.day === d.day ? 'bold' : 'normal'}
                >
                  {d.day}
                </text>
              </g>
            );
          })}
        </svg>

        {/* Hover Tooltip card positioned floating above cursor */}
        {hoveredPoint && (
          <div className="absolute top-2 right-4 px-2.5 py-1.5 bg-[#171530] border border-[#3d3570] rounded-lg shadow-xl text-[10.5px] flex items-center gap-3 pointer-events-none z-20">
            <span className="font-bold text-white font-mono">{hoveredPoint.day}</span>
            <span className="text-[#4ade80] font-semibold flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-[#4ade80]" />
              {hoveredPoint.allowed}
            </span>
            <span className="text-[#facc15] font-semibold flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-[#facc15]" />
              {hoveredPoint.review}
            </span>
            <span className="text-[#f87171] font-semibold flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-[#f87171]" />
              {hoveredPoint.blocked}
            </span>
          </div>
        )}
      </div>

      {/* Footer Legend */}
      <div className="flex items-center justify-end gap-3.5 pt-2 border-t border-[#25204c] text-[11px] font-medium text-[#8b84bd]">
        <div className="flex items-center gap-1.5">
          <span className="w-2 h-2 rounded-xs bg-[#22c55e]" />
          <span>Allowed</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-2 h-2 rounded-xs bg-[#eab308]" />
          <span>Review</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-2 h-2 rounded-xs bg-[#ef4444]" />
          <span>Blocked</span>
        </div>
      </div>
    </PixelCard>
  );
};
