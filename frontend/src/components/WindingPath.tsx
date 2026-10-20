import React from "react";

export interface PathStop {
  id: number;
  label: string;
  description: string;
  category: "proposal" | "security" | "execution" | "audit";
}

interface WindingPathProps {
  stops: PathStop[];
  activeStopIndex?: number;
  onSelectStop?: (stop: PathStop) => void;
}

export const WindingPath: React.FC<WindingPathProps> = ({
  stops,
  activeStopIndex = 0,
  onSelectStop,
}) => {
  // SVG coordinates for a balanced winding 7-stop pipeline path (e.g. S-curve / zig-zag)
  // Stops: (1) Propose -> (2) Validate -> (3) Risk -> (4) Policy -> (5) Decision -> (6) Execute -> (7) Audit
  const coordinates = [
    { x: 60, y: 70 },
    { x: 190, y: 50 },
    { x: 310, y: 90 },
    { x: 440, y: 55 },
    { x: 570, y: 95 },
    { x: 690, y: 60 },
    { x: 800, y: 85 },
  ];

  // SVG curved path connecting all coordinates smoothly
  const pathD = coordinates.reduce((acc, point, index) => {
    if (index === 0) return `M ${point.x} ${point.y}`;
    const prev = coordinates[index - 1];
    const midX = (prev.x + point.x) / 2;
    return `${acc} C ${midX} ${prev.y}, ${midX} ${point.y}, ${point.x} ${point.y}`;
  }, "");

  return (
    <div className="w-full overflow-x-auto py-4">
      <div className="min-w-[860px] px-4">
        <svg
          viewBox="0 0 860 160"
          className="w-full h-auto drop-shadow-[0_10px_20px_rgba(0,0,0,0.5)]"
        >
          <defs>
            <linearGradient id="pathGradient" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#38bdf8" />
              <stop offset="35%" stopColor="#818cf8" />
              <stop offset="65%" stopColor="#c084fc" />
              <stop offset="100%" stopColor="#34d399" />
            </linearGradient>
            <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
              <feGaussianBlur stdDeviation="3" result="blur" />
              <feComposite in="SourceGraphic" in2="blur" operator="over" />
            </filter>
          </defs>

          {/* Background glowing path line */}
          <path
            d={pathD}
            fill="none"
            stroke="url(#pathGradient)"
            strokeWidth="8"
            strokeLinecap="round"
            strokeOpacity="0.25"
          />

          {/* Main animated connecting dashed path */}
          <path
            d={pathD}
            fill="none"
            stroke="url(#pathGradient)"
            strokeWidth="3.5"
            strokeLinecap="round"
            strokeDasharray="6 4"
            className="transition-all duration-500"
          />

          {/* Render 7 stops */}
          {stops.map((stop, idx) => {
            const pos = coordinates[idx] || { x: 50 + idx * 110, y: 70 };
            const isActive = idx === activeStopIndex;
            const isPassed = idx < activeStopIndex;

            return (
              <g
                key={stop.id}
                className="cursor-pointer group"
                onClick={() => onSelectStop && onSelectStop(stop)}
              >
                {/* Active pulse aura */}
                {isActive && (
                  <circle
                    cx={pos.x}
                    cy={pos.y}
                    r="24"
                    fill="#38bdf8"
                    fillOpacity="0.15"
                    className="animate-ping"
                  />
                )}

                {/* Base circle background */}
                <circle
                  cx={pos.x}
                  cy={pos.y}
                  r="18"
                  fill="#0f172a"
                  stroke={
                    isActive
                      ? "#38bdf8"
                      : isPassed
                      ? "#818cf8"
                      : "#334155"
                  }
                  strokeWidth={isActive ? "3" : "2"}
                  filter={isActive ? "url(#glow)" : undefined}
                  className="transition-all duration-300 group-hover:stroke-sky-400"
                />

                {/* Stop number */}
                <text
                  x={pos.x}
                  y={pos.y + 5}
                  textAnchor="middle"
                  fill={isActive ? "#38bdf8" : "#94a3b8"}
                  fontSize="13"
                  fontWeight="bold"
                  fontFamily="monospace"
                >
                  {stop.id}
                </text>

                {/* Label text under or above the point */}
                <text
                  x={pos.x}
                  y={pos.y + (pos.y > 70 ? 32 : -26)}
                  textAnchor="middle"
                  fill={isActive ? "#f8fafc" : "#cbd5e1"}
                  fontSize="12"
                  fontWeight="600"
                  className="transition-colors group-hover:fill-sky-300"
                >
                  {stop.label}
                </text>

                {/* Subtitle brief */}
                <text
                  x={pos.x}
                  y={pos.y + (pos.y > 70 ? 44 : -14)}
                  textAnchor="middle"
                  fill="#64748b"
                  fontSize="9.5"
                  fontFamily="sans-serif"
                >
                  {stop.description}
                </text>
              </g>
            );
          })}
        </svg>
      </div>
    </div>
  );
};
