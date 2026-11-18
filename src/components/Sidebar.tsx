import React, { useState, useEffect } from 'react';
import {
  PixelShieldIcon,
  PixelHouseIcon,
  PixelLayersIcon,
  PixelClipboardCheckIcon,
  PixelSlidersIcon,
  PixelBarChartIcon,
} from './pixel/PixelIcons';
import { PixelKnightIllustration } from './pixel/PixelKnightIllustration';
import { AnimatedNumber } from './pixel/AnimatedNumber';
import { ChevronDown, Check, ChevronLeft, ChevronRight } from 'lucide-react';
import { computeReviewBadge, formatVersion } from '../health';

interface SidebarProps {
  currentTab: string;
  onSelectTab: (tab: string) => void;
  isCollapsed?: boolean;
  onToggleCollapse?: () => void;
  isOpenMobile?: boolean;
  onCloseMobile?: () => void;
  pendingReviewsCount?: number;
  environment?: string;
  version?: string;
  isReadOnly?: boolean;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentTab,
  onSelectTab,
  isCollapsed = false,
  onToggleCollapse,
  isOpenMobile = false,
  onCloseMobile,
  pendingReviewsCount,
  environment = 'Staging',
  version = '0.2.0',
  isReadOnly = false,
}) => {
  const [envOpen, setEnvOpen] = useState(false);
  const [selectedEnv, setSelectedEnv] = useState<string>(environment);

  useEffect(() => {
    if (environment) {
      setSelectedEnv(environment);
    }
  }, [environment]);

  const navItems = [
    { id: 'Overview', label: 'Overview', icon: PixelHouseIcon },
    { id: 'Events', label: 'Events', icon: PixelLayersIcon },
    {
      id: 'Review',
      label: 'Review',
      icon: PixelClipboardCheckIcon,
      badge: computeReviewBadge(pendingReviewsCount),
    },
    { id: 'Policies', label: 'Policies & Agents', icon: PixelSlidersIcon },
    { id: 'Benchmarks', label: 'Benchmarks', icon: PixelBarChartIcon },
  ];

  const environments = ['Staging', 'Development', 'Production'] as const;
  const { displayVersion, shortVersion } = formatVersion(version);

  return (
    <>
      {/* Mobile Backdrop */}
      {isOpenMobile && (
        <div
          className="fixed inset-0 z-40 bg-black/60 backdrop-blur-sm lg:hidden"
          onClick={onCloseMobile}
        />
      )}

      <aside
        className={`fixed top-0 bottom-0 left-0 z-50 flex flex-col bg-[#121124] border-r border-[#2e285a] transition-all duration-300 ease-in-out ${
          isCollapsed ? 'w-[72px]' : 'w-[272px]'
        } ${isOpenMobile ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'}`}
      >
        {/* BRANDING SECTION */}
        <div className={`flex items-center ${isCollapsed ? 'justify-center flex-col gap-2' : 'justify-between'} px-4 py-4 border-b border-[#221e42]`}>
          <div className="flex items-center gap-3 overflow-hidden">
            <div className="flex-shrink-0 drop-shadow-[0_0_8px_rgba(112,62,232,0.4)]">
              <PixelShieldIcon size={isCollapsed ? 32 : 34} />
            </div>
            {!isCollapsed && (
              <div className="flex flex-col whitespace-nowrap overflow-hidden">
                <span className="text-[17px] font-bold tracking-tight text-white flex items-center gap-1">
                  AgentShield
                </span>
                <span className="text-[11px] font-medium text-[#938ec0] tracking-wide">
                  AI Agent Runtime Security
                </span>
              </div>
            )}
          </div>

          {/* Desktop Collapse / Expand Toggle Button */}
          {onToggleCollapse && (
            <button
              onClick={onToggleCollapse}
              title={isCollapsed ? "Expand sidebar" : "Collapse sidebar"}
              className="hidden lg:flex items-center justify-center w-7 h-7 text-[#8780b8] hover:text-white hover:bg-[#1f1b3d] rounded-lg transition-colors flex-shrink-0"
            >
              {isCollapsed ? <ChevronRight size={17} /> : <ChevronLeft size={17} />}
            </button>
          )}
        </div>

        {/* NAVIGATION ITEMS */}
        <nav className={`flex flex-col gap-1.5 ${isCollapsed ? 'px-2' : 'px-3'} py-4`}>
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = currentTab === item.id;

            return (
              <div key={item.id} className="relative group">
                <button
                  onClick={() => {
                    onSelectTab(item.id);
                    if (onCloseMobile) onCloseMobile();
                  }}
                  className={`flex items-center ${
                    isCollapsed ? 'justify-center w-full h-11' : 'justify-between w-full px-3.5 py-2.5'
                  } rounded-xl font-medium text-[13.5px] transition-all duration-150 ${
                    isActive
                      ? 'bg-[#6d3ee8] text-white shadow-[0_2px_12px_rgba(109,62,232,0.45)]'
                      : 'text-[#9c96c9] hover:text-white hover:bg-[#1d1a3a]'
                  }`}
                >
                  <div className="flex items-center gap-3">
                    <span
                      className={`flex items-center justify-center transition-colors ${
                        isActive ? 'text-white' : 'text-[#8780b8] group-hover:text-white'
                      }`}
                    >
                      <Icon size={18} />
                    </span>
                    {!isCollapsed && <span>{item.label}</span>}
                  </div>

                  {!isCollapsed && item.badge !== undefined && (
                    <span
                      className={`px-2 py-0.5 text-[11px] font-bold rounded-md ${
                        isActive
                          ? 'bg-[#5527ca] text-white'
                          : 'bg-[#6d3ee8] text-white shadow-[0_1px_4px_rgba(109,62,232,0.4)]'
                      }`}
                    >
                      <AnimatedNumber value={item.badge} />
                    </span>
                  )}

                  {isCollapsed && item.badge !== undefined && (
                    <span className="absolute top-1.5 right-1.5 w-2 h-2 rounded-full bg-[#6d3ee8] ring-2 ring-[#121124]" />
                  )}
                </button>

                {/* Collapsed Tooltip on Hover */}
                {isCollapsed && (
                  <div className="fixed left-[76px] z-50 px-2.5 py-1.5 bg-[#181636] border border-[#3e3678] rounded-lg shadow-xl text-xs font-semibold text-white whitespace-nowrap pointer-events-none opacity-0 group-hover:opacity-100 transition-opacity">
                    {item.label} {item.badge ? `(${item.badge})` : ''}
                  </div>
                )}
              </div>
            );
          })}
        </nav>

        {/* SPACER */}
        <div className="flex-1 min-h-[10px]" />

        {/* PIXEL-ART KNIGHT ILLUSTRATION */}
        {!isCollapsed && (
          <div className="relative w-full overflow-hidden mt-auto transition-opacity duration-200">
            <PixelKnightIllustration />
          </div>
        )}

        {/* FOOTER SECTION: ENVIRONMENT SELECTOR & VERSION */}
        <div className={`${isCollapsed ? 'px-2 py-3' : 'px-4 pt-1 pb-4'}`}>
          {!isCollapsed ? (
            <div className="relative">
              <button
                onClick={() => setEnvOpen(!envOpen)}
                className="flex items-center justify-between w-full px-3 py-2 bg-[#1b1935] border border-[#342d63] rounded-xl hover:bg-[#232044] transition-colors text-[13px] text-white font-medium shadow-sm"
              >
                <div className="flex items-center gap-2">
                  <span className="relative flex h-2.5 w-2.5">
                    <span className={`animate-ping absolute inline-flex h-full w-full rounded-full ${isReadOnly ? 'bg-amber-400' : 'bg-emerald-400'} opacity-75`}></span>
                    <span className={`relative inline-flex rounded-full h-2.5 w-2.5 ${isReadOnly ? 'bg-amber-500' : 'bg-[#22c55e]'}`}></span>
                  </span>
                  <span>{selectedEnv} {isReadOnly ? '(RO)' : ''}</span>
                </div>
                <ChevronDown
                  size={15}
                  className={`text-[#9892c5] transition-transform duration-200 ${
                    envOpen ? 'rotate-180' : ''
                  }`}
                />
              </button>

              {/* Dropdown Menu */}
              {envOpen && (
                <div className="absolute bottom-full left-0 right-0 mb-2 p-1 bg-[#191733] border border-[#3c3475] rounded-xl shadow-xl z-50">
                  {environments.map((env) => (
                    <button
                      key={env}
                      onClick={() => {
                        setSelectedEnv(env);
                        setEnvOpen(false);
                      }}
                      className={`flex items-center justify-between w-full px-3 py-1.5 rounded-lg text-xs font-medium text-left transition-colors ${
                        selectedEnv === env
                          ? 'bg-[#6d3ee8] text-white'
                          : 'text-[#a9a3d4] hover:bg-[#232047] hover:text-white'
                      }`}
                    >
                      <span>{env}</span>
                      {selectedEnv === env && <Check size={13} />}
                    </button>
                  ))}
                </div>
              )}

              <div className="mt-3 px-1 text-[11px] font-mono font-medium text-[#645e8a]">
                {displayVersion}
              </div>
            </div>
          ) : (
            <div className="flex flex-col items-center gap-3">
              <span className="relative flex h-3 w-3" title={`Environment: ${selectedEnv}`}>
                <span className={`animate-ping absolute inline-flex h-full w-full rounded-full ${isReadOnly ? 'bg-amber-400' : 'bg-emerald-400'} opacity-75`}></span>
                <span className={`relative inline-flex rounded-full h-3 w-3 ${isReadOnly ? 'bg-amber-500' : 'bg-[#22c55e]'}`}></span>
              </span>
              <span className="text-[10px] font-mono font-medium text-[#645e8a]">{shortVersion}</span>
            </div>
          )}
        </div>
      </aside>
    </>
  );
};
