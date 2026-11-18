import React, { useState, useEffect, useMemo } from 'react';
import { Search, X, ArrowRight, Activity, RefreshCw, LogIn, LogOut, Shield } from 'lucide-react';
import {
  PixelRobotIcon,
  PixelCrossShieldIcon,
  PixelSlidersIcon,
  PixelHouseIcon,
  PixelLayersIcon,
  PixelClipboardCheckIcon,
  PixelBarChartIcon,
} from './pixel/PixelIcons';
import type { Agent, SecurityEvent } from '../types';
import type { ApiSessionResponse } from '../api/client';

export interface CommandPaletteProps {
  isOpen: boolean;
  onClose: () => void;
  onNavigateTab: (tab: string) => void;
  onOpenHealth: () => void;
  onRefresh: () => void;
  onOpenLogin: () => void;
  onLogout: () => void;
  onOpenSecuritySettings?: () => void;
  session?: ApiSessionResponse | null;
  agents?: Agent[] | null;
  events?: SecurityEvent[] | null;
  onSelectAgent?: (agent: Agent) => void;
  onSelectEvent?: (event: SecurityEvent) => void;
}

interface CommandItem {
  id: string;
  title: string;
  subtitle: string;
  category: 'Navigation' | 'Actions' | 'Agents' | 'Events';
  icon: React.ComponentType<{ size?: number; className?: string }>;
  onExecute: () => void;
}

export const CommandPalette: React.FC<CommandPaletteProps> = ({
  isOpen,
  onClose,
  onNavigateTab,
  onOpenHealth,
  onRefresh,
  onOpenLogin,
  onLogout,
  onOpenSecuritySettings,
  session,
  agents = [],
  events = [],
  onSelectAgent,
  onSelectEvent,
}) => {
  const [query, setQuery] = useState('');

  // Handle ESC key
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isOpen) {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  // Build authentic application commands and live resources
  const commands = useMemo(() => {
    const list: CommandItem[] = [
      // 1. Navigation commands
      {
        id: 'nav-overview',
        title: 'Go to Overview',
        subtitle: 'Main operational security overview & real-time telemetry',
        category: 'Navigation',
        icon: PixelHouseIcon,
        onExecute: () => onNavigateTab('Overview'),
      },
      {
        id: 'nav-events',
        title: 'Go to Events',
        subtitle: 'Inspect full runtime audit logs, risk scores & tool calls',
        category: 'Navigation',
        icon: PixelLayersIcon,
        onExecute: () => onNavigateTab('Events'),
      },
      {
        id: 'nav-review',
        title: 'Go to Review Queue',
        subtitle: 'Examine proposals requiring human supervisor authorization',
        category: 'Navigation',
        icon: PixelClipboardCheckIcon,
        onExecute: () => onNavigateTab('Review'),
      },
      {
        id: 'nav-policies',
        title: 'Go to Policies & Agents',
        subtitle: 'Manage active security policies & containment toggles',
        category: 'Navigation',
        icon: PixelSlidersIcon,
        onExecute: () => onNavigateTab('Policies'),
      },
      {
        id: 'nav-benchmarks',
        title: 'Go to Benchmarks',
        subtitle: 'Run automated policy benchmarks & adversary simulations',
        category: 'Navigation',
        icon: PixelBarChartIcon,
        onExecute: () => onNavigateTab('Benchmarks'),
      },

      // 2. Operational Actions
      {
        id: 'act-health',
        title: 'System Health Diagnostics',
        subtitle: 'Inspect database connectivity, storage, and telemetry spool status',
        category: 'Actions',
        icon: Activity,
        onExecute: () => onOpenHealth(),
      },
      {
        id: 'act-refresh',
        title: 'Refresh Dashboard Data',
        subtitle: 'Synchronize events, agents, and metrics from live runtime',
        category: 'Actions',
        icon: RefreshCw,
        onExecute: () => onRefresh(),
      },
      {
        id: 'act-security-settings',
        title: 'Open Security Settings',
        subtitle: 'Manage API keys, inspect runtime configuration and engine limits',
        category: 'Actions',
        icon: Shield,
        onExecute: () => onOpenSecuritySettings?.(),
      },
    ];

    if (!session?.authenticated) {
      list.push({
        id: 'act-login',
        title: 'Sign In as Administrator',
        subtitle: 'Authenticate session with admin secret key for policy edits',
        category: 'Actions',
        icon: LogIn,
        onExecute: () => onOpenLogin(),
      });
    } else {
      list.push({
        id: 'act-logout',
        title: 'Sign Out Administrator',
        subtitle: `Terminate active session for ${session.role || 'administrator'}`,
        category: 'Actions',
        icon: LogOut,
        onExecute: () => onLogout(),
      });
    }

    // 3. Discovered Live Agents
    if (agents && agents.length > 0) {
      agents.forEach((ag) => {
        list.push({
          id: `agent-${ag.id}`,
          title: `Agent: ${ag.name}`,
          subtitle: `Status: ${ag.status} • Policy: ${ag.policy || 'Enforced'} • ${ag.events7d} events`,
          category: 'Agents',
          icon: PixelRobotIcon,
          onExecute: () => {
            if (onSelectAgent) {
              onSelectAgent(ag);
            } else {
              onNavigateTab('Policies');
            }
          },
        });
      });
    }

    // 4. Live Monitored Security Events
    if (events && events.length > 0) {
      events.slice(0, 6).forEach((evt) => {
        list.push({
          id: `event-${evt.id}`,
          title: `Event: ${evt.agent} · ${evt.action}`,
          subtitle: `${evt.decision} • Risk ${evt.riskScore} • ${evt.timestamp}`,
          category: 'Events',
          icon: PixelCrossShieldIcon,
          onExecute: () => {
            if (onSelectEvent) {
              onSelectEvent(evt);
            } else {
              onNavigateTab('Events');
            }
          },
        });
      });
    }

    return list;
  }, [
    session,
    agents,
    events,
    onNavigateTab,
    onOpenHealth,
    onRefresh,
    onOpenLogin,
    onLogout,
    onOpenSecuritySettings,
    onSelectAgent,
    onSelectEvent,
  ]);

  if (!isOpen) return null;

  const filtered = commands.filter(
    (c) =>
      c.title.toLowerCase().includes(query.toLowerCase()) ||
      c.subtitle.toLowerCase().includes(query.toLowerCase()) ||
      c.category.toLowerCase().includes(query.toLowerCase())
  );

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center pt-20 px-4 bg-black/70 backdrop-blur-sm animate-in fade-in duration-150">
      <div
        className="relative w-full max-w-xl bg-[#171533] border border-[#3e3678] rounded-2xl shadow-2xl overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Search Input Bar */}
        <div className="flex items-center px-4 py-3.5 border-b border-[#2a2456] gap-3">
          <Search size={18} className="text-[#8c85bd]" />
          <input
            type="text"
            placeholder="Type an action or search live agents and events..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            autoFocus
            className="w-full bg-transparent text-sm text-white placeholder-[#7872a3] focus:outline-none font-medium"
          />
          <button
            onClick={onClose}
            className="p-1 text-[#8c85bd] hover:text-white rounded-md transition-colors cursor-pointer"
          >
            <X size={16} />
          </button>
        </div>

        {/* Results List */}
        <div className="max-h-80 overflow-y-auto p-2">
          {filtered.length > 0 ? (
            <div className="flex flex-col gap-1">
              {filtered.map((item) => {
                const Icon = item.icon;
                return (
                  <button
                    key={item.id}
                    onClick={() => {
                      item.onExecute();
                      onClose();
                    }}
                    className="flex items-center justify-between w-full px-3 py-2.5 rounded-xl text-left hover:bg-[#231f47] transition-colors group cursor-pointer"
                  >
                    <div className="flex items-center gap-3 min-w-0">
                      <div className="flex-shrink-0 flex items-center justify-center text-[#c084fc]">
                        <Icon size={18} />
                      </div>
                      <div className="min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-semibold text-white group-hover:text-[#c4bbf0] transition-colors truncate">
                            {item.title}
                          </span>
                          <span className="text-[9.5px] px-1.5 py-0.2 rounded font-mono font-medium bg-[#1d1a3b] text-[#9a94cb] border border-[#312a5e]">
                            {item.category}
                          </span>
                        </div>
                        <div className="text-[11px] text-[#8680b5] truncate mt-0.5">
                          {item.subtitle}
                        </div>
                      </div>
                    </div>
                    <ArrowRight size={14} className="text-[#6d669c] group-hover:text-white group-hover:translate-x-0.5 transition-all flex-shrink-0 ml-2" />
                  </button>
                );
              })}
            </div>
          ) : (
            <div className="py-8 text-center text-xs text-[#8c85bd]">
              No actions or resources found for "{query}"
            </div>
          )}
        </div>

        {/* Footer shortcuts */}
        <div className="flex items-center justify-between px-4 py-2.5 border-t border-[#2a2456] bg-[#14122b] text-[11px] text-[#716a9c]">
          <span>Select any action to execute immediately</span>
          <span>Press <kbd className="px-1.5 py-0.5 bg-[#201d42] rounded text-[#a59fcf]">ESC</kbd> to exit</span>
        </div>
      </div>
    </div>
  );
};
