import React, { useState, useRef, useEffect } from 'react';
import { Search, ChevronDown, Plus, X, Check } from 'lucide-react';
import type { PolicyFilterState, PolicyStatus } from './policyTypes';

interface PolicyToolbarProps {
  filters: PolicyFilterState;
  onFilterChange: <K extends keyof PolicyFilterState>(key: K, value: PolicyFilterState[K]) => void;
  onResetFilters: () => void;
  onOpenNewPolicy: () => void;
  availableAgents?: string[];
}

export const PolicyToolbar: React.FC<PolicyToolbarProps> = ({
  filters,
  onFilterChange,
  onResetFilters,
  onOpenNewPolicy,
  availableAgents,
}) => {
  const [openDropdown, setOpenDropdown] = useState<string | null>(null);
  const toolbarRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (toolbarRef.current && !toolbarRef.current.contains(event.target as Node)) {
        setOpenDropdown(null);
      }
    };
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setOpenDropdown(null);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    document.addEventListener('keydown', handleKeyDown);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
      document.removeEventListener('keydown', handleKeyDown);
    };
  }, []);

  const toggleDropdown = (name: string) => {
    setOpenDropdown((prev) => (prev === name ? null : name));
  };

  const statuses: (PolicyStatus | 'All')[] = ['All', 'Active', 'Draft', 'Archived'];
  const agents = [
    'All',
    ...Array.from(
      new Set(
        availableAgents && availableAgents.length > 0
          ? availableAgents
          : ['research-agent', 'ops-agent', 'data-agent', 'email-agent']
      )
    ),
  ];

  const hasActiveFilters =
    filters.searchQuery.trim() !== '' ||
    filters.status !== 'All' ||
    filters.assignedAgent !== 'All';

  return (
    <div ref={toolbarRef} className="relative z-20 flex flex-wrap items-center justify-between gap-2.5 mb-3.5">
      {/* LEFT: SEARCH & DROPDOWNS */}
      <div className="flex flex-wrap items-center gap-2 flex-1 min-w-0">
        {/* Search */}
        <div className="relative flex-1 min-w-[200px] max-w-[320px]">
          <Search
            size={14}
            className="absolute left-3 top-1/2 -translate-y-1/2 text-[#8b84bc] pointer-events-none"
          />
          <input
            type="text"
            value={filters.searchQuery}
            onChange={(e) => onFilterChange('searchQuery', e.target.value)}
            placeholder="Search policies..."
            className="w-full h-9 pl-9 pr-8 bg-[#171530] border border-[#3b3472] rounded-xl text-xs text-white placeholder-[#7f78ab] focus:outline-none focus:border-[#6d3ee8] focus:ring-1 focus:ring-[#6d3ee8] transition-all shadow-inner"
          />
          {filters.searchQuery && (
            <button
              onClick={() => onFilterChange('searchQuery', '')}
              className="absolute right-2.5 top-1/2 -translate-y-1/2 text-[#7f78ab] hover:text-white"
            >
              <X size={13} />
            </button>
          )}
        </div>

        {/* Status Dropdown */}
        <div className="relative">
          <button
            onClick={() => toggleDropdown('status')}
            className={`flex items-center gap-1.5 h-9 px-3 bg-[#171530] border rounded-xl text-xs font-medium transition-colors ${
              filters.status !== 'All'
                ? 'border-[#6d3ee8] text-white bg-[#221c45]'
                : 'border-[#3b3472] text-[#d4cfea] hover:border-[#534994]'
            }`}
          >
            <span>{filters.status === 'All' ? 'Status' : filters.status}</span>
            <ChevronDown size={13} className="text-[#8e87bf]" />
          </button>

          {openDropdown === 'status' && (
            <div className="absolute left-0 mt-1.5 w-36 p-1 bg-[#181635] border border-[#3e3678] rounded-xl shadow-2xl z-50 animate-in fade-in zoom-in-95 duration-100">
              {statuses.map((s) => (
                <button
                  key={s}
                  onClick={() => {
                    onFilterChange('status', s);
                    setOpenDropdown(null);
                  }}
                  className={`flex items-center justify-between w-full px-3 py-1.5 rounded-lg text-xs font-medium text-left transition-colors ${
                    filters.status === s
                      ? 'bg-[#6d3ee8] text-white'
                      : 'text-[#aaa4d4] hover:bg-[#25204c] hover:text-white'
                  }`}
                >
                  <span>{s === 'All' ? 'All Statuses' : s}</span>
                  {filters.status === s && <Check size={13} />}
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Assigned Agents Dropdown */}
        <div className="relative">
          <button
            onClick={() => toggleDropdown('agent')}
            className={`flex items-center gap-1.5 h-9 px-3 bg-[#171530] border rounded-xl text-xs font-medium transition-colors ${
              filters.assignedAgent !== 'All'
                ? 'border-[#6d3ee8] text-white bg-[#221c45]'
                : 'border-[#3b3472] text-[#d4cfea] hover:border-[#534994]'
            }`}
          >
            <span>{filters.assignedAgent === 'All' ? 'Assigned Agents' : filters.assignedAgent}</span>
            <ChevronDown size={13} className="text-[#8e87bf]" />
          </button>

          {openDropdown === 'agent' && (
            <div className="absolute left-0 mt-1.5 w-44 p-1 bg-[#181635] border border-[#3e3678] rounded-xl shadow-2xl z-50 animate-in fade-in zoom-in-95 duration-100">
              {agents.map((ag) => (
                <button
                  key={ag}
                  onClick={() => {
                    onFilterChange('assignedAgent', ag);
                    setOpenDropdown(null);
                  }}
                  className={`flex items-center justify-between w-full px-3 py-1.5 rounded-lg text-xs font-medium text-left transition-colors ${
                    filters.assignedAgent === ag
                      ? 'bg-[#6d3ee8] text-white'
                      : 'text-[#aaa4d4] hover:bg-[#25204c] hover:text-white'
                  }`}
                >
                  <span>{ag === 'All' ? 'All Agents' : ag}</span>
                  {filters.assignedAgent === ag && <Check size={13} />}
                </button>
              ))}
            </div>
          )}
        </div>

        {hasActiveFilters && (
          <button
            onClick={onResetFilters}
            className="text-xs font-medium text-[#a59ecd] hover:text-white transition-colors cursor-pointer px-1 py-1 flex items-center gap-1"
          >
            <span>Reset Filters</span>
          </button>
        )}
      </div>

      {/* RIGHT: NEW POLICY BUTTON */}
      <button
        onClick={onOpenNewPolicy}
        className="flex items-center gap-1.5 px-3.5 py-2 bg-[#6d3ee8] hover:bg-[#5b2ec9] text-white rounded-xl text-xs font-bold transition-all shadow-[0_2px_12px_rgba(109,62,232,0.4)] cursor-pointer active:scale-95"
      >
        <Plus size={14} strokeWidth={2.5} />
        <span>New Policy</span>
      </button>
    </div>
  );
};

