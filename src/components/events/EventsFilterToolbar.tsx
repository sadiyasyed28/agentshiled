import React, { useState, useRef, useEffect } from 'react';
import { Search, ChevronDown, SlidersHorizontal, X, Check } from 'lucide-react';
import type { EventsFilterState, EventDecision, ExecutionStatus } from './eventsTypes';

interface EventsFilterToolbarProps {
  filters: EventsFilterState;
  onFilterChange: <K extends keyof EventsFilterState>(key: K, value: EventsFilterState[K]) => void;
  onClearAll: () => void;
  activeFilterCount: number;
  availableAgents?: string[];
  availableTools?: string[];
  availablePolicies?: string[];
}

export const EventsFilterToolbar: React.FC<EventsFilterToolbarProps> = ({
  filters,
  onFilterChange,
  onClearAll,
  activeFilterCount,
  availableAgents,
  availableTools,
  availablePolicies,
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

  const decisions: (EventDecision | 'All')[] = ['All', 'Allowed', 'Review', 'Blocked'];
  
  const agents = [
    'All',
    ...Array.from(
      new Set(
        availableAgents && availableAgents.length > 0
          ? availableAgents
          : ['research-agent', 'email-agent', 'ops-agent', 'data-agent']
      )
    ),
  ];

  const tools = [
    'All',
    ...Array.from(
      new Set(
        availableTools && availableTools.length > 0
          ? availableTools
          : [
              'read_web',
              'send_email',
              'list_files',
              'query_db',
              'download_file',
              'read_mail',
              'modify_record',
              'delete_record',
            ]
      )
    ),
  ];

  const riskRanges: EventsFilterState['riskRange'][] = [
    'All',
    'Low (0-30)',
    'Medium (31-70)',
    'High (71-100)',
  ];

  const executions: (ExecutionStatus | 'All')[] = ['All', 'Executed', 'Not Executed', 'Pending'];

  const policies = [
    'All',
    ...Array.from(
      new Set(
        availablePolicies && availablePolicies.length > 0
          ? availablePolicies
          : [
              'Research v2',
              'Restricted v1',
              'Operations v1',
              'Data Access v3',
              'Email v1',
            ]
      )
    ),
  ];

  return (
    <div ref={toolbarRef} className="relative z-20 flex flex-wrap items-center justify-between gap-2.5 mb-3.5">
      {/* LEFT: SEARCH & FILTER BUTTONS */}
      <div className="flex flex-wrap items-center gap-2 flex-1 min-w-0">
        {/* 1. SEARCH INPUT */}
        <div className="relative flex-1 min-w-[220px] max-w-[340px]">
          <Search
            size={14}
            className="absolute left-3 top-1/2 -translate-y-1/2 text-[#8b84bc] pointer-events-none"
          />
          <input
            type="text"
            value={filters.searchQuery}
            onChange={(e) => onFilterChange('searchQuery', e.target.value)}
            placeholder="Search by event ID, agent, or tool..."
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

        {/* 2. DECISION DROPDOWN */}
        <div className="relative">
          <button
            onClick={() => toggleDropdown('decision')}
            className={`flex items-center gap-1.5 h-9 px-3 bg-[#171530] border rounded-xl text-xs font-medium transition-colors ${
              filters.decision !== 'All'
                ? 'border-[#6d3ee8] text-white bg-[#221c45]'
                : 'border-[#3b3472] text-[#d4cfea] hover:border-[#534994]'
            }`}
          >
            <span>{filters.decision === 'All' ? 'Decision' : filters.decision}</span>
            <ChevronDown size={13} className="text-[#8e87bf]" />
          </button>

          {openDropdown === 'decision' && (
            <div className="absolute left-0 mt-1.5 w-36 p-1 bg-[#181635] border border-[#3e3678] rounded-xl shadow-2xl z-50 animate-in fade-in zoom-in-95 duration-100">
              {decisions.map((d) => (
                <button
                  key={d}
                  onClick={() => {
                    onFilterChange('decision', d);
                    setOpenDropdown(null);
                  }}
                  className={`flex items-center justify-between w-full px-3 py-1.5 rounded-lg text-xs font-medium text-left transition-colors ${
                    filters.decision === d
                      ? 'bg-[#6d3ee8] text-white'
                      : 'text-[#aaa4d4] hover:bg-[#25204c] hover:text-white'
                  }`}
                >
                  <span>{d === 'All' ? 'All Decisions' : d}</span>
                  {filters.decision === d && <Check size={13} />}
                </button>
              ))}
            </div>
          )}
        </div>

        {/* 3. AGENT DROPDOWN */}
        <div className="relative">
          <button
            onClick={() => toggleDropdown('agent')}
            className={`flex items-center gap-1.5 h-9 px-3 bg-[#171530] border rounded-xl text-xs font-medium transition-colors ${
              filters.agent !== 'All'
                ? 'border-[#6d3ee8] text-white bg-[#221c45]'
                : 'border-[#3b3472] text-[#d4cfea] hover:border-[#534994]'
            }`}
          >
            <span>{filters.agent === 'All' ? 'Agent' : filters.agent}</span>
            <ChevronDown size={13} className="text-[#8e87bf]" />
          </button>

          {openDropdown === 'agent' && (
            <div className="absolute left-0 mt-1.5 w-44 p-1 bg-[#181635] border border-[#3e3678] rounded-xl shadow-2xl z-50 animate-in fade-in zoom-in-95 duration-100">
              {agents.map((ag) => (
                <button
                  key={ag}
                  onClick={() => {
                    onFilterChange('agent', ag);
                    setOpenDropdown(null);
                  }}
                  className={`flex items-center justify-between w-full px-3 py-1.5 rounded-lg text-xs font-medium text-left transition-colors ${
                    filters.agent === ag
                      ? 'bg-[#6d3ee8] text-white'
                      : 'text-[#aaa4d4] hover:bg-[#25204c] hover:text-white'
                  }`}
                >
                  <span>{ag === 'All' ? 'All Agents' : ag}</span>
                  {filters.agent === ag && <Check size={13} />}
                </button>
              ))}
            </div>
          )}
        </div>

        {/* 4. TOOL DROPDOWN */}
        <div className="relative">
          <button
            onClick={() => toggleDropdown('tool')}
            className={`flex items-center gap-1.5 h-9 px-3 bg-[#171530] border rounded-xl text-xs font-medium transition-colors ${
              filters.tool !== 'All'
                ? 'border-[#6d3ee8] text-white bg-[#221c45]'
                : 'border-[#3b3472] text-[#d4cfea] hover:border-[#534994]'
            }`}
          >
            <span>{filters.tool === 'All' ? 'Tool' : filters.tool}</span>
            <ChevronDown size={13} className="text-[#8e87bf]" />
          </button>

          {openDropdown === 'tool' && (
            <div className="absolute left-0 mt-1.5 w-44 p-1 bg-[#181635] border border-[#3e3678] rounded-xl shadow-2xl z-50 animate-in fade-in zoom-in-95 duration-100 max-h-56 overflow-y-auto">
              {tools.map((t) => (
                <button
                  key={t}
                  onClick={() => {
                    onFilterChange('tool', t);
                    setOpenDropdown(null);
                  }}
                  className={`flex items-center justify-between w-full px-3 py-1.5 rounded-lg text-xs font-medium text-left transition-colors ${
                    filters.tool === t
                      ? 'bg-[#6d3ee8] text-white'
                      : 'text-[#aaa4d4] hover:bg-[#25204c] hover:text-white'
                  }`}
                >
                  <span>{t === 'All' ? 'All Tools' : t}</span>
                  {filters.tool === t && <Check size={13} />}
                </button>
              ))}
            </div>
          )}
        </div>

        {/* 5. RISK SCORE DROPDOWN */}
        <div className="relative">
          <button
            onClick={() => toggleDropdown('risk')}
            className={`flex items-center gap-1.5 h-9 px-3 bg-[#171530] border rounded-xl text-xs font-medium transition-colors ${
              filters.riskRange !== 'All'
                ? 'border-[#6d3ee8] text-white bg-[#221c45]'
                : 'border-[#3b3472] text-[#d4cfea] hover:border-[#534994]'
            }`}
          >
            <span>{filters.riskRange === 'All' ? 'Risk Score' : filters.riskRange}</span>
            <ChevronDown size={13} className="text-[#8e87bf]" />
          </button>

          {openDropdown === 'risk' && (
            <div className="absolute left-0 mt-1.5 w-44 p-1 bg-[#181635] border border-[#3e3678] rounded-xl shadow-2xl z-50 animate-in fade-in zoom-in-95 duration-100">
              {riskRanges.map((r) => (
                <button
                  key={r}
                  onClick={() => {
                    onFilterChange('riskRange', r);
                    setOpenDropdown(null);
                  }}
                  className={`flex items-center justify-between w-full px-3 py-1.5 rounded-lg text-xs font-medium text-left transition-colors ${
                    filters.riskRange === r
                      ? 'bg-[#6d3ee8] text-white'
                      : 'text-[#aaa4d4] hover:bg-[#25204c] hover:text-white'
                  }`}
                >
                  <span>{r === 'All' ? 'All Risk Scores' : r}</span>
                  {filters.riskRange === r && <Check size={13} />}
                </button>
              ))}
            </div>
          )}
        </div>

        {/* 6. EXECUTION DROPDOWN */}
        <div className="relative">
          <button
            onClick={() => toggleDropdown('execution')}
            className={`flex items-center gap-1.5 h-9 px-3 bg-[#171530] border rounded-xl text-xs font-medium transition-colors ${
              filters.execution !== 'All'
                ? 'border-[#6d3ee8] text-white bg-[#221c45]'
                : 'border-[#3b3472] text-[#d4cfea] hover:border-[#534994]'
            }`}
          >
            <span>{filters.execution === 'All' ? 'Execution' : filters.execution}</span>
            <ChevronDown size={13} className="text-[#8e87bf]" />
          </button>

          {openDropdown === 'execution' && (
            <div className="absolute left-0 mt-1.5 w-44 p-1 bg-[#181635] border border-[#3e3678] rounded-xl shadow-2xl z-50 animate-in fade-in zoom-in-95 duration-100">
              {executions.map((e) => (
                <button
                  key={e}
                  onClick={() => {
                    onFilterChange('execution', e);
                    setOpenDropdown(null);
                  }}
                  className={`flex items-center justify-between w-full px-3 py-1.5 rounded-lg text-xs font-medium text-left transition-colors ${
                    filters.execution === e
                      ? 'bg-[#6d3ee8] text-white'
                      : 'text-[#aaa4d4] hover:bg-[#25204c] hover:text-white'
                  }`}
                >
                  <span>{e === 'All' ? 'All Statuses' : e}</span>
                  {filters.execution === e && <Check size={13} />}
                </button>
              ))}
            </div>
          )}
        </div>

        {/* 7. MORE FILTERS */}
        <div className="relative">
          <button
            onClick={() => toggleDropdown('more')}
            className={`flex items-center gap-1.5 h-9 px-3 bg-[#171530] border rounded-xl text-xs font-medium transition-colors ${
              filters.policy !== 'All'
                ? 'border-[#6d3ee8] text-white bg-[#221c45]'
                : 'border-[#3b3472] text-[#d4cfea] hover:border-[#534994]'
            }`}
          >
            <SlidersHorizontal size={13} className="text-[#a59ecd]" />
            <span>More Filters</span>
            {filters.policy !== 'All' && (
              <span className="w-1.5 h-1.5 rounded-full bg-[#6d3ee8]" />
            )}
          </button>

          {openDropdown === 'more' && (
            <div className="absolute left-0 mt-1.5 w-52 p-2 bg-[#181635] border border-[#3e3678] rounded-xl shadow-2xl z-50 animate-in fade-in zoom-in-95 duration-100">
              <div className="text-[11px] font-bold uppercase tracking-wider text-[#8b84bc] px-2 py-1">
                Filter by Policy
              </div>
              {policies.map((p) => (
                <button
                  key={p}
                  onClick={() => {
                    onFilterChange('policy', p);
                    setOpenDropdown(null);
                  }}
                  className={`flex items-center justify-between w-full px-2.5 py-1.5 rounded-lg text-xs font-medium text-left transition-colors ${
                    filters.policy === p
                      ? 'bg-[#6d3ee8] text-white'
                      : 'text-[#aaa4d4] hover:bg-[#25204c] hover:text-white'
                  }`}
                >
                  <span>{p === 'All' ? 'All Policies' : p}</span>
                  {filters.policy === p && <Check size={13} />}
                </button>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* RIGHT: CLEAR ALL */}
      {activeFilterCount > 0 ? (
        <button
          onClick={onClearAll}
          className="text-xs font-semibold text-[#a59ecd] hover:text-white transition-colors cursor-pointer px-1 py-1 flex items-center gap-1"
        >
          <span>Clear All</span>
          <span className="px-1.5 py-0.2 bg-[#2d2459] text-[#c4bbf0] text-[10px] rounded-md font-mono">
            {activeFilterCount}
          </span>
        </button>
      ) : (
        <span className="text-xs font-medium text-[#766f9e] select-none px-1">
          Clear All
        </span>
      )}
    </div>
  );
};

