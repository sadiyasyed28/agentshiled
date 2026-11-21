import React, { useState, useRef, useEffect } from 'react';
import { Search, ChevronDown, ArrowUpDown, X, Check } from 'lucide-react';
import type { ReviewFilterState } from './reviewTypes';

interface ReviewToolbarProps {
  filters: ReviewFilterState;
  onFilterChange: <K extends keyof ReviewFilterState>(key: K, value: ReviewFilterState[K]) => void;
  onResetFilters: () => void;
  availableAgents?: string[];
  availableTools?: string[];
}

export const ReviewToolbar: React.FC<ReviewToolbarProps> = ({
  filters,
  onFilterChange,
  onResetFilters,
  availableAgents,
  availableTools,
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

  const agents = [
    'All',
    ...Array.from(
      new Set(
        availableAgents && availableAgents.length > 0
          ? availableAgents
          : ['research-agent', 'data-agent', 'email-agent', 'ops-agent']
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
              'export_db',
              'send_email',
              'api_call',
              'update_record',
              'download_file',
            ]
      )
    ),
  ];
  const riskScores = ['All', 'High (75+)', 'Medium (40-74)', 'Low (0-39)'];
  const sortOptions: ReviewFilterState['sortBy'][] = [
    'Newest',
    'Oldest',
    'Highest Risk',
    'Lowest Risk',
  ];

  const hasActiveFilters =
    filters.searchQuery.trim() !== '' ||
    filters.agent !== 'All' ||
    filters.tool !== 'All' ||
    filters.riskRange !== 'All';

  return (
    <div ref={toolbarRef} className="relative z-20 flex flex-wrap items-center justify-between gap-2.5 mb-3.5">
      <div className="flex flex-wrap items-center gap-2 flex-1 min-w-0">
        {/* 1. SEARCH INPUT */}
        <div className="relative flex-1 min-w-[200px] max-w-[320px]">
          <Search
            size={14}
            className="absolute left-3 top-1/2 -translate-y-1/2 text-[#8b84bc] pointer-events-none"
          />
          <input
            type="text"
            value={filters.searchQuery}
            onChange={(e) => onFilterChange('searchQuery', e.target.value)}
            placeholder="Search review requests..."
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

        {/* 2. AGENT DROPDOWN */}
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

        {/* 3. TOOL DROPDOWN */}
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

        {/* 4. RISK SCORE DROPDOWN */}
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
              {riskScores.map((r) => (
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
                  <span>{r === 'All' ? 'All Scores' : r}</span>
                  {filters.riskRange === r && <Check size={13} />}
                </button>
              ))}
            </div>
          )}
        </div>

        {/* 5. SORT DROPDOWN (Default: Newest) */}
        <div className="relative">
          <button
            onClick={() => toggleDropdown('sort')}
            className="flex items-center gap-1.5 h-9 px-3 bg-[#171530] border border-[#3b3472] rounded-xl text-xs font-medium text-[#d4cfea] hover:border-[#534994] transition-colors"
          >
            <ArrowUpDown size={13} className="text-[#8e87bf]" />
            <span>{filters.sortBy}</span>
            <ChevronDown size={13} className="text-[#8e87bf]" />
          </button>

          {openDropdown === 'sort' && (
            <div className="absolute left-0 mt-1.5 w-40 p-1 bg-[#181635] border border-[#3e3678] rounded-xl shadow-2xl z-50 animate-in fade-in zoom-in-95 duration-100">
              {sortOptions.map((s) => (
                <button
                  key={s}
                  onClick={() => {
                    onFilterChange('sortBy', s);
                    setOpenDropdown(null);
                  }}
                  className={`flex items-center justify-between w-full px-3 py-1.5 rounded-lg text-xs font-medium text-left transition-colors ${
                    filters.sortBy === s
                      ? 'bg-[#6d3ee8] text-white'
                      : 'text-[#aaa4d4] hover:bg-[#25204c] hover:text-white'
                  }`}
                >
                  <span>{s}</span>
                  {filters.sortBy === s && <Check size={13} />}
                </button>
              ))}
            </div>
          )}
        </div>
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
  );
};

