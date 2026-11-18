import React, { useState } from 'react';
import { Calendar, RefreshCw, ChevronDown, Download, Check, FileSpreadsheet, FileCode, ShieldCheck } from 'lucide-react';
import { PixelHeaderBackdrop } from '../pixel/PixelHeaderBackdrop';

interface EventsPageHeaderProps {
  onRefresh: () => void;
  isRefreshing?: boolean;
  onExport: (format: 'csv' | 'json') => void;
  dateRange: string;
  onDateRangeChange: (range: string) => void;
  onVerifyAudit?: () => void;
  isVerifyingAudit?: boolean;
}

export const EventsPageHeader: React.FC<EventsPageHeaderProps> = ({
  onRefresh,
  isRefreshing = false,
  onExport,
  dateRange,
  onDateRangeChange,
  onVerifyAudit,
  isVerifyingAudit = false,
}) => {
  const [dateRangeOpen, setDateRangeOpen] = useState(false);
  const [exportOpen, setExportOpen] = useState(false);

  const ranges = ['Last 24 Hours', 'Last 7 Days', 'Last 30 Days', 'All Time'];

  return (
    <div className="relative pt-2 pb-3.5">
      {/* Pixel-art background scene (Sunset Moon, Silhouette Castle & Towers) */}
      <div className="absolute top-0 right-52 left-[440px] h-20 hidden lg:block opacity-95 overflow-hidden pointer-events-none">
        <PixelHeaderBackdrop className="w-full h-full" />
      </div>

      <div className="relative z-10 flex flex-col md:flex-row md:items-center justify-between gap-3">
        {/* LEFT: TITLE & SUBTITLE */}
        <div>
          <h2 className="text-[26px] md:text-[28px] font-bold text-white tracking-tight leading-tight">
            Events
          </h2>
          <p className="text-[13.5px] font-medium text-[#938ebf] mt-0.5">
            Complete history of all agent actions and security decisions.
          </p>
        </div>

        {/* RIGHT: LAST 7 DAYS + EXPORT + REFRESH */}
        <div className="flex items-center gap-2.5 self-start md:self-auto relative z-20">
          {/* 1. Date Range Dropdown */}
          <div className="relative">
            <button
              onClick={() => {
                setDateRangeOpen(!dateRangeOpen);
                setExportOpen(false);
              }}
              className="flex items-center gap-2 px-3.5 py-2 bg-[#1b1937] border border-[#3a3270] rounded-xl text-xs font-semibold text-white hover:border-[#584ea4] transition-colors shadow-sm"
            >
              <Calendar size={14} className="text-[#a29bcf]" />
              <span>{dateRange}</span>
              <ChevronDown
                size={13}
                className={`text-[#8e87bf] transition-transform duration-200 ${
                  dateRangeOpen ? 'rotate-180' : ''
                }`}
              />
            </button>

            {dateRangeOpen && (
              <div className="absolute right-0 mt-1.5 w-44 p-1 bg-[#191733] border border-[#3e3678] rounded-xl shadow-2xl z-50 animate-in fade-in zoom-in-95 duration-100">
                {ranges.map((range) => (
                  <button
                    key={range}
                    onClick={() => {
                      onDateRangeChange(range);
                      setDateRangeOpen(false);
                    }}
                    className={`flex items-center justify-between w-full px-3 py-1.5 rounded-lg text-xs font-medium text-left transition-colors ${
                      dateRange === range
                        ? 'bg-[#6d3ee8] text-white'
                        : 'text-[#aaa4d4] hover:bg-[#25204c] hover:text-white'
                    }`}
                  >
                    <span>{range}</span>
                    {dateRange === range && <Check size={13} />}
                  </button>
                ))}
              </div>
            )}
          </div>

          {/* 2. Export Dropdown */}
          <div className="relative">
            <button
              onClick={() => {
                setExportOpen(!exportOpen);
                setDateRangeOpen(false);
              }}
              className="flex items-center gap-2 px-3.5 py-2 bg-[#1b1937] border border-[#3a3270] rounded-xl text-xs font-semibold text-white hover:border-[#584ea4] transition-colors shadow-sm"
            >
              <Download size={14} className="text-[#a29bcf]" />
              <span>Export</span>
              <ChevronDown
                size={13}
                className={`text-[#8e87bf] transition-transform duration-200 ${
                  exportOpen ? 'rotate-180' : ''
                }`}
              />
            </button>

            {exportOpen && (
              <div className="absolute right-0 mt-1.5 w-48 p-1 bg-[#191733] border border-[#3e3678] rounded-xl shadow-2xl z-50 animate-in fade-in zoom-in-95 duration-100">
                <button
                  onClick={() => {
                    onExport('csv');
                    setExportOpen(false);
                  }}
                  className="flex items-center gap-2.5 w-full px-3 py-2 rounded-lg text-xs font-medium text-[#aaa4d4] hover:bg-[#25204c] hover:text-white transition-colors"
                >
                  <FileSpreadsheet size={14} className="text-[#22c55e]" />
                  <span>Export as CSV</span>
                </button>
                <button
                  onClick={() => {
                    onExport('json');
                    setExportOpen(false);
                  }}
                  className="flex items-center gap-2.5 w-full px-3 py-2 rounded-lg text-xs font-medium text-[#aaa4d4] hover:bg-[#25204c] hover:text-white transition-colors"
                >
                  <FileCode size={14} className="text-[#60a5fa]" />
                  <span>Export as JSON</span>
                </button>
              </div>
            )}
          </div>

          {/* 3. Verify Audit Integrity Button */}
          {onVerifyAudit && (
            <button
              onClick={onVerifyAudit}
              disabled={isVerifyingAudit}
              title="Verify cryptographic SHA-256 hash chain of all audit events"
              className="flex items-center gap-1.5 px-3 py-2 bg-[#1b1937] border border-[#3a3270] hover:border-[#6d3ee8] rounded-xl text-xs font-semibold text-[#c084fc] hover:text-white transition-colors shadow-sm disabled:opacity-50 cursor-pointer"
            >
              <ShieldCheck size={14} className={isVerifyingAudit ? 'animate-pulse text-[#c084fc]' : 'text-[#a855f7]'} />
              <span>{isVerifyingAudit ? 'Verifying...' : 'Verify Audit'}</span>
            </button>
          )}

          {/* 4. Refresh Action Button */}
          <button
            onClick={onRefresh}
            title="Refresh events list"
            className="flex items-center justify-center w-8 h-8 bg-[#1b1937] border border-[#3a3270] rounded-xl text-[#a29bcf] hover:text-white hover:border-[#584ea4] active:scale-95 transition-all shadow-sm group cursor-pointer"
          >
            <RefreshCw
              size={14}
              className={`transition-transform duration-500 ${
                isRefreshing ? 'animate-spin text-[#c4bbf0]' : 'group-hover:rotate-180'
              }`}
            />
          </button>
        </div>
      </div>
    </div>
  );
};

