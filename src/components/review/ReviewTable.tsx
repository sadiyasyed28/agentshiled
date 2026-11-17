import React, { useState } from 'react';
import { ChevronRight, Check } from 'lucide-react';
import type { ReviewRequest } from './reviewTypes';
import { PixelRobotIcon } from '../pixel/PixelIcons';
import { AnimatedNumber } from '../pixel/AnimatedNumber';
import {
  PixelGlobeIcon,
  PixelDatabaseIcon,
  PixelMailIcon,
  PixelCodeIcon,
  PixelPencilIcon,
  PixelDownloadIcon,
} from './ReviewIcons';

interface ReviewTableProps {
  requests: ReviewRequest[];
  selectedRequest: ReviewRequest | null;
  onSelectRequest: (req: ReviewRequest) => void;
}

export const ReviewTable: React.FC<ReviewTableProps> = ({
  requests,
  selectedRequest,
  onSelectRequest,
}) => {
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());

  const isAllSelected =
    requests.length > 0 && requests.every((r) => selectedIds.has(r.id));

  const toggleSelectAll = () => {
    if (isAllSelected) {
      setSelectedIds(new Set());
    } else {
      setSelectedIds(new Set(requests.map((r) => r.id)));
    }
  };

  const toggleSelectRow = (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  };

  const renderToolIcon = (tool: string) => {
    switch (tool) {
      case 'read_web':
        return <PixelGlobeIcon size={14} className="text-[#60a5fa]" />;
      case 'export_db':
        return <PixelDatabaseIcon size={14} className="text-[#a78bfa]" />;
      case 'send_email':
        return <PixelMailIcon size={14} className="text-[#38bdf8]" />;
      case 'api_call':
        return <PixelCodeIcon size={14} className="text-[#34d399]" />;
      case 'update_record':
        return <PixelPencilIcon size={14} className="text-[#fbbf24]" />;
      case 'download_file':
        return <PixelDownloadIcon size={14} className="text-[#c084fc]" />;
      default:
        return <PixelGlobeIcon size={14} className="text-[#938ebf]" />;
    }
  };

  return (
    <div className="relative p-[1.5px] bg-[#3a3273] pixel-corners shadow-[0_4px_24px_rgba(0,0,0,0.45)]">
      <div className="w-full bg-[#16142e] pixel-corners flex flex-col">
        <div className="w-full overflow-x-auto">
          <table className="w-full text-left border-collapse min-w-[700px]">
            {/* TABLE HEADER */}
            <thead>
              <tr className="border-b border-[#292352] text-[#dcd7f2] text-xs font-semibold select-none bg-[#16142e]">
                {/* Selection Checkbox */}
                <th className="py-3 px-3 w-9 text-center">
                  <button
                    onClick={toggleSelectAll}
                    title="Select all"
                    className={`w-4 h-4 rounded-sm flex items-center justify-center transition-colors border ${
                      isAllSelected
                        ? 'bg-[#6d3ee8] border-[#6d3ee8] text-white'
                        : 'bg-[#1b1836] border-[#443c7c] hover:border-[#6d3ee8]'
                    }`}
                  >
                    {isAllSelected && <Check size={11} strokeWidth={3} />}
                  </button>
                </th>

                <th className="py-3 px-3 whitespace-nowrap">Request</th>
                <th className="py-3 px-3 whitespace-nowrap">Agent</th>
                <th className="py-3 px-3 whitespace-nowrap">Action (Tool)</th>
                <th className="py-3 px-3 whitespace-nowrap">Risk</th>
                <th className="py-3 px-3 whitespace-nowrap">Requested At</th>
                <th className="py-3 px-3 whitespace-nowrap">Expires In</th>
                <th className="py-3 px-3 w-8 text-center"></th>
              </tr>
            </thead>

            {/* TABLE BODY */}
            <tbody className="divide-y divide-[#221e45] text-xs">
              {requests.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-[#8e87bf]">
                    No review requests found for this tab or filter criteria.
                  </td>
                </tr>
              ) : (
                requests.map((req) => {
                  const isChecked = selectedIds.has(req.id);
                  const isCurrent = selectedRequest?.id === req.id;

                  return (
                    <tr
                      key={req.id}
                      onClick={() => onSelectRequest(req)}
                      className={`cursor-pointer transition-colors ${
                        isCurrent
                          ? 'bg-[#251e52] shadow-inner border-l-2 border-[#6d3ee8]'
                          : isChecked
                          ? 'bg-[#1e1944]'
                          : 'hover:bg-[#1c183b]'
                      }`}
                    >
                      {/* Checkbox */}
                      <td
                        className="py-3 px-3 text-center"
                        onClick={(e) => toggleSelectRow(req.id, e)}
                      >
                        <button
                          type="button"
                          className={`w-4 h-4 rounded-sm flex items-center justify-center transition-colors border ${
                            isChecked
                              ? 'bg-[#6d3ee8] border-[#6d3ee8] text-white'
                              : 'bg-[#1b1836] border-[#443c7c] hover:border-[#6d3ee8]'
                          }`}
                        >
                          {isChecked && <Check size={11} strokeWidth={3} />}
                        </button>
                      </td>

                      {/* Request: ID & Description */}
                      <td className="py-2.5 px-3 whitespace-nowrap">
                        <div className="font-mono font-bold text-white text-[12.5px] leading-tight">
                          {req.id}
                        </div>
                        <div className="text-[11.5px] text-[#9c96c9] mt-0.5 font-medium leading-tight">
                          {req.description}
                        </div>
                      </td>

                      {/* Agent */}
                      <td className="py-2.5 px-3 whitespace-nowrap">
                        <div className="flex items-center gap-1.5">
                          <span className="flex-shrink-0 text-[#a5b4fc]">
                            <PixelRobotIcon size={15} />
                          </span>
                          <span className="font-medium text-white text-[12px]">
                            {req.agent}
                          </span>
                        </div>
                      </td>

                      {/* Action (Tool) */}
                      <td className="py-2.5 px-3 whitespace-nowrap">
                        <div className="flex items-center gap-1.5 font-mono text-[#dcd7f2] text-[12px]">
                          {renderToolIcon(req.tool)}
                          <span>{req.tool}</span>
                        </div>
                      </td>

                      {/* Risk */}
                      <td className="py-2.5 px-3 whitespace-nowrap">
                        <span
                          className={`inline-flex items-center justify-center px-2 py-0.5 min-w-[28px] rounded-md font-mono font-bold text-xs text-white ${
                            req.riskScore >= 75
                              ? 'bg-[#ef4444]'
                              : req.riskScore >= 40
                              ? 'bg-[#f59e0b]'
                              : 'bg-[#22c55e]'
                          }`}
                        >
                          {req.riskScore}
                        </span>
                      </td>

                      {/* Requested At */}
                      <td className="py-2.5 px-3 text-[#a59ecd] whitespace-nowrap text-[12px]">
                        {req.requestedAt}
                      </td>

                      {/* Expires In */}
                      <td className="py-2.5 px-3 whitespace-nowrap">
                        {req.status === 'Pending' ? (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-[#332b14] border border-[#71540f] text-[#facc15] font-semibold text-[11.5px]">
                            <span className="text-[11px]">🕒</span>
                            <span>{req.expiresIn}</span>
                          </span>
                        ) : req.status === 'Approved' ? (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-[#14331b] border border-[#1f6633] text-[#4ade80] font-semibold text-[11.5px]">
                            <span>✔ Approved</span>
                          </span>
                        ) : req.status === 'Denied' ? (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-[#381616] border border-[#782424] text-[#f87171] font-semibold text-[11.5px]">
                            <span>✖ Denied</span>
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-[#252042] border border-[#483d7a] text-[#a59ecd] font-semibold text-[11.5px]">
                            <span>Expired</span>
                          </span>
                        )}
                      </td>

                      {/* Right Chevron */}
                      <td className="py-2.5 px-3 text-center text-[#8e87bf]">
                        <ChevronRight
                          size={15}
                          className={`transition-transform ${
                            isCurrent ? 'text-white translate-x-0.5' : 'text-[#736c9e]'
                          }`}
                        />
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* FOOTER */}
        <div className="flex items-center justify-between px-4 py-2.5 border-t border-[#292352] bg-[#16142e] text-xs text-[#9c96c9] select-none font-medium">
          <div>
            {requests.length === 0 ? (
              <span>0 requests</span>
            ) : (
              <>
                Showing <span className="text-white font-mono">1–<AnimatedNumber value={requests.length} /></span> of{' '}
                <span className="text-white font-mono"><AnimatedNumber value={requests.length} /></span> requests
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

