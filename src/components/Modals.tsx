import React from 'react';
import { X } from 'lucide-react';
import type { Agent, SecurityEvent } from '../types';
import { PixelRobotIcon, PixelCrossShieldIcon, PixelCheckCircleIcon, PixelClockCircleIcon } from './pixel/PixelIcons';
import { AnimatedNumber } from './pixel/AnimatedNumber';

// Modal for Inspecting an Agent
export const AgentDetailModal: React.FC<{
  agent: Agent | null;
  onClose: () => void;
}> = ({ agent, onClose }) => {
  if (!agent) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-in fade-in duration-150">
      <div className="relative w-full max-w-lg p-6 bg-[#181636] border border-[#40387d] rounded-2xl shadow-2xl">
        <button
          onClick={onClose}
          className="absolute top-4 right-4 p-1 text-[#8b84bd] hover:text-white transition-colors"
        >
          <X size={18} />
        </button>

        <div className="flex items-center gap-3 mb-4">
          <div className="w-10 h-10 rounded-xl bg-[#2b2559] flex items-center justify-center text-[#c084fc]">
            <PixelRobotIcon size={24} />
          </div>
          <div>
            <h3 className="text-lg font-bold text-white font-mono">{agent.name}</h3>
            <span className="text-xs text-[#958ec4]">
              Runtime: {agent.runtime || 'Unavailable'}
            </span>
          </div>
        </div>

        <p className="text-xs text-[#c6c1ed] mb-5 leading-relaxed bg-[#1f1c42] p-3 rounded-xl border border-[#322c61]">
          {agent.description || 'No custom agent description registered.'}
        </p>

        <div className="grid grid-cols-2 gap-3 mb-5 text-xs">
          <div className="p-3 bg-[#1e1a3f] rounded-xl border border-[#312a5e]">
            <span className="text-[11px] text-[#8680b5] block">Operational Status</span>
            <span className="text-sm font-bold text-white mt-0.5 block">{agent.status}</span>
          </div>
          <div className="p-3 bg-[#1e1a3f] rounded-xl border border-[#312a5e]">
            <span className="text-[11px] text-[#8680b5] block">Active Policy</span>
            <span className="text-sm font-bold text-[#c084fc] mt-0.5 block">{agent.policy || 'Unassigned'}</span>
          </div>
          <div className="p-3 bg-[#1e1a3f] rounded-xl border border-[#312a5e]">
            <span className="text-[11px] text-[#8680b5] block">7-Day Event Volume</span>
            <span className="text-sm font-bold text-white mt-0.5 block"><AnimatedNumber value={agent.events7d} /></span>
          </div>
          <div className="p-3 bg-[#1e1a3f] rounded-xl border border-[#312a5e]">
            <span className="text-[11px] text-[#8680b5] block">Blocked Rate</span>
            <span className="text-sm font-bold text-[#ef4444] mt-0.5 block">
              <AnimatedNumber value={agent.blockedCount} /> (
              <AnimatedNumber value={parseFloat(agent.blockedRate || '0')} decimals={1} suffix="%" />)
            </span>
          </div>
          <div className="p-3 bg-[#1e1a3f] rounded-xl border border-[#312a5e]">
            <span className="text-[11px] text-[#8680b5] block">Last Activity</span>
            <span className="text-sm font-bold text-white mt-0.5 block">{agent.lastActive || 'Unavailable'}</span>
          </div>
          <div className="p-3 bg-[#1e1a3f] rounded-xl border border-[#312a5e]">
            <span className="text-[11px] text-[#8680b5] block">Execution Containment</span>
            <span className={`text-sm font-bold mt-0.5 block ${agent.status === 'Paused' ? 'text-[#facc15]' : 'text-[#4ade80]'}`}>
              {agent.status === 'Paused' ? 'Contained' : 'Permitted'}
            </span>
          </div>
        </div>

        <div className="flex justify-end gap-2.5">
          <button
            onClick={onClose}
            className="px-4 py-2 text-xs font-semibold text-white bg-[#6d3ee8] hover:bg-[#7e50f5] rounded-xl transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};

// Modal for Inspecting a Security Event
export const EventDetailModal: React.FC<{
  event: SecurityEvent | null;
  onClose: () => void;
}> = ({ event, onClose }) => {
  if (!event) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-in fade-in duration-150">
      <div className="relative w-full max-w-lg p-6 bg-[#181636] border border-[#40387d] rounded-2xl shadow-2xl">
        <button
          onClick={onClose}
          className="absolute top-4 right-4 p-1 text-[#8b84bd] hover:text-white transition-colors"
        >
          <X size={18} />
        </button>

        <div className="flex items-center gap-3 mb-4">
          <div className="w-10 h-10 rounded-xl bg-[#2b2559] flex items-center justify-center">
            {event.decision === 'Blocked' && <PixelCrossShieldIcon size={22} />}
            {event.decision === 'Allowed' && <PixelCheckCircleIcon size={22} />}
            {event.decision === 'Review' && <PixelClockCircleIcon size={22} />}
          </div>
          <div>
            <h3 className="text-base font-bold text-white font-mono">
              {event.agent} · {event.action}
            </h3>
            <span className="text-xs text-[#958ec4]">{event.timestamp}</span>
          </div>
        </div>

        <div className="flex items-center gap-2 mb-4">
          <span
            className={`px-2.5 py-0.5 text-xs font-bold rounded-md ${
              event.decision === 'Allowed'
                ? 'bg-[#154629] text-[#4ade80]'
                : event.decision === 'Blocked'
                ? 'bg-[#4d1a24] text-[#f87171]'
                : 'bg-[#453712] text-[#facc15]'
            }`}
          >
            {event.decision}
          </span>
          <span className="px-2.5 py-0.5 text-xs font-bold rounded-md bg-[#282252] text-[#c4bbf0]">
            Risk Score: <AnimatedNumber value={event.riskScore} /> / 100
          </span>
        </div>

        <div className="mb-4">
          <label className="text-[11px] font-semibold text-[#8680b5] uppercase tracking-wider block mb-1">
            Anomaly Reason
          </label>
          <p className="text-xs text-[#c6c1ed] bg-[#1f1c42] p-3 rounded-xl border border-[#322c61] leading-relaxed">
            {event.reason || 'Normal event execution pattern verified.'}
          </p>
        </div>

        {event.payloadSummary && (
          <div className="mb-5">
            <label className="text-[11px] font-semibold text-[#8680b5] uppercase tracking-wider block mb-1">
              Command / Telemetry Payload
            </label>
            <pre className="text-[11px] font-mono text-[#a5b4fc] bg-[#110f24] p-3 rounded-xl border border-[#2e285a] overflow-x-auto whitespace-pre-wrap">
              {event.payloadSummary}
            </pre>
          </div>
        )}

        <div className="flex justify-end gap-2.5">
          <button
            onClick={onClose}
            className="px-4 py-2 text-xs font-semibold text-white bg-[#6d3ee8] hover:bg-[#7e50f5] rounded-xl transition-colors"
          >
            Dismiss
          </button>
        </div>
      </div>
    </div>
  );
};
