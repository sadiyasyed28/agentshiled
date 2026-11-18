import React from 'react';
import { X, Shield, Lock, Info } from 'lucide-react';
import type { SecurityPolicy } from './policyTypes';

interface PolicyModalProps {
  isOpen: boolean;
  onClose: () => void;
  policyToEdit: SecurityPolicy | null;
  policyVersionHash?: string | null;
  knownTools?: string[];
}

export const PolicyModal: React.FC<PolicyModalProps> = ({
  isOpen,
  onClose,
  policyToEdit,
  policyVersionHash,
  knownTools = [],
}) => {
  if (!isOpen) return null;

  const policy = policyToEdit;
  const versionDisplay = policyVersionHash || policy?.version || 'v1.0.0';

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-xs animate-in fade-in duration-150">
      <div className="fixed inset-0" onClick={onClose} />

      <div className="relative w-full max-w-lg bg-[#16142e] border border-[#3a3273] rounded-2xl shadow-2xl p-5 z-10 animate-in zoom-in-95 duration-150 font-mono text-xs">
        {/* Header */}
        <div className="flex items-center justify-between pb-3 border-b border-[#292352]">
          <div className="flex items-center gap-2">
            <Shield size={18} className="text-[#3ddc97]" />
            <h3 className="text-base font-bold text-white font-sans">
              Policy Ruleset Inspection
            </h3>
          </div>
          <button
            onClick={onClose}
            className="w-7 h-7 rounded-lg bg-[#231f45] hover:bg-[#342d6a] text-[#8e87bf] hover:text-white flex items-center justify-center transition-colors cursor-pointer"
          >
            <X size={16} />
          </button>
        </div>

        {/* Read-Only Deterministic Architecture Explanation */}
        <div className="mt-3.5 p-3 bg-[#403413]/70 border border-[#6b551c] rounded-xl text-[11px] text-[#fde047] space-y-1.5 leading-relaxed">
          <div className="font-bold flex items-center gap-1.5 text-[#facc15]">
            <Lock size={13} />
            <span>Immutable Deterministic Ruleset (Read-Only)</span>
          </div>
          <p>
            AgentShield policies are statically defined in Python code and verified via cryptographic SHA-256 hash. Runtime edits and dynamic creation are disabled by design to prevent prompt injection and unauthorized rule manipulation.
          </p>
        </div>

        {/* Policy Details */}
        <div className="mt-4 space-y-3 text-xs text-[#cdc7ea]">
          <div className="grid grid-cols-2 gap-2">
            <div className="p-2.5 bg-[#191738] rounded-xl border border-[#3b3472]">
              <span className="text-[10px] text-[#8b84bc] block uppercase font-bold">Policy Name</span>
              <span className="font-bold text-white mt-0.5 block truncate">
                {policy?.name || 'Enforced Engine Policy'}
              </span>
            </div>
            <div className="p-2.5 bg-[#191738] rounded-xl border border-[#3b3472]">
              <span className="text-[10px] text-[#8b84bc] block uppercase font-bold">Policy Hash / Tag</span>
              <span className="font-bold text-[#3ddc97] mt-0.5 block truncate select-all" title={versionDisplay}>
                {versionDisplay}
              </span>
            </div>
          </div>

          <div className="p-2.5 bg-[#191738] rounded-xl border border-[#3b3472]">
            <span className="text-[10px] text-[#8b84bc] block uppercase font-bold">Description</span>
            <span className="text-white mt-0.5 block leading-relaxed text-[11.5px]">
              {policy?.description || 'Core deterministic tool authorization ruleset enforced by PolicyEngine.'}
            </span>
          </div>

          <div className="p-2.5 bg-[#191738] rounded-xl border border-[#3b3472]">
            <span className="text-[10px] text-[#8b84bc] block uppercase font-bold">
              Engine Allowed Tools ({policy?.rules.allowedTools.length ?? knownTools.length})
            </span>
            <div className="flex flex-wrap gap-1.5 mt-1.5">
              {(policy?.rules.allowedTools || knownTools).map((tool) => (
                <span
                  key={tool}
                  className="px-2 py-0.5 rounded text-[10.5px] bg-[#241f48] text-[#c084fc] border border-[#3e3478]"
                >
                  {tool}
                </span>
              ))}
            </div>
          </div>

          <div className="p-2.5 bg-[#191738] rounded-xl border border-[#3b3472]">
            <span className="text-[10px] text-[#8b84bc] block uppercase font-bold">
              Allowed Destination Hostnames
            </span>
            <div className="flex flex-wrap gap-1.5 mt-1.5">
              {(policy?.rules.allowedHostnames || ['*.internal', 'api.openai.com']).map((host) => (
                <span
                  key={host}
                  className="px-2 py-0.5 rounded text-[10.5px] bg-[#1a2d24] text-[#4ade80] border border-[#226742]"
                >
                  {host}
                </span>
              ))}
            </div>
          </div>

          <div className="grid grid-cols-2 gap-2 text-[11px]">
            <div className="p-2 bg-[#191738] rounded-lg border border-[#3b3472]">
              <span className="text-[#8b84bc] block">Review Threshold:</span>
              <span className="font-bold text-white">Risk ≥ {policy?.rules.reviewThreshold ?? 60}</span>
            </div>
            <div className="p-2 bg-[#191738] rounded-lg border border-[#3b3472]">
              <span className="text-[#8b84bc] block">Default Decision:</span>
              <span className="font-bold text-[#f87171]">BLOCK (Fail-closed)</span>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between pt-3 mt-4 border-t border-[#292352]">
          <span className="text-[10.5px] text-[#8b84bc] flex items-center gap-1">
            <Info size={12} /> Statically defined in Python SDK
          </span>
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-1.5 rounded-xl bg-[#6d3ee8] hover:bg-[#5b2ec9] text-xs font-bold text-white transition-colors cursor-pointer"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
