import React, { useState } from 'react';
import { X, Lock, Key, AlertCircle, Loader2, CheckCircle2 } from 'lucide-react';
import { PixelShieldIcon } from './pixel/PixelIcons';
import { apiClient, type ApiSessionResponse, ApiError } from '../api/client';

interface LoginModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: (session: ApiSessionResponse) => void;
}

export const LoginModal: React.FC<LoginModalProps> = ({
  isOpen,
  onClose,
  onSuccess,
}) => {
  const [adminKey, setAdminKey] = useState('');
  const [tenantId, setTenantId] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [showTenantInput, setShowTenantInput] = useState(false);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage(null);

    const trimmedKey = adminKey.trim();
    if (!trimmedKey) {
      setErrorMessage('Administrative key is required.');
      return;
    }

    setIsLoading(true);
    try {
      const payload: { admin_key: string; tenant_id?: string } = { admin_key: trimmedKey };
      if (tenantId.trim()) {
        payload.tenant_id = tenantId.trim();
      }

      const res = await apiClient.login(payload);
      if (res && res.authenticated) {
        setAdminKey('');
        setTenantId('');
        onSuccess(res);
      } else {
        setErrorMessage('Authentication was not completed by the server.');
      }
    } catch (err: unknown) {
      if (err instanceof ApiError) {
        if (err.status === 401) {
          setErrorMessage('Invalid administrative credentials. Please verify your admin key.');
        } else if (err.status === 403) {
          setErrorMessage(
            err.message || 'Access forbidden: Admin authentication is disabled or restricted.'
          );
        } else {
          setErrorMessage(err.message || 'Authentication failed. Please check server logs.');
        }
      } else {
        setErrorMessage('Network error connecting to AgentShield authentication service.');
      }
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm animate-in fade-in duration-150">
      <div
        className="relative w-full max-w-md p-6 bg-[#181636] border border-[#40387d] rounded-2xl shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Close Button */}
        <button
          onClick={onClose}
          disabled={isLoading}
          className="absolute top-4 right-4 p-1 text-[#8b84bd] hover:text-white transition-colors disabled:opacity-50 cursor-pointer"
          aria-label="Close login dialog"
        >
          <X size={18} />
        </button>

        {/* Header with PixelShieldIcon */}
        <div className="flex items-center gap-3 mb-4">
          <div className="flex-shrink-0 drop-shadow-[0_0_8px_rgba(112,62,232,0.4)]">
            <PixelShieldIcon size={34} />
          </div>
          <div>
            <h3 className="text-base font-bold text-white tracking-tight flex items-center gap-1.5 font-mono">
              Admin Authentication
            </h3>
            <span className="text-xs text-[#958ec4]">
              Unlock AgentShield runtime policy & review controls
            </span>
          </div>
        </div>

        {/* Security Notice */}
        <div className="mb-4 p-3 bg-[#1e1a3f] rounded-xl border border-[#312a5e] text-xs text-[#b8b3e2] leading-relaxed">
          <p className="flex items-center gap-1.5 font-medium text-white mb-1">
            <Lock size={13} className="text-[#c084fc]" />
            Session Authentication
          </p>
          <p className="text-[11px] text-[#9c96c9]">
            Administrative requests require signed HTTP-only cookies and double-submit CSRF verification.
            Keys are never stored in browser local storage.
          </p>
        </div>

        {/* Error Alert */}
        {errorMessage && (
          <div className="mb-4 p-2.5 bg-[#4a1c25]/90 border border-[#782836] rounded-xl text-xs text-[#f87171] font-mono flex items-start gap-2 shadow-sm animate-in fade-in duration-100">
            <AlertCircle size={15} className="flex-shrink-0 mt-0.5 text-[#f87171]" />
            <span className="leading-tight">{errorMessage}</span>
          </div>
        )}

        {/* Login Form */}
        <form onSubmit={handleSubmit} className="flex flex-col gap-3.5">
          <div>
            <label className="text-[11px] font-semibold text-[#8b84bd] block mb-1 uppercase tracking-wider flex items-center justify-between">
              <span className="flex items-center gap-1.5">
                <Key size={12} className="text-[#a29bcf]" />
                Administrative Key
              </span>
              <span className="text-[10px] font-normal text-[#6f6999] normal-case">
                AGENTSHIELD_ADMIN_KEY
              </span>
            </label>
            <input
              type="password"
              value={adminKey}
              onChange={(e) => setAdminKey(e.target.value)}
              placeholder="Paste administrative secret key..."
              disabled={isLoading}
              autoFocus
              className="w-full px-3 py-2.5 bg-[#121029] border border-[#372f6a] rounded-xl text-xs text-white placeholder-[#6f6999] focus:outline-none focus:border-[#6d3ee8] disabled:opacity-50 font-mono transition-colors"
            />
          </div>

          {/* Optional Tenant ID Toggle */}
          <div>
            <button
              type="button"
              onClick={() => setShowTenantInput(!showTenantInput)}
              className="text-[11px] text-[#8b84bd] hover:text-[#c4bbf0] transition-colors underline cursor-pointer"
            >
              {showTenantInput ? 'Hide Workspace / Tenant ID' : '+ Specify Tenant / Workspace ID (Optional)'}
            </button>
            {showTenantInput && (
              <div className="mt-2 animate-in fade-in duration-100">
                <input
                  type="text"
                  value={tenantId}
                  onChange={(e) => setTenantId(e.target.value)}
                  placeholder="default or custom workspace slug..."
                  disabled={isLoading}
                  className="w-full px-3 py-2 bg-[#121029] border border-[#372f6a] rounded-xl text-xs text-white placeholder-[#6f6999] focus:outline-none focus:border-[#6d3ee8] disabled:opacity-50 font-mono"
                />
              </div>
            )}
          </div>

          {/* Form Actions */}
          <div className="flex items-center justify-end gap-2.5 mt-2 pt-3 border-t border-[#25204c]">
            <button
              type="button"
              onClick={onClose}
              disabled={isLoading}
              className="px-4 py-2 text-xs font-semibold text-[#8b84bd] hover:text-white bg-[#221e45] hover:bg-[#2c2759] border border-[#3b3370] rounded-xl transition-colors disabled:opacity-50 cursor-pointer"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isLoading}
              className="px-5 py-2 text-xs font-semibold text-white bg-[#6d3ee8] hover:bg-[#7e50f5] rounded-xl transition-all shadow-[0_2px_10px_rgba(109,62,232,0.4)] disabled:opacity-50 flex items-center gap-1.5 cursor-pointer"
            >
              {isLoading ? (
                <>
                  <Loader2 size={14} className="animate-spin" />
                  <span>Authenticating...</span>
                </>
              ) : (
                <>
                  <CheckCircle2 size={14} />
                  <span>Authenticate</span>
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

