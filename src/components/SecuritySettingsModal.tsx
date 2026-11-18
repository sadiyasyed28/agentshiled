import React, { useState, useEffect, useCallback } from 'react';
import {
  X,
  Shield,
  Key,
  Server,
  AlertTriangle,
  Check,
  Copy,
  Plus,
  RefreshCw,
  Trash2,
  Lock,
  Cpu,
  LogIn,
  Sliders,
} from 'lucide-react';
import {
  apiClient,
  type ApiKeyItem,
  type ApiRuntimeConfigResponse,
  type ApiSessionResponse,
  ApiError,
} from '../api/client';

interface SecuritySettingsModalProps {
  isOpen: boolean;
  onClose: () => void;
  session: ApiSessionResponse | null;
  onOpenLogin?: () => void;
}

export const SecuritySettingsModal: React.FC<SecuritySettingsModalProps> = ({
  isOpen,
  onClose,
  session,
  onOpenLogin,
}) => {
  const [activeTab, setActiveTab] = useState<'config' | 'apikeys'>('config');

  // Runtime config state
  const [config, setConfig] = useState<ApiRuntimeConfigResponse | null>(null);
  const [isLoadingConfig, setIsLoadingConfig] = useState(false);
  const [configError, setConfigError] = useState<string | null>(null);

  // API keys state
  const [apiKeys, setApiKeys] = useState<ApiKeyItem[]>([]);
  const [isLoadingKeys, setIsLoadingKeys] = useState(false);
  const [keysError, setKeysError] = useState<string | null>(null);

  // Key creation state
  const [isCreatingKey, setIsCreatingKey] = useState(false);
  const [newKeyName, setNewKeyName] = useState('');
  const [newKeyPrefix, setNewKeyPrefix] = useState('agnt');
  const [isSubmittingNewKey, setIsSubmittingNewKey] = useState(false);
  const [createKeyError, setCreateKeyError] = useState<string | null>(null);

  // One-time newly generated plaintext key display (NEVER persisted in storage)
  const [newlyGeneratedSecret, setNewlyGeneratedSecret] = useState<{
    name: string;
    key: string;
    action: 'created' | 'rotated';
  } | null>(null);
  const [copiedSecret, setCopiedSecret] = useState(false);

  // Key action pending states
  const [rotatingKeyId, setRotatingKeyId] = useState<string | null>(null);
  const [revokingKeyId, setRevokingKeyId] = useState<string | null>(null);
  const [keyToRevoke, setKeyToRevoke] = useState<ApiKeyItem | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  const fetchConfiguration = useCallback(async () => {
    setIsLoadingConfig(true);
    setConfigError(null);
    try {
      const res = await apiClient.getRuntimeConfig();
      setConfig(res);
    } catch (err: unknown) {
      if (err instanceof ApiError) {
        if (err.status === 403) {
          setConfigError('Global administrator privileges required to view full runtime configuration.');
        } else if (err.status === 401) {
          setConfigError('Authentication required to access runtime security settings.');
        } else {
          setConfigError(`Failed to load configuration (${err.status}): ${err.message}`);
        }
      } else {
        setConfigError('Unable to connect to runtime configuration endpoint.');
      }
    } finally {
      setIsLoadingConfig(false);
    }
  }, []);

  const fetchApiKeys = useCallback(async () => {
    setIsLoadingKeys(true);
    setKeysError(null);
    try {
      const res = await apiClient.getApiKeys();
      if (res && Array.isArray(res.keys)) {
        setApiKeys(res.keys);
      } else {
        setApiKeys([]);
      }
    } catch (err: unknown) {
      if (err instanceof ApiError) {
        if (err.status === 403) {
          setKeysError('Administrator role required to manage API keys.');
        } else if (err.status === 401) {
          setKeysError('Authentication required to list API keys. Please sign in as an administrator.');
        } else {
          setKeysError(`Failed to load API keys (${err.status}): ${err.message}`);
        }
      } else {
        setKeysError('Unable to connect to API keys service.');
      }
    } finally {
      setIsLoadingKeys(false);
    }
  }, []);

  useEffect(() => {
    if (isOpen) {
      fetchConfiguration();
      fetchApiKeys();
    } else {
      // Clear sensitive state when modal is closed
      setNewlyGeneratedSecret(null);
      setKeyToRevoke(null);
      setActionError(null);
      setCreateKeyError(null);
    }
  }, [isOpen, fetchConfiguration, fetchApiKeys]);

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

  const handleCreateKey = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newKeyName.trim()) {
      setCreateKeyError('Key description/name is required');
      return;
    }

    setIsSubmittingNewKey(true);
    setCreateKeyError(null);
    setActionError(null);

    try {
      const res = await apiClient.createApiKey({
        name: newKeyName.trim(),
        prefix: newKeyPrefix.trim() || undefined,
      });

      // Display newly generated secret ONLY ONCE in component state
      setNewlyGeneratedSecret({
        name: res.name,
        key: res.api_key,
        action: 'created',
      });
      setIsCreatingKey(false);
      setNewKeyName('');
      await fetchApiKeys();
    } catch (err: unknown) {
      if (err instanceof ApiError) {
        if (err.status === 403) {
          setCreateKeyError('Operation Blocked (403): Read-only mode or insufficient privileges prevent creating API keys.');
        } else if (err.status === 401) {
          setCreateKeyError('Session expired. Please sign in again.');
        } else {
          setCreateKeyError(`Failed to create API key (${err.status}): ${err.message}`);
        }
      } else {
        setCreateKeyError('Failed to generate API key. Network or server error.');
      }
    } finally {
      setIsSubmittingNewKey(false);
    }
  };

  const handleRotateKey = async (key: ApiKeyItem) => {
    setRotatingKeyId(key.key_id);
    setActionError(null);
    try {
      const res = await apiClient.rotateApiKey(key.key_id);
      // Display newly rotated secret ONLY ONCE in component state
      setNewlyGeneratedSecret({
        name: res.name,
        key: res.api_key,
        action: 'rotated',
      });
      await fetchApiKeys();
    } catch (err: unknown) {
      if (err instanceof ApiError) {
        if (err.status === 403) {
          setActionError('Operation Blocked (403): Read-only mode or insufficient privileges prevent rotating API keys.');
        } else if (err.status === 401) {
          setActionError('Session expired. Please sign in again.');
        } else {
          setActionError(`Failed to rotate key (${err.status}): ${err.message}`);
        }
      } else {
        setActionError('Failed to rotate API key.');
      }
    } finally {
      setRotatingKeyId(null);
    }
  };

  const handleConfirmRevoke = async () => {
    if (!keyToRevoke) return;

    setRevokingKeyId(keyToRevoke.key_id);
    setActionError(null);
    try {
      await apiClient.revokeApiKey(keyToRevoke.key_id);
      setKeyToRevoke(null);
      await fetchApiKeys();
    } catch (err: unknown) {
      if (err instanceof ApiError) {
        if (err.status === 403) {
          setActionError('Operation Blocked (403): Read-only mode or insufficient privileges prevent revoking API keys.');
        } else if (err.status === 401) {
          setActionError('Session expired. Please sign in again.');
        } else {
          setActionError(`Failed to revoke key (${err.status}): ${err.message}`);
        }
      } else {
        setActionError('Failed to revoke API key.');
      }
    } finally {
      setRevokingKeyId(null);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedSecret(true);
    setTimeout(() => setCopiedSecret(false), 2000);
  };

  if (!isOpen) return null;

  const isReadOnly = Boolean(config?.read_only ?? session?.read_only);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="relative w-full max-w-2xl bg-[#141226] border-2 border-[#3d3478] rounded-2xl shadow-2xl p-5 sm:p-6 overflow-hidden max-h-[90vh] flex flex-col">
        {/* Top Header */}
        <div className="flex items-center justify-between pb-3.5 border-b border-[#2b2559]">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-[#261f52] border border-[#3e3478] flex items-center justify-center text-[#c084fc] flex-shrink-0 shadow-sm">
              <Shield size={22} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-base font-bold text-white tracking-tight font-mono">
                  Security Settings
                </h3>
                {isReadOnly && (
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-[#403413] text-[#facc15] border border-[#6b551c]">
                    READ-ONLY MODE
                  </span>
                )}
              </div>
              <p className="text-[11.5px] text-[#958ec4] mt-0.5">
                Runtime security configuration, engine thresholds & API key management
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="w-8 h-8 rounded-lg bg-[#1f1b3d] hover:bg-[#2b2559] border border-[#3b3273] text-[#9a94cb] hover:text-white flex items-center justify-center transition-colors cursor-pointer"
          >
            <X size={16} />
          </button>
        </div>

        {/* Tab Selector */}
        <div className="flex items-center gap-2 pt-3 pb-2">
          <button
            onClick={() => setActiveTab('config')}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors cursor-pointer ${
              activeTab === 'config'
                ? 'bg-[#6d3ee8] text-white shadow-sm'
                : 'text-[#9c96c9] hover:bg-[#1f1a42] hover:text-white'
            }`}
          >
            <Server size={14} />
            <span>Runtime Configuration</span>
          </button>
          <button
            onClick={() => setActiveTab('apikeys')}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors cursor-pointer ${
              activeTab === 'apikeys'
                ? 'bg-[#6d3ee8] text-white shadow-sm'
                : 'text-[#9c96c9] hover:bg-[#1f1a42] hover:text-white'
            }`}
          >
            <Key size={14} />
            <span>API Key Management</span>
            {apiKeys.length > 0 && (
              <span className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-black/40 text-[#c084fc]">
                {apiKeys.length}
              </span>
            )}
          </button>
        </div>

        {/* Modal Scrollable Body */}
        <div className="flex-1 overflow-y-auto space-y-4 py-2 pr-1">
          {/* Read-Only Notice Banner */}
          {isReadOnly && (
            <div className="p-3 bg-[#403413]/70 border border-[#6b551c] rounded-xl text-xs font-mono text-[#fde047] flex items-start gap-2.5">
              <Lock size={15} className="flex-shrink-0 mt-0.5 text-[#facc15]" />
              <div className="leading-relaxed">
                <span className="font-bold">Engine Operating in Read-Only Mode:</span> All mutations (creating or rotating keys, policy modifications, containment pauses) are deterministically rejected by the FastAPI runtime.
              </div>
            </div>
          )}

          {/* Action error banner */}
          {actionError && (
            <div className="p-3 bg-[#4a1c25] border border-[#ef4444] rounded-xl text-xs font-mono text-[#fca5a5] flex items-start justify-between gap-2">
              <div className="flex items-start gap-2">
                <AlertTriangle size={15} className="flex-shrink-0 mt-0.5 text-[#ef4444]" />
                <span>{actionError}</span>
              </div>
              <button
                onClick={() => setActionError(null)}
                className="text-white hover:underline text-[10px]"
              >
                Dismiss
              </button>
            </div>
          )}

          {/* Newly Generated Plaintext Secret Banner (ONLY displayed once, never saved in storage) */}
          {newlyGeneratedSecret && (
            <div className="p-4 bg-[#18392b] border-2 border-[#22c55e] rounded-xl text-xs font-mono space-y-2.5 shadow-lg animate-in zoom-in-95">
              <div className="flex items-center justify-between text-[#4ade80]">
                <span className="font-bold flex items-center gap-2">
                  <Check size={16} /> Key Successfully {newlyGeneratedSecret.action === 'created' ? 'Created' : 'Rotated'}: {newlyGeneratedSecret.name}
                </span>
                <span className="text-[10px] uppercase tracking-wider font-bold bg-[#14532d] px-2 py-0.5 rounded border border-[#22c55e]">
                  Show Once
                </span>
              </div>
              <p className="text-[11px] text-[#bbf7d0]">
                Copy this API key now. It will <strong className="text-white underline">never</strong> be displayed again or stored in plaintext:
              </p>
              <div className="flex items-center gap-2 bg-[#0d2217] p-2.5 rounded-lg border border-[#166534]">
                <code className="text-[#86efac] font-bold select-all flex-1 break-all">
                  {newlyGeneratedSecret.key}
                </code>
                <button
                  onClick={() => copyToClipboard(newlyGeneratedSecret.key)}
                  className="px-3 py-1.5 bg-[#22c55e] hover:bg-[#16a34a] text-black font-bold rounded text-xs flex items-center gap-1.5 cursor-pointer transition-colors shadow-sm"
                >
                  {copiedSecret ? <Check size={13} /> : <Copy size={13} />}
                  <span>{copiedSecret ? 'Copied' : 'Copy'}</span>
                </button>
              </div>
              <div className="flex justify-end pt-1">
                <button
                  onClick={() => setNewlyGeneratedSecret(null)}
                  className="px-3 py-1 bg-black/40 hover:bg-black/60 border border-white/20 rounded text-[11px] text-white cursor-pointer"
                >
                  I Have Safely Saved This Key
                </button>
              </div>
            </div>
          )}

          {/* Confirmation Dialog for Revocation */}
          {keyToRevoke && (
            <div className="p-4 bg-[#4a1c25] border-2 border-[#ef4444] rounded-xl text-xs font-mono space-y-2.5 shadow-lg">
              <div className="font-bold text-[#fca5a5] flex items-center gap-2">
                <AlertTriangle size={16} className="text-[#ef4444]" />
                Confirm Immediate Key Revocation
              </div>
              <p className="text-[11.5px] text-[#fecaca] leading-relaxed">
                Are you sure you want to revoke API key <strong>"{keyToRevoke.name}"</strong> (<code className="text-white">{keyToRevoke.masked_key}</code>)?
                Any AI agent or tool currently utilizing this key will be permanently denied authorization.
              </p>
              <div className="flex items-center justify-end gap-2 pt-2">
                <button
                  onClick={() => setKeyToRevoke(null)}
                  className="px-3 py-1.5 bg-[#25204c] hover:bg-[#342d6a] text-white rounded-lg text-xs font-semibold cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  onClick={handleConfirmRevoke}
                  disabled={revokingKeyId !== null}
                  className="px-3.5 py-1.5 bg-[#ef4444] hover:bg-[#dc2626] text-white font-bold rounded-lg text-xs flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
                >
                  <Trash2 size={13} />
                  <span>{revokingKeyId ? 'Revoking...' : 'Confirm Revoke'}</span>
                </button>
              </div>
            </div>
          )}

          {/* TAB 1: RUNTIME CONFIGURATION */}
          {activeTab === 'config' && (
            <div className="space-y-3.5">
              {configError ? (
                <div className="p-3.5 bg-[#401a24] border border-[#f87171] rounded-xl text-xs font-mono text-[#fca5a5] space-y-2">
                  <div className="font-bold flex items-center gap-2 text-[#f87171]">
                    <AlertTriangle size={15} /> Runtime Configuration Unavailable
                  </div>
                  <p className="text-[11px]">{configError}</p>
                  {!session?.authenticated && onOpenLogin && (
                    <button
                      onClick={() => {
                        onClose();
                        onOpenLogin();
                      }}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-[#6d3ee8] hover:bg-[#5b32c7] text-white font-bold rounded-lg text-xs cursor-pointer mt-1"
                    >
                      <LogIn size={13} /> Sign In as Administrator
                    </button>
                  )}
                </div>
              ) : isLoadingConfig ? (
                <div className="p-8 text-center text-xs font-mono text-[#958ec4] animate-pulse">
                  Querying runtime security configuration from AgentShield backend...
                </div>
              ) : config ? (
                <div className="space-y-3 text-xs font-mono">
                  {/* Grid 1: Basic Runtime Info */}
                  <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
                    <div className="p-2.5 bg-[#1b1739] rounded-xl border border-[#2e265c]">
                      <span className="text-[10px] text-[#8680b5] block uppercase font-bold">Environment</span>
                      <span className="font-bold text-white mt-0.5 block capitalize">
                        {config.environment}
                      </span>
                    </div>
                    <div className="p-2.5 bg-[#1b1739] rounded-xl border border-[#2e265c]">
                      <span className="text-[10px] text-[#8680b5] block uppercase font-bold">Operating Mode</span>
                      <span
                        className={`font-bold mt-0.5 block ${
                          config.read_only ? 'text-[#facc15]' : 'text-[#4ade80]'
                        }`}
                      >
                        {config.read_only ? 'Read-Only' : 'Active Mutation'}
                      </span>
                    </div>
                    <div className="p-2.5 bg-[#1b1739] rounded-xl border border-[#2e265c]">
                      <span className="text-[10px] text-[#8680b5] block uppercase font-bold">Storage Backend</span>
                      <span className="font-bold text-[#c084fc] mt-0.5 block">
                        {config.storage_backend}
                      </span>
                    </div>
                  </div>

                  {/* Policy Engine & Analyst Provider */}
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                    <div className="p-3 bg-[#1b1739] rounded-xl border border-[#2e265c]">
                      <div className="flex items-center gap-1.5 text-[#8680b5] text-[10.5px] uppercase font-bold mb-1">
                        <Cpu size={13} className="text-[#c084fc]" />
                        <span>Analyst Provider</span>
                      </div>
                      <div className="text-white font-semibold">
                        {config.analyst_provider} {config.analyst_model ? `(${config.analyst_model})` : ''}
                      </div>
                      <div className="text-[10.5px] text-[#8680b5] mt-1">
                        Mock fallback enabled: <strong className="text-white">{config.mock_fallback_enabled ? 'Yes' : 'No'}</strong>
                      </div>
                    </div>

                    <div className="p-3 bg-[#1b1739] rounded-xl border border-[#2e265c]">
                      <div className="flex items-center gap-1.5 text-[#8680b5] text-[10.5px] uppercase font-bold mb-1">
                        <Shield size={13} className="text-[#3ddc97]" />
                        <span>Policy Engine Version Hash</span>
                      </div>
                      <div className="text-[#3ddc97] font-bold truncate select-all" title={config.policy_version_hash}>
                        {config.policy_version_hash || 'SHA-256 Engine v1'}
                      </div>
                      <div className="text-[10.5px] text-[#8680b5] mt-1">
                        Database connection: <strong className="text-white">{config.database_configured ? 'Configured' : 'In-Memory / Local'}</strong>
                      </div>
                    </div>
                  </div>

                  {/* Circuit Breaker & Safety Thresholds */}
                  <div className="p-3 bg-[#1b1739] rounded-xl border border-[#2e265c]">
                    <div className="flex items-center gap-1.5 text-[#8680b5] text-[10.5px] uppercase font-bold mb-2">
                      <Sliders size={13} className="text-[#facc15]" />
                      <span>Runtime Safety Limits & Circuit Breaker</span>
                    </div>
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[11px]">
                      <div>
                        <span className="text-[#8680b5] block">Failure Threshold:</span>
                        <span className="font-semibold text-white">
                          {config.circuit_breaker_failure_threshold ?? 5} consecutive
                        </span>
                      </div>
                      <div>
                        <span className="text-[#8680b5] block">Recovery Timeout:</span>
                        <span className="font-semibold text-white">
                          {config.circuit_breaker_recovery_timeout ?? 30}s
                        </span>
                      </div>
                      <div>
                        <span className="text-[#8680b5] block">Max Execution:</span>
                        <span className="font-semibold text-white">
                          {config.max_tool_execution_seconds ?? 30}s
                        </span>
                      </div>
                      <div>
                        <span className="text-[#8680b5] block">Max Body Size:</span>
                        <span className="font-semibold text-white">
                          {config.max_body_bytes ? `${Math.round(config.max_body_bytes / 1024)} KB` : '1024 KB'}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>
              ) : null}
            </div>
          )}

          {/* TAB 2: API KEY MANAGEMENT */}
          {activeTab === 'apikeys' && (
            <div className="space-y-3.5">
              {keysError ? (
                <div className="p-3.5 bg-[#401a24] border border-[#f87171] rounded-xl text-xs font-mono text-[#fca5a5] space-y-2">
                  <div className="font-bold flex items-center gap-2 text-[#f87171]">
                    <AlertTriangle size={15} /> Unable to Access API Keys
                  </div>
                  <p className="text-[11px]">{keysError}</p>
                  {!session?.authenticated && onOpenLogin && (
                    <button
                      onClick={() => {
                        onClose();
                        onOpenLogin();
                      }}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-[#6d3ee8] hover:bg-[#5b32c7] text-white font-bold rounded-lg text-xs cursor-pointer mt-1"
                    >
                      <LogIn size={13} /> Sign In as Administrator
                    </button>
                  )}
                </div>
              ) : (
                <>
                  {/* Action Bar */}
                  <div className="flex items-center justify-between flex-wrap gap-2">
                    <span className="text-xs font-mono text-[#958ec4]">
                      {isLoadingKeys
                        ? 'Loading keys...'
                        : `${apiKeys.length} active agent credential${apiKeys.length === 1 ? '' : 's'}`}
                    </span>
                    <button
                      onClick={() => {
                        setIsCreatingKey(!isCreatingKey);
                        setCreateKeyError(null);
                      }}
                      disabled={isReadOnly}
                      className="flex items-center gap-1.5 px-3 py-1.5 bg-[#6d3ee8] hover:bg-[#5b32c7] text-white text-xs font-bold rounded-lg transition-colors shadow-sm disabled:opacity-50 cursor-pointer"
                    >
                      <Plus size={14} />
                      <span>Generate New Key</span>
                    </button>
                  </div>

                  {/* Key Creation Form */}
                  {isCreatingKey && (
                    <form
                      onSubmit={handleCreateKey}
                      className="p-3.5 bg-[#1b1739] border border-[#3e3478] rounded-xl space-y-3 font-mono text-xs animate-in fade-in"
                    >
                      <div className="font-bold text-white flex items-center gap-2">
                        <Key size={14} className="text-[#c084fc]" />
                        Generate Agent API Key
                      </div>
                      <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                        <div className="sm:col-span-2 space-y-1">
                          <label className="text-[11px] text-[#958ec4] block">Key Description / Name *</label>
                          <input
                            type="text"
                            value={newKeyName}
                            onChange={(e) => setNewKeyName(e.target.value)}
                            placeholder="e.g. Production Data Extraction Agent"
                            required
                            className="w-full px-3 py-1.5 bg-[#121024] border border-[#372f6b] rounded-lg text-white text-xs focus:outline-none focus:border-[#6d3ee8]"
                          />
                        </div>
                        <div className="space-y-1">
                          <label className="text-[11px] text-[#958ec4] block">Prefix</label>
                          <input
                            type="text"
                            value={newKeyPrefix}
                            onChange={(e) => setNewKeyPrefix(e.target.value)}
                            placeholder="agnt"
                            className="w-full px-3 py-1.5 bg-[#121024] border border-[#372f6b] rounded-lg text-white text-xs focus:outline-none focus:border-[#6d3ee8]"
                          />
                        </div>
                      </div>
                      {createKeyError && (
                        <p className="text-[11px] text-[#f87171]">{createKeyError}</p>
                      )}
                      <div className="flex items-center justify-end gap-2 pt-1">
                        <button
                          type="button"
                          onClick={() => setIsCreatingKey(false)}
                          className="px-3 py-1 bg-[#25204c] hover:bg-[#342d6a] text-white rounded text-xs cursor-pointer"
                        >
                          Cancel
                        </button>
                        <button
                          type="submit"
                          disabled={isSubmittingNewKey}
                          className="px-3 py-1 bg-[#22c55e] hover:bg-[#16a34a] text-black font-bold rounded text-xs cursor-pointer disabled:opacity-50"
                        >
                          {isSubmittingNewKey ? 'Generating...' : 'Confirm Generate'}
                        </button>
                      </div>
                    </form>
                  )}

                  {/* Keys Table / List */}
                  {apiKeys.length === 0 && !isLoadingKeys ? (
                    <div className="p-6 bg-[#181632] border border-[#2c2656] rounded-xl text-center font-mono text-xs text-[#8c85be]">
                      No API keys currently provisioned for this tenant.
                    </div>
                  ) : (
                    <div className="space-y-2">
                      {apiKeys.map((k) => (
                        <div
                          key={k.key_id}
                          className="p-3 bg-[#1b1739] border border-[#2e265c] hover:border-[#4c3f8e] rounded-xl flex items-center justify-between gap-3 text-xs font-mono transition-colors"
                        >
                          <div className="space-y-0.5 min-w-0">
                            <div className="flex items-center gap-2">
                              <span className="font-bold text-white truncate">{k.name}</span>
                              <span className="px-1.5 py-0.2 rounded text-[9.5px] bg-[#143d26] text-[#4ade80] border border-[#1b6d39]">
                                Active
                              </span>
                            </div>
                            <div className="text-[11px] text-[#8680b5] flex items-center gap-3">
                              <span>Masked: <code className="text-[#c084fc]">{k.masked_key}</code></span>
                              {k.created_at && (
                                <span>Created: {new Date(k.created_at * 1000).toLocaleDateString()}</span>
                              )}
                            </div>
                          </div>

                          <div className="flex items-center gap-2 flex-shrink-0">
                            <button
                              onClick={() => handleRotateKey(k)}
                              disabled={isReadOnly || rotatingKeyId === k.key_id}
                              title="Rotate key (revokes current credential and issues new secret)"
                              className="px-2.5 py-1 bg-[#241f4a] hover:bg-[#322c66] text-[#c084fc] hover:text-white border border-[#3e3478] rounded-lg text-[11px] font-semibold flex items-center gap-1.5 transition-colors disabled:opacity-40 cursor-pointer"
                            >
                              <RefreshCw size={12} className={rotatingKeyId === k.key_id ? 'animate-spin' : ''} />
                              <span>{rotatingKeyId === k.key_id ? 'Rotating...' : 'Rotate'}</span>
                            </button>
                            <button
                              onClick={() => setKeyToRevoke(k)}
                              disabled={isReadOnly}
                              title="Revoke key immediately"
                              className="p-1.5 bg-[#3a1820] hover:bg-[#521e2a] text-[#f87171] hover:text-white border border-[#6b2533] rounded-lg transition-colors disabled:opacity-40 cursor-pointer"
                            >
                              <Trash2 size={13} />
                            </button>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </>
              )}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="pt-3 border-t border-[#2b2559] flex items-center justify-between text-[11px] font-mono text-[#8d87bc]">
          <span>AgentShield Core Security Architecture</span>
          <button
            onClick={onClose}
            className="px-3 py-1 bg-[#231f47] hover:bg-[#312b63] border border-[#3e3578] rounded-lg text-white font-semibold cursor-pointer"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};

