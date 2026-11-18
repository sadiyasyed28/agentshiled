import React, { useState } from 'react';
import { Search, Bell, ChevronDown, Menu, Shield, CheckCircle, AlertTriangle, X, PanelLeftClose, PanelLeftOpen, LogIn, LogOut, Lock, Activity, XCircle } from 'lucide-react';
import { PixelAvatar } from './pixel/PixelAvatar';
import type { ApiSessionResponse } from '../api/client';
import type { HealthStatusType } from './SystemHealthModal';
import type { SecurityNotificationItem } from '../types';

interface TopNavigationProps {
  title?: string;
  onOpenSearch: () => void;
  onToggleMobileMenu: () => void;
  isCollapsed?: boolean;
  onToggleCollapse?: () => void;
  session?: ApiSessionResponse | null;
  onOpenLogin?: () => void;
  onLogout?: () => void;
  onOpenSecuritySettings?: () => void;
  healthStatus?: HealthStatusType;
  onOpenHealth?: () => void;
  notifications?: SecurityNotificationItem[];
  onSelectNotification?: (item: SecurityNotificationItem) => void;
}

export const TopNavigation: React.FC<TopNavigationProps> = ({
  title = 'Overview',
  onOpenSearch,
  onToggleMobileMenu,
  isCollapsed = false,
  onToggleCollapse,
  session,
  onOpenLogin,
  onLogout,
  onOpenSecuritySettings,
  healthStatus = 'Loading',
  onOpenHealth,
  notifications = [],
  onSelectNotification,
}) => {
  const [adminMenuOpen, setAdminMenuOpen] = useState(false);
  const [notificationsOpen, setNotificationsOpen] = useState(false);

  const isAuthenticated = Boolean(session?.authenticated);
  const userRole = session?.role === 'global_admin'
    ? 'Global Administrator'
    : session?.role === 'tenant_admin'
    ? 'Tenant Administrator'
    : 'Guest (Read-Only)';
  const userLabel = isAuthenticated
    ? (session?.role === 'global_admin' ? 'Admin' : (session?.tenant_id || 'Tenant Admin'))
    : 'Sign In';

  return (
    <header className="relative z-30 flex items-center justify-between h-[68px] px-6 bg-[#121124] border-b border-[#2e285a]">
      {/* LEFT: TITLE, TOGGLE, & DECORATIVE PIXEL CLOUDS */}
      <div className="flex items-center gap-3">
        {/* Mobile Hamburger */}
        <button
          onClick={onToggleMobileMenu}
          className="p-1.5 text-[#9892c5] hover:text-white rounded-lg hover:bg-[#1f1c3d] lg:hidden"
        >
          <Menu size={22} />
        </button>

        {/* Desktop Sidebar Collapse Toggle */}
        {onToggleCollapse && (
          <button
            onClick={onToggleCollapse}
            title={isCollapsed ? "Expand sidebar" : "Collapse sidebar"}
            className="hidden lg:flex items-center justify-center p-1.5 text-[#9892c5] hover:text-white rounded-lg hover:bg-[#1f1c3d] transition-colors"
          >
            {isCollapsed ? <PanelLeftOpen size={18} /> : <PanelLeftClose size={18} />}
          </button>
        )}

        <div className="relative flex items-center">
          <h1 className="text-xl font-bold tracking-tight text-white relative z-10">
            {title}
          </h1>

          {/* Decorative pixel clouds floating behind title */}
          <div className="absolute -top-1 left-24 pointer-events-none select-none opacity-60">
            <svg width="64" height="20" viewBox="0 0 64 20" fill="none" className="pixelated" shapeRendering="crispEdges">
              <rect x="16" y="2" width="28" height="5" fill="#3a3266" />
              <rect x="8" y="7" width="44" height="6" fill="#3a3266" />
              <rect x="2" y="13" width="56" height="5" fill="#2d2752" />
              <rect x="18" y="4" width="20" height="3" fill="#4d4285" />
            </svg>
          </div>
        </div>
      </div>

      {/* RIGHT: SEARCH, NOTIFICATIONS, ADMIN PROFILE */}
      <div className="flex items-center gap-3.5">
        {/* Global Search Bar */}
        <button
          onClick={onOpenSearch}
          className="flex items-center justify-between w-64 md:w-80 h-9 px-3 bg-[#191733] border border-[#342d63] rounded-xl text-xs text-[#8780b8] hover:border-[#52479e] transition-all shadow-inner group"
        >
          <div className="flex items-center gap-2 overflow-hidden text-ellipsis whitespace-nowrap">
            <Search size={14} className="text-[#8780b8] group-hover:text-[#c4bbf0] transition-colors" />
            <span className="text-[12.5px] text-[#7d77a8] group-hover:text-[#aba4db] transition-colors">
              Search events, agents, policies...
            </span>
          </div>
          <kbd className="hidden sm:inline-flex items-center px-1.5 py-0.5 text-[10.5px] font-mono font-medium text-[#9a94cb] bg-[#242047] border border-[#3c3475] rounded-md shadow-xs">
            ⌘ K
          </kbd>
        </button>

        {/* Notification Bell */}
        <div className="relative">
          <button
            onClick={() => {
              setNotificationsOpen(!notificationsOpen);
              setAdminMenuOpen(false);
            }}
            className="relative flex items-center justify-center w-9 h-9 bg-[#191733] border border-[#342d63] rounded-xl text-[#9c96c9] hover:text-white hover:border-[#52479e] transition-colors shadow-sm cursor-pointer"
            title={notifications.length > 0 ? `${notifications.length} unread security alert${notifications.length === 1 ? '' : 's'}` : 'Security Alerts (None)'}
          >
            <Bell size={16} />
            {/* Honest notification badge: only shown when real notifications exist */}
            {notifications.length > 0 && (
              <span className="absolute top-1.5 right-1.5 flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-[#ef4444] ring-2 ring-[#121124]"></span>
              </span>
            )}
          </button>

          {/* Notification Popover */}
          {notificationsOpen && (
            <div className="absolute right-0 mt-2 w-80 p-3 bg-[#181634] border border-[#3e3678] rounded-2xl shadow-2xl z-50 animate-in fade-in slide-in-from-top-2 duration-150">
              <div className="flex items-center justify-between pb-2 border-b border-[#282352]">
                <div className="flex items-center gap-1.5">
                  <span className="text-xs font-bold text-white tracking-wide uppercase">Security Alerts</span>
                  {notifications.length > 0 && (
                    <span className="px-1.5 py-0.2 rounded text-[10px] font-mono font-bold bg-[#4a1c25] text-[#f87171] border border-[#782836]">
                      {notifications.length}
                    </span>
                  )}
                </div>
                <button
                  onClick={() => setNotificationsOpen(false)}
                  className="text-[#8881b8] hover:text-white cursor-pointer"
                >
                  <X size={14} />
                </button>
              </div>

              <div className="flex flex-col gap-2 mt-2 max-h-64 overflow-y-auto">
                {notifications.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-6 text-center text-xs">
                    <div className="w-8 h-8 rounded-full bg-[#153e28] text-[#4ade80] flex items-center justify-center mb-2 shadow-xs">
                      <CheckCircle size={18} />
                    </div>
                    <span className="font-semibold text-white">No Security Alerts</span>
                    <span className="text-[11px] text-[#8680b5] mt-1 max-w-[220px]">
                      All monitored agent operations are within normal security parameters.
                    </span>
                  </div>
                ) : (
                  notifications.map((item) => (
                    <div
                      key={item.id}
                      onClick={() => {
                        item.onAction?.();
                        onSelectNotification?.(item);
                        setNotificationsOpen(false);
                      }}
                      className={`p-2.5 rounded-xl border text-xs cursor-pointer transition-colors ${
                        item.severity === 'critical' || item.severity === 'high'
                          ? 'bg-[#221e45] hover:bg-[#2b2559] border-[#3c3474]'
                          : 'bg-[#1d1a3b] hover:bg-[#25204c] border-[#312a5e]'
                      }`}
                    >
                      <div className="flex items-center justify-between font-semibold mb-1">
                        <span
                          className={`flex items-center gap-1.5 ${
                            item.severity === 'critical' || item.severity === 'high'
                              ? 'text-[#ef4444]'
                              : 'text-[#eab308]'
                          }`}
                        >
                          <AlertTriangle size={13} /> {item.title}
                        </span>
                        {item.timestamp && (
                          <span className="text-[10px] text-[#8680b5]">{item.timestamp}</span>
                        )}
                      </div>
                      <p className="text-[#c6c2e8] text-[11px] leading-relaxed">
                        {item.message}
                      </p>
                    </div>
                  ))
                )}
              </div>
            </div>
          )}
        </div>

        {/* Interactive System Health Status Pill */}
        {onOpenHealth && (
          <button
            onClick={onOpenHealth}
            title={`System Health: ${healthStatus}. Click to inspect live diagnostics.`}
            className={`hidden sm:flex items-center gap-1.5 px-2.5 py-1 text-xs font-semibold rounded-xl border transition-all cursor-pointer ${
              healthStatus === 'Healthy'
                ? 'bg-[#153e28]/70 text-[#4ade80] border-[#226742] hover:bg-[#153e28]'
                : healthStatus === 'Awaiting telemetry'
                ? 'bg-[#1e2a4a]/70 text-[#60a5fa] border-[#2a4374] hover:bg-[#1e2a4a]'
                : healthStatus === 'Degraded'
                ? 'bg-[#403413]/70 text-[#facc15] border-[#6b551c] hover:bg-[#403413]'
                : healthStatus === 'Unhealthy' || healthStatus === 'Unavailable'
                ? 'bg-[#4a1c25]/70 text-[#f87171] border-[#782836] hover:bg-[#4a1c25]'
                : 'bg-[#221e45]/70 text-[#c0bbe6] border-[#3b3370] hover:bg-[#221e45]'
            }`}
          >
            <span
              className={`w-2 h-2 rounded-full ${
                healthStatus === 'Healthy'
                  ? 'bg-[#4ade80]'
                  : healthStatus === 'Awaiting telemetry'
                  ? 'bg-[#60a5fa]'
                  : healthStatus === 'Degraded'
                  ? 'bg-[#facc15]'
                  : healthStatus === 'Unhealthy' || healthStatus === 'Unavailable'
                  ? 'bg-[#f87171]'
                  : 'bg-[#a78bfa] animate-pulse'
              }`}
            />
            <span className="hidden md:inline">Health:</span>
            <span>{healthStatus}</span>
          </button>
        )}

        {/* Administrator Profile / Auth Dropdown */}
        <div className="relative">
          <button
            onClick={() => {
              setAdminMenuOpen(!adminMenuOpen);
              setNotificationsOpen(false);
            }}
            className={`flex items-center gap-2 pl-2 pr-2.5 py-1 bg-[#191733] border rounded-xl transition-all shadow-sm ${
              isAuthenticated
                ? 'border-[#342d63] hover:border-[#6d3ee8]'
                : 'border-[#4a2e70] hover:border-[#9d68f5]'
            }`}
          >
            {isAuthenticated ? (
              <div className="relative">
                <PixelAvatar size={26} />
                <span className="absolute -bottom-0.5 -right-0.5 w-2 h-2 rounded-full bg-[#22c55e] ring-2 ring-[#191733]" />
              </div>
            ) : (
              <div className="w-6.5 h-6.5 rounded-lg bg-[#2b1f59] text-[#c084fc] flex items-center justify-center">
                <Lock size={13} />
              </div>
            )}
            <span className="text-[12.5px] font-semibold text-white">{userLabel}</span>
            <ChevronDown
              size={13}
              className={`text-[#8d87bc] transition-transform duration-200 ${
                adminMenuOpen ? 'rotate-180' : ''
              }`}
            />
          </button>

          {/* Admin / Auth Dropdown Menu */}
          {adminMenuOpen && (
            <div className="absolute right-0 mt-2 w-60 p-1.5 bg-[#181634] border border-[#3e3678] rounded-2xl shadow-2xl z-50 animate-in fade-in slide-in-from-top-2 duration-150">
              <div className="px-3 py-2 border-b border-[#282352]">
                <div className="flex items-center justify-between">
                  <p className="text-xs font-bold text-white tracking-tight">{userRole}</p>
                  <span
                    className={`inline-flex items-center gap-1 px-1.5 py-0.2 rounded text-[10px] font-mono font-semibold ${
                      isAuthenticated
                        ? 'bg-[#153e28] text-[#4ade80] border border-[#226742]'
                        : 'bg-[#403413] text-[#facc15] border border-[#6b551c]'
                    }`}
                  >
                    <span className="w-1.5 h-1.5 rounded-full bg-current" />
                    {isAuthenticated ? 'Authenticated' : 'Guest'}
                  </span>
                </div>
                <p className="text-[11px] font-mono text-[#8d87bc] truncate mt-0.5">
                  {isAuthenticated
                    ? `Workspace: ${session?.tenant_id || 'default'}`
                    : 'Sign in to manage policies & reviews'}
                </p>
              </div>

              <div className="py-1 flex flex-col gap-0.5">
                {!isAuthenticated ? (
                  <button
                    onClick={() => {
                      setAdminMenuOpen(false);
                      onOpenLogin?.();
                    }}
                    className="flex items-center gap-2 w-full px-3 py-2 text-xs font-semibold text-[#c084fc] hover:bg-[#2e1d54] hover:text-white rounded-lg transition-colors cursor-pointer"
                  >
                    <LogIn size={14} className="text-[#c084fc]" /> Sign In as Admin
                  </button>
                ) : (
                  <>
                    <button
                      onClick={() => {
                        setAdminMenuOpen(false);
                        onOpenSecuritySettings?.();
                      }}
                      className="flex items-center gap-2 w-full px-3 py-2 text-xs font-medium text-[#c0bbe6] hover:bg-[#25204c] hover:text-white rounded-lg transition-colors cursor-pointer"
                    >
                      <Shield size={14} /> Security Settings
                    </button>
                    <button
                      onClick={() => {
                        setAdminMenuOpen(false);
                        onLogout?.();
                      }}
                      className="flex items-center gap-2 w-full px-3 py-2 text-xs font-semibold text-[#f87171] hover:bg-[#4a1c25] hover:text-white rounded-lg transition-colors cursor-pointer"
                    >
                      <LogOut size={14} className="text-[#f87171]" /> Sign Out
                    </button>
                  </>
                )}
                <button
                  onClick={() => {
                    setAdminMenuOpen(false);
                    onOpenHealth?.();
                  }}
                  className="flex items-center justify-between w-full px-3 py-2 text-xs font-medium text-[#c0bbe6] hover:bg-[#25204c] hover:text-white rounded-lg transition-colors cursor-pointer"
                >
                  <div className="flex items-center gap-2">
                    {healthStatus === 'Healthy' ? (
                      <CheckCircle size={14} className="text-[#4ade80]" />
                    ) : healthStatus === 'Awaiting telemetry' ? (
                      <Activity size={14} className="text-[#60a5fa]" />
                    ) : healthStatus === 'Degraded' ? (
                      <AlertTriangle size={14} className="text-[#facc15]" />
                    ) : (
                      <XCircle size={14} className="text-[#f87171]" />
                    )}
                    <span>System Health</span>
                  </div>
                  <span
                    className={`text-[10px] font-mono px-1.5 py-0.5 rounded font-semibold ${
                      healthStatus === 'Healthy'
                        ? 'bg-[#153e28] text-[#4ade80]'
                        : healthStatus === 'Awaiting telemetry'
                        ? 'bg-[#1e2a4a] text-[#60a5fa]'
                        : healthStatus === 'Degraded'
                        ? 'bg-[#403413] text-[#facc15]'
                        : 'bg-[#4a1c25] text-[#f87171]'
                    }`}
                  >
                    {healthStatus}
                  </span>
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </header>
  );
};
