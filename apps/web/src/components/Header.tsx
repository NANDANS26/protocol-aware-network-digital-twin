import React from 'react';
import { Activity, ShieldCheck, RefreshCw, AlertCircle, WifiOff, Menu, Database } from 'lucide-react';
import type { HealthStatusResponse } from '@contracts/health';
import type { ApiError } from '../api/client';
import { useAnalysisContext } from '../context/AnalysisContext';

interface HeaderProps {
  health: HealthStatusResponse | null;
  isLoading: boolean;
  error: ApiError | null;
  onRefresh: () => void;
  onToggleNavDrawer?: () => void;
  isNavDrawerOpen?: boolean;
}

export const Header: React.FC<HeaderProps> = ({
  health,
  isLoading,
  error,
  onRefresh,
  onToggleNavDrawer,
  isNavDrawerOpen = false,
}) => {
  const {
    activeCaptureId,
    activeStatus,
    capturesList,
    setActiveCaptureId,
  } = useAnalysisContext();

  return (
    <header className="h-16 border-b border-surface-border bg-surface px-6 flex items-center justify-between z-10">
      <div className="flex items-center gap-3">
        {onToggleNavDrawer && (
          <button
            type="button"
            onClick={onToggleNavDrawer}
            aria-label={isNavDrawerOpen ? 'Close navigation drawer' : 'Open navigation menu'}
            className="p-2 rounded bg-surface-raised hover:bg-gray-700/80 border border-surface-border text-gray-300 hover:text-cyan-300 transition flex items-center justify-center focus:outline-none focus:ring-1 focus:ring-cyan-500"
            title="Toggle System Modules Menu"
          >
            <Menu className="w-4 h-4 text-cyan-400" />
          </button>
        )}
        <div className="w-9 h-9 rounded bg-blue-600/20 border border-blue-500/40 flex items-center justify-center text-blue-400">
          <Activity className="w-5 h-5" />
        </div>
        <div>
          <div className="flex items-center gap-2">
            <h1 className="font-semibold text-sm tracking-wide text-gray-100 uppercase font-mono">
              Protocol Digital Twin
            </h1>
            <span className="text-xs px-1.5 py-0.5 rounded bg-blue-900/50 text-blue-300 border border-blue-700/50 font-mono">
              v{health?.version || '1.0.0'} Active
            </span>
          </div>
          <p className="text-xs text-gray-400">
            Security Verification & Protocol Analysis Engine
          </p>
        </div>
      </div>

      <div className="flex items-center gap-4">
        {/* Active Analysis Context Selector */}
        <div className="flex items-center gap-2 px-3 py-1 rounded bg-slate-900/90 border border-slate-700/70 text-xs font-mono">
          <Database className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
          <span className="text-slate-400 text-[11px] font-sans">Active Capture:</span>
          {capturesList.length > 0 ? (
            <select
              aria-label="Active Capture Selection"
              value={activeCaptureId || ''}
              onChange={(e) => setActiveCaptureId(e.target.value || null)}
              className="bg-slate-950 text-cyan-300 border border-slate-700 rounded px-2 py-0.5 text-xs focus:outline-none focus:ring-1 focus:ring-cyan-500 font-mono max-w-[200px] truncate"
            >
              {capturesList.map((c) => (
                <option key={c.capture_id} value={c.capture_id}>
                  {c.filename || c.file_name} ({c.packet_count || 0} pkts)
                </option>
              ))}
            </select>
          ) : (
            <span className="text-slate-400 italic">None registered</span>
          )}

          {activeStatus && (
            <span
              className={`px-1.5 py-0.2 rounded text-[10px] font-semibold uppercase ${
                activeStatus === 'COMPLETE' || activeStatus === 'completed'
                  ? 'bg-emerald-950/80 text-emerald-400 border border-emerald-800/60'
                  : activeStatus === 'PROCESSING' || activeStatus === 'NORMALIZING' || activeStatus === 'PERSISTING'
                  ? 'bg-amber-950/80 text-amber-300 border border-amber-800/60 animate-pulse'
                  : 'bg-rose-950/80 text-rose-300 border border-rose-800/60'
              }`}
            >
              {activeStatus}
            </span>
          )}
        </div>

        {/* Connection status indicator */}
        <div className="flex items-center gap-2 text-xs font-mono">
          {isLoading && !health ? (
            <span className="flex items-center gap-1.5 text-gray-400">
              <RefreshCw className="w-3.5 h-3.5 animate-spin text-blue-400" />
              <span>Connecting to Backend...</span>
            </span>
          ) : error ? (
            <span className="flex items-center gap-1.5 text-rose-400 bg-rose-950/40 px-2.5 py-1 rounded border border-rose-800/40">
              <WifiOff className="w-3.5 h-3.5" />
              <span>Backend Disconnected</span>
            </span>
          ) : health ? (
            <span className="flex items-center gap-1.5 text-emerald-400 bg-emerald-950/40 px-2.5 py-1 rounded border border-emerald-800/40">
              <ShieldCheck className="w-3.5 h-3.5" />
              <span>API Live ({health.version})</span>
            </span>
          ) : (
            <span className="flex items-center gap-1.5 text-gray-400">
              <AlertCircle className="w-3.5 h-3.5" />
              <span>Idle</span>
            </span>
          )}
        </div>

        {/* Refresh action */}
        <button
          onClick={onRefresh}
          disabled={isLoading}
          aria-label="Refresh backend status"
          className="p-1.5 rounded bg-surface-raised hover:bg-gray-700 border border-surface-border text-gray-300 hover:text-white transition disabled:opacity-50"
          title="Refresh Backend Health"
        >
          <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin text-blue-400' : ''}`} />
        </button>
      </div>
    </header>
  );
};
