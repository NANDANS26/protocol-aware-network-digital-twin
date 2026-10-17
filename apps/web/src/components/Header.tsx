import React from 'react';
import { Activity, ShieldCheck, RefreshCw, AlertCircle, WifiOff } from 'lucide-react';
import type { HealthStatusResponse } from '@contracts/health';
import type { ApiError } from '../api/client';

interface HeaderProps {
  health: HealthStatusResponse | null;
  isLoading: boolean;
  error: ApiError | null;
  onRefresh: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  health,
  isLoading,
  error,
  onRefresh,
}) => {
  return (
    <header className="h-16 border-b border-surface-border bg-surface px-6 flex items-center justify-between z-10">
      <div className="flex items-center gap-3">
        <div className="w-9 h-9 rounded bg-blue-600/20 border border-blue-500/40 flex items-center justify-center text-blue-400">
          <Activity className="w-5 h-5" />
        </div>
        <div>
          <div className="flex items-center gap-2">
            <h1 className="font-semibold text-sm tracking-wide text-gray-100 uppercase font-mono">
              Protocol Digital Twin
            </h1>
            <span className="text-xs px-1.5 py-0.5 rounded bg-blue-900/50 text-blue-300 border border-blue-700/50 font-mono">
              Phase 00 Foundation
            </span>
          </div>
          <p className="text-xs text-gray-400">
            Security Verification & Protocol Analysis Engine
          </p>
        </div>
      </div>

      <div className="flex items-center gap-4">
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
