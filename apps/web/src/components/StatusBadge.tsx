import React from 'react';
import type { SubsystemState, OperationalState, OverallHealthStatus } from '@contracts/health';

interface StatusBadgeProps {
  status: SubsystemState | OperationalState | OverallHealthStatus | string;
  size?: 'sm' | 'md';
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({ status, size = 'md' }) => {
  const norm = status.toLowerCase();

  let bgClass = 'bg-gray-800 text-gray-300 border-gray-700';
  let dotClass = 'bg-gray-400';
  let label = status;

  if (norm === 'operational' || norm === 'healthy' || norm === 'ok') {
    bgClass = 'bg-emerald-950/60 text-emerald-300 border-emerald-800/60';
    dotClass = 'bg-emerald-400';
    label = norm === 'ok' ? 'Operational' : status.charAt(0).toUpperCase() + status.slice(1);
  } else if (norm === 'degraded') {
    bgClass = 'bg-amber-950/60 text-amber-300 border-amber-800/60';
    dotClass = 'bg-amber-400';
    label = 'Degraded';
  } else if (norm === 'down' || norm === 'unhealthy' || norm === 'not_ready') {
    bgClass = 'bg-rose-950/60 text-rose-300 border-rose-800/60';
    dotClass = 'bg-rose-400';
    label = norm === 'not_ready' ? 'Not Ready' : 'Down';
  } else if (norm === 'planned') {
    bgClass = 'bg-slate-800/80 text-slate-400 border-slate-700/60';
    dotClass = 'bg-slate-500';
    label = 'Planned';
  } else if (norm === 'disabled') {
    bgClass = 'bg-gray-800/60 text-gray-400 border-gray-700/60';
    dotClass = 'bg-gray-500';
    label = 'Disabled';
  } else if (norm === 'unavailable') {
    bgClass = 'bg-amber-950/40 text-amber-300/90 border-amber-800/40';
    dotClass = 'bg-amber-500';
    label = 'Unavailable';
  }

  const sizeClasses = size === 'sm' ? 'px-2 py-0.5 text-xs' : 'px-2.5 py-1 text-xs';

  return (
    <span
      className={`inline-flex items-center gap-1.5 font-mono uppercase tracking-wider rounded border font-medium ${bgClass} ${sizeClasses}`}
      data-testid="status-badge"
    >
      <span className={`w-1.5 h-1.5 rounded-full ${dotClass} ${norm === 'healthy' || norm === 'ok' ? 'animate-pulse' : ''}`} />
      {label}
    </span>
  );
};
