import React from 'react';
import type { SubsystemReport } from '@contracts/health';
import { StatusBadge } from './StatusBadge';
import { CheckCircle2, Clock, AlertTriangle } from 'lucide-react';

interface SubsystemCardProps {
  id: string;
  name: string;
  phase: string;
  report?: SubsystemReport;
  description: string;
}

export const SubsystemCard: React.FC<SubsystemCardProps> = ({
  name,
  phase,
  report,
  description,
}) => {
  const isOperational = report?.operational_state === 'operational';
  const isPlanned = report?.operational_state === 'planned';

  return (
    <div
      className={`p-4 rounded-lg border transition ${
        isOperational
          ? 'bg-surface-raised border-emerald-900/40'
          : isPlanned
          ? 'bg-surface border-surface-border'
          : 'bg-surface border-amber-900/40'
      }`}
      data-testid="subsystem-card"
    >
      <div className="flex items-start justify-between gap-3 mb-2">
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded bg-surface border border-surface-border text-gray-300">
            {isOperational ? (
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            ) : isPlanned ? (
              <Clock className="w-4 h-4 text-slate-400" />
            ) : (
              <AlertTriangle className="w-4 h-4 text-amber-400" />
            )}
          </div>
          <div>
            <h3 className="font-semibold text-sm text-gray-100">{name}</h3>
            <span className="text-[11px] font-mono text-gray-400">{phase}</span>
          </div>
        </div>

        {report ? (
          <StatusBadge status={report.operational_state} size="sm" />
        ) : (
          <StatusBadge status="unavailable" size="sm" />
        )}
      </div>

      <p className="text-xs text-gray-400 mb-3 leading-relaxed">{description}</p>

      {report?.details && (
        <div className="p-2.5 rounded bg-background/80 border border-surface-border text-[11px] font-mono text-gray-300">
          <div className="text-[10px] uppercase text-gray-500 mb-0.5 tracking-wider">
            Live Status Telemetry
          </div>
          <div className="truncate">{report.details}</div>
        </div>
      )}

      {report?.last_checked && (
        <div className="mt-2 text-[10px] font-mono text-gray-500 flex items-center gap-1">
          <span>Checked:</span>
          <span>{new Date(report.last_checked).toLocaleTimeString()}</span>
        </div>
      )}
    </div>
  );
};
