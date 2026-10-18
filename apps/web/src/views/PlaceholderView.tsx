import React from 'react';
import type { TabDefinition } from '../types/navigation';
import { Clock, ArrowRight, ShieldAlert, Cpu } from 'lucide-react';

interface PlaceholderViewProps {
  tab: TabDefinition;
}

export const PlaceholderView: React.FC<PlaceholderViewProps> = ({ tab }) => {
  return (
    <div className="max-w-4xl mx-auto py-12 px-4" data-testid="placeholder-view">
      <div className="p-8 rounded-xl bg-surface border border-surface-border space-y-6">
        <div className="flex items-center gap-3">
          <div className="p-3 rounded-lg bg-blue-600/10 border border-blue-500/30 text-blue-400">
            <Clock className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-xl font-bold text-gray-100">{tab.label}</h2>
              <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700 text-xs font-mono">
                {tab.phase} Planned
              </span>
            </div>
            <p className="text-xs text-gray-400 mt-1 font-mono">
              Module Status: Planned Architecture Component (Not yet implemented)
            </p>
          </div>
        </div>

        <div className="p-4 rounded-lg bg-background/80 border border-surface-border space-y-2">
          <div className="text-xs font-semibold text-gray-300 uppercase tracking-wider font-mono">
            Subsystem Purpose & Mission
          </div>
          <p className="text-sm text-gray-300 leading-relaxed">
            {tab.description}
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="p-4 rounded-lg bg-surface-raised border border-surface-border space-y-2">
            <div className="flex items-center gap-2 text-xs font-semibold text-blue-400 uppercase font-mono">
              <Cpu className="w-4 h-4" />
              <span>Technical Dependencies</span>
            </div>
            <ul className="text-xs text-gray-400 space-y-1.5 list-disc list-inside">
              <li>Foundation contracts and verified build system (Active)</li>
              <li>C++20 packet-ingestion & zero-copy decoder pipeline (Active)</li>
              <li>Persistent relational storage & analytical store (Active)</li>
            </ul>
          </div>

          <div className="p-4 rounded-lg bg-surface-raised border border-surface-border space-y-2">
            <div className="flex items-center gap-2 text-xs font-semibold text-emerald-400 uppercase font-mono">
              <ShieldAlert className="w-4 h-4" />
              <span>Reliability & Truthfulness Policy</span>
            </div>
            <p className="text-xs text-gray-400 leading-relaxed">
              No simulated packets, fake security alerts, or fabricated models are displayed.
              Real-time processing will be unlocked as downstream phases land.
            </p>
          </div>
        </div>

        <div className="pt-2 flex items-center justify-between text-xs text-gray-500 font-mono border-t border-surface-border">
          <span>Component: {tab.id}</span>
          <span className="flex items-center gap-1 text-blue-400">
            <span>Scheduled for {tab.phase}</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </span>
        </div>
      </div>
    </div>
  );
};
