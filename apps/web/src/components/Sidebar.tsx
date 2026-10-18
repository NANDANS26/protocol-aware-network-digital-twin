import React from 'react';
import {
  LayoutDashboard,
  Radio,
  Network,
  FlaskConical,
  Binary,
  Bot,
  ExternalLink,
} from 'lucide-react';
import { NAVIGATION_TABS, type NavigationTab } from '../types/navigation';

interface SidebarProps {
  currentTab: NavigationTab;
  onSelectTab: (tab: NavigationTab) => void;
}

const TAB_ICONS: Record<NavigationTab, React.ReactNode> = {
  overview: <LayoutDashboard className="w-4 h-4" />,
  observatory: <Radio className="w-4 h-4" />,
  twin: <Network className="w-4 h-4" />,
  laboratory: <FlaskConical className="w-4 h-4" />,
  research: <Binary className="w-4 h-4" />,
  investigation: <Bot className="w-4 h-4" />,
};

export const Sidebar: React.FC<SidebarProps> = ({ currentTab, onSelectTab }) => {
  return (
    <aside className="w-64 border-r border-surface-border bg-surface flex flex-col justify-between shrink-0">
      <div className="p-4 space-y-1">
        <div className="px-3 py-2 text-xs font-semibold text-gray-400 uppercase tracking-wider font-mono">
          System Modules
        </div>
        <nav className="space-y-1" aria-label="Main Navigation">
          {NAVIGATION_TABS.map((tab) => {
            const isActive = currentTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => onSelectTab(tab.id)}
                className={`w-full flex items-center justify-between px-3 py-2.5 rounded text-xs font-medium transition text-left ${
                  isActive
                    ? 'bg-blue-600/20 text-blue-300 border border-blue-500/30'
                    : 'text-gray-300 hover:bg-surface-raised hover:text-white'
                }`}
                aria-current={isActive ? 'page' : undefined}
              >
                <div className="flex items-center gap-2.5">
                  <span className={isActive ? 'text-blue-400' : 'text-gray-400'}>
                    {TAB_ICONS[tab.id]}
                  </span>
                  <span>{tab.label}</span>
                </div>
                <span
                  className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${
                    tab.isImplemented
                      ? 'bg-emerald-950/60 text-emerald-300 border-emerald-800/40'
                      : 'bg-slate-800 text-slate-400 border-slate-700'
                  }`}
                >
                  {tab.statusLabel}
                </span>
              </button>
            );
          })}
        </nav>
      </div>

      <div className="p-4 border-t border-surface-border space-y-2">
        <div className="p-3 rounded bg-surface-raised border border-surface-border text-xs text-gray-400">
          <div className="text-gray-200 font-semibold mb-1 flex items-center gap-1.5 font-mono">
            <span>FastAPI Docs</span>
            <ExternalLink className="w-3 h-3 text-gray-400" />
          </div>
          <p className="text-[11px] text-gray-400 mb-2">
            OpenAPI specification & Swagger UI
          </p>
          <a
            href="/docs"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-block text-xs font-mono text-blue-400 hover:text-blue-300 underline"
          >
            /docs &rarr;
          </a>
        </div>
        <div className="text-[10px] font-mono text-gray-500 text-center">
          Protocol Twin Platform • 2026
        </div>
      </div>
    </aside>
  );
};
