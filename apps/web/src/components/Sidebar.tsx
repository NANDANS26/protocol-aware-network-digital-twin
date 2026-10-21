import React, { useEffect } from 'react';
import {
  LayoutDashboard,
  Radio,
  Network,
  FlaskConical,
  Binary,
  Bot,
  ExternalLink,
  X,
  Layers,
} from 'lucide-react';
import { NAVIGATION_TABS, type NavigationTab } from '../types/navigation';

interface SidebarProps {
  currentTab: NavigationTab;
  onSelectTab: (tab: NavigationTab) => void;
  isOpen?: boolean;
  onClose?: () => void;
}

const TAB_ICONS: Record<NavigationTab, React.ReactNode> = {
  overview: <LayoutDashboard className="w-4 h-4" />,
  observatory: <Radio className="w-4 h-4" />,
  twin: <Network className="w-4 h-4" />,
  laboratory: <FlaskConical className="w-4 h-4" />,
  research: <Binary className="w-4 h-4" />,
  investigation: <Bot className="w-4 h-4" />,
};

export const Sidebar: React.FC<SidebarProps> = ({
  currentTab,
  onSelectTab,
  isOpen = false,
  onClose = () => {},
}) => {
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isOpen) {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  const handleSelect = (tab: NavigationTab) => {
    onSelectTab(tab);
    onClose();
  };

  return (
    <>
      {/* Backdrop */}
      {isOpen && (
        <div
          data-testid="nav-drawer-backdrop"
          onClick={onClose}
          className="fixed inset-0 bg-black/60 backdrop-blur-sm z-40 transition-opacity"
          aria-hidden="true"
        />
      )}

      {/* Slide-out Navigation Drawer */}
      <aside
        data-testid="nav-drawer"
        role="dialog"
        aria-label="System Navigation"
        aria-modal={isOpen}
        className={`fixed inset-y-0 left-0 z-50 w-72 bg-slate-950/95 border-r border-cyan-900/40 shadow-2xl flex flex-col justify-between shrink-0 transform transition-transform duration-200 ease-in-out font-sans ${
          isOpen ? 'translate-x-0' : '-translate-x-full pointer-events-none'
        }`}
      >
        <div className="p-4 space-y-3">
          <div className="flex items-center justify-between pb-2 border-b border-gray-800/80">
            <div className="flex items-center gap-2">
              <Layers className="w-4 h-4 text-cyan-400" />
              <span className="text-xs font-bold text-gray-200 uppercase tracking-wider font-mono">
                System Modules
              </span>
            </div>
            <button
              type="button"
              onClick={onClose}
              aria-label="Close navigation menu"
              className="p-1 rounded hover:bg-gray-800/80 text-gray-400 hover:text-white transition"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          <nav className="space-y-1.5" aria-label="Main Navigation">
            {NAVIGATION_TABS.map((tab) => {
              const isActive = currentTab === tab.id;
              return (
                <button
                  type="button"
                  key={tab.id}
                  onClick={() => handleSelect(tab.id)}
                  className={`w-full flex items-center justify-between px-3 py-2.5 rounded text-xs font-medium transition text-left ${
                    isActive
                      ? 'bg-gradient-to-r from-cyan-950/60 to-blue-950/40 text-cyan-300 border border-cyan-500/40 shadow-sm'
                      : 'text-gray-300 hover:bg-surface-raised hover:text-white border border-transparent'
                  }`}
                  aria-current={isActive ? 'page' : undefined}
                >
                  <div className="flex items-center gap-2.5 min-w-0">
                    <span className={isActive ? 'text-cyan-400' : 'text-gray-400'}>
                      {TAB_ICONS[tab.id]}
                    </span>
                    <span className="truncate">{tab.label}</span>
                  </div>
                  <span
                    className={`text-[10px] font-mono px-1.5 py-0.5 rounded border shrink-0 ${
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

        <div className="p-4 border-t border-gray-800/80 space-y-2">
          <div className="p-3 rounded bg-surface-raised border border-surface-border text-xs text-gray-400">
            <div className="text-gray-200 font-semibold mb-1 flex items-center gap-1.5 font-mono">
              <span>FastAPI Docs</span>
              <ExternalLink className="w-3 h-3 text-gray-400" />
            </div>
            <p className="text-[11px] text-gray-400 mb-2">
              OpenAPI specification &amp; Swagger UI
            </p>
            <a
              href="/docs"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-block text-xs font-mono text-cyan-400 hover:text-cyan-300 underline"
            >
              /docs &rarr;
            </a>
          </div>
          <div className="text-[10px] font-mono text-gray-500 text-center">
            Protocol Twin Platform • 2026
          </div>
        </div>
      </aside>
    </>
  );
};
