import React, { useEffect, useRef } from 'react';
import { X, Network } from 'lucide-react';
import type {
  TopologyGraph,
  TopologyNode,
  TopologyEdge,
  EvidenceClass,
} from '../../../types/intelligence';
import { TopologyGraphView } from './TopologyGraphView';

export interface TopologyModalProps {
  isOpen: boolean;
  onClose: () => void;
  topology: TopologyGraph | null;
  selectedNode: TopologyNode | null;
  selectedEdge: TopologyEdge | null;
  onSelectNode: (node: TopologyNode | null) => void;
  onSelectEdge: (edge: TopologyEdge | null) => void;
  evidenceClassFilter: string;
  onChangeEvidenceFilter: (filter: string) => void;
  renderEvidenceClassBadge?: (evClass?: EvidenceClass | string) => React.ReactNode;
}

export const TopologyModal: React.FC<TopologyModalProps> = ({
  isOpen,
  onClose,
  topology,
  selectedNode,
  selectedEdge,
  onSelectNode,
  onSelectEdge,
  evidenceClassFilter,
  onChangeEvidenceFilter,
  renderEvidenceClassBadge,
}) => {
  const previousActiveElement = useRef<HTMLElement | null>(null);
  const modalContentRef = useRef<HTMLDivElement>(null);
  const closeButtonRef = useRef<HTMLButtonElement>(null);

  // Store previously focused element and restore on unmount/close
  useEffect(() => {
    if (isOpen) {
      previousActiveElement.current = document.activeElement as HTMLElement | null;
      // Prevent background body scroll
      const originalOverflow = document.body.style.overflow;
      document.body.style.overflow = 'hidden';

      // Focus close button initially for accessibility
      setTimeout(() => {
        closeButtonRef.current?.focus();
      }, 50);

      return () => {
        document.body.style.overflow = originalOverflow;
        if (previousActiveElement.current && typeof previousActiveElement.current.focus === 'function') {
          previousActiveElement.current.focus();
        }
      };
    }
  }, [isOpen]);

  // Handle Escape key to close modal
  useEffect(() => {
    if (!isOpen) return;

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' || e.key === 'Esc') {
        e.preventDefault();
        e.stopPropagation();
        onClose();
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => {
      window.removeEventListener('keydown', handleKeyDown);
    };
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  // Derive counts from actual topology data
  const nodeCount = topology?.node_count || (topology?.nodes || []).length;
  const edgeCount = topology?.edge_count || (topology?.edges || []).length;
  const subnetCount =
    topology?.subnets_count ||
    (topology?.nodes || []).filter((n) => n.node_type === 'SUBNET').length;
  const routerCount = (topology?.nodes || []).filter((n) => n.node_type === 'ROUTER').length;

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="topology-modal-title"
      data-testid="topology-modal-backdrop"
      className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/85 backdrop-blur-md p-2 sm:p-4 md:p-6 overflow-hidden animate-in fade-in duration-200"
      onClick={(e) => {
        // Only close if clicking directly on the backdrop, not during graph interaction
        if (e.target === e.currentTarget) {
          onClose();
        }
      }}
    >
      <div
        ref={modalContentRef}
        data-testid="topology-modal-content"
        className="w-full h-full max-w-[1850px] max-h-[96vh] bg-[#0b0f19] border border-slate-800 rounded-2xl shadow-2xl flex flex-col overflow-hidden text-slate-100"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Modal Header */}
        <div className="flex items-center justify-between px-5 py-3.5 border-b border-slate-800/90 bg-slate-900/90 shrink-0">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-indigo-950/80 border border-indigo-700/50 text-indigo-400">
              <Network className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2.5">
                <h2 id="topology-modal-title" className="text-base sm:text-lg font-bold text-white tracking-tight">
                  Interactive Network Topology
                </h2>
                <span className="px-2 py-0.5 rounded text-[11px] font-mono font-medium bg-emerald-950/80 text-emerald-400 border border-emerald-800/60 flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                  Full-Screen Workspace
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Hierarchical clustered twin with boundary edge routing &bull;{' '}
                <span className="font-mono text-slate-300 font-semibold">{nodeCount}</span> nodes &bull;{' '}
                <span className="font-mono text-cyan-400 font-semibold">{subnetCount}</span> subnets &bull;{' '}
                <span className="font-mono text-purple-400 font-semibold">{routerCount}</span> transit routers &bull;{' '}
                <span className="font-mono text-amber-400 font-semibold">{edgeCount}</span> relationships
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              ref={closeButtonRef}
              type="button"
              onClick={onClose}
              aria-label="Close Interactive Topology"
              title="Close Interactive Topology (Esc)"
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white border border-slate-700 transition focus:outline-none focus:ring-2 focus:ring-indigo-500"
            >
              <X className="w-4 h-4" />
              <span className="text-xs font-mono hidden sm:inline">Close</span>
              <kbd className="hidden sm:inline-block px-1.5 py-0.2 text-[10px] font-mono bg-slate-900 border border-slate-700 rounded text-slate-400 ml-0.5">
                Esc
              </kbd>
            </button>
          </div>
        </div>

        {/* Modal Body / Graph Canvas Viewport */}
        <div className="flex-1 min-h-0 overflow-hidden p-3 sm:p-4 flex flex-col bg-[#080c14]">
          <TopologyGraphView
            topology={topology}
            selectedNode={selectedNode}
            selectedEdge={selectedEdge}
            onSelectNode={onSelectNode}
            onSelectEdge={onSelectEdge}
            evidenceClassFilter={evidenceClassFilter}
            onChangeEvidenceFilter={onChangeEvidenceFilter}
            renderEvidenceClassBadge={renderEvidenceClassBadge}
            isModal={true}
          />
        </div>
      </div>
    </div>
  );
};
