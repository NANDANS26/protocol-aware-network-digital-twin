import React, { useState, useMemo, useRef, useEffect, useCallback } from 'react';
import {
  ZoomIn,
  ZoomOut,
  Maximize2,
  RotateCcw,
  Search,
  X,
  Layers,
  ChevronRight,
  ChevronDown,
  Info,
} from 'lucide-react';
import type {
  TopologyGraph,
  TopologyNode,
  TopologyEdge,
  EvidenceClass,
} from '../../../types/intelligence';
import {
  computeHierarchicalLayout,
  type TopologyLayoutResult,
} from './layoutEngine';

export interface TopologyGraphViewProps {
  topology: TopologyGraph | null;
  selectedNode: TopologyNode | null;
  selectedEdge: TopologyEdge | null;
  onSelectNode: (node: TopologyNode | null) => void;
  onSelectEdge: (edge: TopologyEdge | null) => void;
  evidenceClassFilter: string;
  onChangeEvidenceFilter: (filter: string) => void;
  renderEvidenceClassBadge?: (evClass?: EvidenceClass | string) => React.ReactNode;
  isModal?: boolean;
  onOpenModal?: () => void;
}

export const TopologyGraphView: React.FC<TopologyGraphViewProps> = ({
  topology,
  selectedNode,
  selectedEdge,
  onSelectNode,
  onSelectEdge,
  evidenceClassFilter,
  onChangeEvidenceFilter,
  renderEvidenceClassBadge,
  isModal = false,
  onOpenModal,
}) => {
  // Canvas viewport & transform state
  const containerRef = useRef<HTMLDivElement>(null);
  const svgRef = useRef<SVGSVGElement>(null);
  const [zoomLevel, setZoomLevel] = useState<number>(1);
  const [panOffset, setPanOffset] = useState<{ x: number; y: number }>({ x: 0, y: 0 });
  const [isPanning, setIsPanning] = useState<boolean>(false);
  const [panStart, setPanStart] = useState<{ x: number; y: number }>({ x: 0, y: 0 });

  // Filtering & Search states
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [nodeTypeFilter, setNodeTypeFilter] = useState<string>('ALL');
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);
  const [inspectorOpen, setInspectorOpen] = useState<boolean>(true);
  const [showRawProperties, setShowRawProperties] = useState<boolean>(false);

  // Subnet collapse state
  const [collapsedSubnets, setCollapsedSubnets] = useState<Set<string>>(new Set());

  // Automatically open inspector when user selects a node or edge
  useEffect(() => {
    if (selectedNode || selectedEdge) {
      setInspectorOpen(true);
    }
  }, [selectedNode, selectedEdge]);

  const renderBadge = (evClass?: string) => {
    if (renderEvidenceClassBadge) {
      return renderEvidenceClassBadge(evClass);
    }
    const colorClasses =
      evClass === 'DIRECTLY_OBSERVED'
        ? 'bg-emerald-950/80 text-emerald-400 border-emerald-800/60'
        : evClass === 'CONFIGURED'
        ? 'bg-blue-950/80 text-blue-400 border-blue-800/60'
        : evClass === 'INFERRED'
        ? 'bg-amber-950/80 text-amber-400 border-amber-800/60'
        : 'bg-slate-800 text-slate-400 border-slate-700';

    return (
      <span
        className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium border font-mono ${colorClasses}`}
      >
        {evClass || 'UNKNOWN'}
      </span>
    );
  };

  const toggleSubnetCollapse = (subnetId: string) => {
    setCollapsedSubnets((prev) => {
      const next = new Set(prev);
      if (next.has(subnetId)) {
        next.delete(subnetId);
      } else {
        next.add(subnetId);
      }
      return next;
    });
  };

  const collapseAll = () => {
    if (!topology || !topology.nodes) return;
    const allSubnets = topology.nodes
      .filter((n) => n.node_type === 'SUBNET')
      .map((n) => n.node_id || n.id);
    setCollapsedSubnets(new Set(allSubnets));
  };

  const expandAll = () => {
    setCollapsedSubnets(new Set());
  };

  // Compute Layout via layoutEngine
  const layout: TopologyLayoutResult = useMemo(() => {
    return computeHierarchicalLayout(topology, collapsedSubnets);
  }, [topology, collapsedSubnets]);

  // Connected nodes & edges calculation for highlighting
  const activeFocusId = selectedNode
    ? selectedNode.node_id || selectedNode.id
    : hoveredNodeId;

  const { connectedNodeIds, connectedEdgeIds } = useMemo(() => {
    if (!activeFocusId || !topology || !topology.edges) {
      return { connectedNodeIds: new Set<string>(), connectedEdgeIds: new Set<string>() };
    }

    const nIds = new Set<string>([activeFocusId]);
    const eIds = new Set<string>();

    topology.edges.forEach((e) => {
      const edgeKey = e.edge_id || e.id;
      if (e.source_node_id === activeFocusId) {
        nIds.add(e.target_node_id);
        eIds.add(edgeKey);
      } else if (e.target_node_id === activeFocusId) {
        nIds.add(e.source_node_id);
        eIds.add(edgeKey);
      }
    });

    return { connectedNodeIds: nIds, connectedEdgeIds: eIds };
  }, [activeFocusId, topology]);

  // Robust Fit to View: calculates actual bounds with margins and centers viewport
  const handleFitToView = useCallback(() => {
    if (!containerRef.current || !layout.bounds) return;
    const { clientWidth, clientHeight } = containerRef.current;
    if (clientWidth <= 0 || clientHeight <= 0) return;

    const b = layout.bounds;
    if (!b.width || !b.height || b.width <= 0 || b.height <= 0) return;

    // Viewport padding around layout bounds
    const paddingX = 64;
    const paddingY = 64;
    const availableW = Math.max(50, clientWidth - paddingX);
    const availableH = Math.max(50, clientHeight - paddingY);

    const scaleX = availableW / b.width;
    const scaleY = availableH / b.height;
    let optimalScale = Math.min(scaleX, scaleY);

    if (!isFinite(optimalScale) || isNaN(optimalScale) || optimalScale <= 0) {
      optimalScale = 1;
    } else {
      // Clamp optimal scale between 0.15 (for large graphs) and 1.50
      optimalScale = Math.min(Math.max(0.15, optimalScale), 1.5);
    }

    const roundedScale = Number(optimalScale.toFixed(2));
    setZoomLevel(roundedScale);

    // Center layout in viewport
    const offsetX = Math.round(clientWidth / 2 - b.centerX * roundedScale);
    const offsetY = Math.round(clientHeight / 2 - b.centerY * roundedScale);
    if (isFinite(offsetX) && isFinite(offsetY)) {
      setPanOffset({ x: offsetX, y: offsetY });
    }
  }, [layout.bounds]);

  // Automatically center on initial load or layout bound changes
  useEffect(() => {
    if (topology && (topology.nodes || []).length > 0) {
      handleFitToView();
      const timer = setTimeout(handleFitToView, 60);
      return () => clearTimeout(timer);
    }
  }, [topology, layout.bounds, handleFitToView]);

  // Active ResizeObserver to adjust on window, modal, or drawer resize
  useEffect(() => {
    if (!containerRef.current || typeof ResizeObserver === 'undefined') return;
    const el = containerRef.current;
    let animationFrameId: number;

    const observer = new ResizeObserver((entries) => {
      for (const entry of entries) {
        if (entry.contentRect.width > 0 && entry.contentRect.height > 0) {
          cancelAnimationFrame(animationFrameId);
          animationFrameId = requestAnimationFrame(() => {
            handleFitToView();
          });
        }
      }
    });

    observer.observe(el);
    return () => {
      cancelAnimationFrame(animationFrameId);
      observer.disconnect();
    };
  }, [handleFitToView]);

  // Zoom and Pan Controls
  const handleZoomIn = () => setZoomLevel((z) => Math.min(3.0, Number((z + 0.15).toFixed(2))));
  const handleZoomOut = () => setZoomLevel((z) => Math.max(0.25, Number((z - 0.15).toFixed(2))));
  const handleResetZoom = () => {
    setZoomLevel(1);
    if (containerRef.current && layout.bounds) {
      const { clientWidth, clientHeight } = containerRef.current;
      setPanOffset({
        x: Math.round(clientWidth / 2 - layout.bounds.centerX),
        y: Math.round(clientHeight / 2 - layout.bounds.centerY),
      });
    } else {
      setPanOffset({ x: 0, y: 0 });
    }
  };

  const handleMouseDown = (e: React.MouseEvent<SVGSVGElement>) => {
    const target = e.target as HTMLElement;
    const targetTag = target.tagName?.toLowerCase();
    if (
      targetTag === 'svg' ||
      target.getAttribute('data-bg') === 'true' ||
      (targetTag === 'rect' && target.getAttribute('data-bg') === 'true')
    ) {
      setIsPanning(true);
      setPanStart({ x: e.clientX - panOffset.x, y: e.clientY - panOffset.y });
    }
  };

  const handleMouseMove = (e: React.MouseEvent<SVGSVGElement>) => {
    if (isPanning) {
      setPanOffset({
        x: e.clientX - panStart.x,
        y: e.clientY - panStart.y,
      });
    }
  };

  const handleMouseUp = () => setIsPanning(false);

  // Attach non-passive wheel event listener directly to SVG to prevent passive listener warning
  useEffect(() => {
    const svgEl = svgRef.current;
    if (!svgEl) return;

    const onWheelHandler = (e: WheelEvent) => {
      e.preventDefault();
      const delta = e.deltaY < 0 ? 0.1 : -0.1;
      setZoomLevel((z) => Math.min(3.0, Math.max(0.25, Number((z + delta).toFixed(2)))));
    };

    svgEl.addEventListener('wheel', onWheelHandler, { passive: false });
    return () => {
      svgEl.removeEventListener('wheel', onWheelHandler);
    };
  }, []);

  // Node matching search query
  const matchingNodeIds = useMemo(() => {
    if (!searchQuery.trim() || !topology || !topology.nodes) return new Set<string>();
    const q = searchQuery.toLowerCase().trim();
    const matches = new Set<string>();

    topology.nodes.forEach((n) => {
      const nId = (n.node_id || n.id).toLowerCase();
      const label = n.label.toLowerCase();
      const ips = [
        ...(n.ip_addresses || []),
        ...((n.properties?.ip_addresses as string[]) || []),
      ].map((ip) => ip.toLowerCase());
      const macs = [
        ...(n.mac_addresses || []),
        ...((n.properties?.mac_addresses as string[]) || []),
      ].map((mac) => mac.toLowerCase());
      const cidr = (n.subnet_cidr || (n.properties?.cidr_prefix as string) || '').toLowerCase();
      const port = String(n.service_port || n.properties?.port || '');

      if (
        nId.includes(q) ||
        label.includes(q) ||
        ips.some((ip) => ip.includes(q)) ||
        macs.some((mac) => mac.includes(q)) ||
        cidr.includes(q) ||
        port.includes(q)
      ) {
        matches.add(n.node_id || n.id);
      }
    });

    return matches;
  }, [searchQuery, topology]);

  const handleResetAll = () => {
    setSearchQuery('');
    setNodeTypeFilter('ALL');
    onChangeEvidenceFilter('ALL');
    setCollapsedSubnets(new Set());
    handleResetZoom();
  };

  // Node count summary for empty inspector onboarding
  const subnetCount = (topology?.nodes || []).filter((n) => n.node_type === 'SUBNET').length;
  const routerCount = (topology?.nodes || []).filter((n) => n.node_type === 'ROUTER').length;
  const assetCount = (topology?.nodes || []).filter(
    (n) => n.node_type === 'ASSET' || n.node_type === 'INTERFACE' || n.node_type === 'DNS_RESOLVER'
  ).length;
  const serviceCount = (topology?.nodes || []).filter((n) => n.node_type === 'SERVICE').length;
  const flowCount = (topology?.edges || []).length;

  return (
    <div
      className={`space-y-3 ${isModal ? 'h-full flex flex-col min-h-0' : ''}`}
      data-testid="topology-graph-container"
    >
      {/* Premium Grouped Toolbar */}
      <div className="flex flex-wrap items-center justify-between gap-2.5 bg-slate-900/90 p-2 sm:p-2.5 rounded-xl border border-slate-800 shadow-sm shrink-0">
        <div className="flex flex-wrap items-center gap-2">
          {/* GROUP 1: Search & Filter */}
          <div className="flex items-center gap-1.5 bg-slate-950/90 border border-slate-800 rounded-lg p-1">
            {/* Search Input with Clear Button */}
            <div className="relative flex items-center">
              <Search className="w-3.5 h-3.5 absolute left-2 text-slate-500 pointer-events-none" />
              <input
                type="text"
                placeholder="Search IP, Host, MAC, ID..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-7 pr-6 py-1 text-xs bg-transparent border-0 rounded text-slate-200 placeholder-slate-500 focus:outline-none font-mono w-44 sm:w-52"
              />
              {searchQuery && (
                <button
                  type="button"
                  onClick={() => setSearchQuery('')}
                  aria-label="Clear search"
                  title="Clear search"
                  className="absolute right-1.5 text-slate-400 hover:text-white transition"
                >
                  <X className="w-3 h-3" />
                </button>
              )}
            </div>

            <div className="h-4 w-px bg-slate-800" />

            {/* Node Type Filter */}
            <select
              value={nodeTypeFilter}
              onChange={(e) => setNodeTypeFilter(e.target.value)}
              className="bg-transparent border-0 px-2 py-1 text-xs text-slate-300 focus:outline-none font-mono cursor-pointer"
            >
              <option value="ALL">All Nodes</option>
              <option value="SUBNET">Subnets Only</option>
              <option value="ROUTER">Routers Only</option>
              <option value="ASSET">Assets Only</option>
              <option value="SERVICE">Services Only</option>
            </select>

            <div className="h-4 w-px bg-slate-800" />

            {/* Evidence Class Filter */}
            <select
              value={evidenceClassFilter}
              onChange={(e) => onChangeEvidenceFilter(e.target.value)}
              className="bg-transparent border-0 px-2 py-1 text-xs text-slate-300 focus:outline-none font-mono cursor-pointer"
            >
              <option value="ALL">All Evidence</option>
              <option value="DIRECTLY_OBSERVED">Observed</option>
              <option value="CONFIGURED">Configured</option>
              <option value="INFERRED">Inferred</option>
            </select>
          </div>

          {/* GROUP 2: Subnet Layout */}
          <div className="flex items-center gap-1 bg-slate-950/90 border border-slate-800 rounded-lg p-1">
            <button
              onClick={expandAll}
              title="Expand All Subnets"
              className="px-2.5 py-1 hover:bg-slate-800 rounded text-[11px] font-mono text-slate-300 hover:text-white transition"
            >
              Expand All
            </button>
            <div className="h-4 w-px bg-slate-800" />
            <button
              onClick={collapseAll}
              title="Collapse All Subnets"
              className="px-2.5 py-1 hover:bg-slate-800 rounded text-[11px] font-mono text-slate-300 hover:text-white transition"
            >
              Collapse All
            </button>
          </div>

          {/* GROUP 3: Viewport & Navigation */}
          <div className="flex items-center gap-1 bg-slate-950/90 border border-slate-800 rounded-lg p-1">
            <button
              type="button"
              onClick={handleZoomIn}
              title="Zoom In (+)"
              className="p-1 hover:bg-slate-800 rounded text-slate-300 hover:text-white transition"
            >
              <ZoomIn className="w-3.5 h-3.5" />
            </button>
            <button
              type="button"
              onClick={handleZoomOut}
              title="Zoom Out (-)"
              className="p-1 hover:bg-slate-800 rounded text-slate-300 hover:text-white transition"
            >
              <ZoomOut className="w-3.5 h-3.5" />
            </button>
            <div className="h-4 w-px bg-slate-800" />
            <button
              type="button"
              onClick={handleFitToView}
              title="Fit Entire Topology to View"
              className="p-1 hover:bg-slate-800 rounded text-indigo-400 hover:text-indigo-300 transition"
            >
              <Maximize2 className="w-3.5 h-3.5" />
            </button>
            <button
              type="button"
              onClick={handleResetAll}
              title="Reset View & All Filters"
              className="p-1 hover:bg-slate-800 rounded text-slate-400 hover:text-white transition"
            >
              <RotateCcw className="w-3.5 h-3.5" />
            </button>
            <button
              type="button"
              onClick={handleResetZoom}
              title="Click to reset 100%"
              className="px-1.5 py-0.5 hover:bg-slate-800 rounded text-[11px] font-mono font-medium text-slate-300 hover:text-white transition"
            >
              {(zoomLevel * 100).toFixed(0)}%
            </button>
          </div>

          {/* GROUP 4: Focus Graph Mode & Actions */}
          <button
            type="button"
            data-testid="focus-graph-button"
            onClick={() => {
              setInspectorOpen((prev) => !prev);
              setTimeout(() => {
                handleFitToView();
              }, 50);
            }}
            title={inspectorOpen ? 'Focus Graph (Hide Details)' : 'Show Details Inspector'}
            aria-label={inspectorOpen ? 'Focus Graph' : 'Show Details'}
            className={`px-2.5 py-1.5 rounded-lg text-xs font-mono font-medium border transition flex items-center gap-1.5 ${
              !inspectorOpen
                ? 'bg-indigo-600/30 border-indigo-500/70 text-indigo-200 shadow-sm'
                : 'bg-slate-950/90 border-slate-800 text-slate-300 hover:text-white hover:bg-slate-800'
            }`}
          >
            <Layers className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">{inspectorOpen ? 'Focus Graph' : 'Show Details'}</span>
          </button>

          {!isModal && onOpenModal && (
            <button
              type="button"
              onClick={onOpenModal}
              title="Open Interactive Full-Screen Topology Workspace"
              className="px-3 py-1.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-xs font-semibold flex items-center gap-1.5 shadow-sm transition active:scale-95"
            >
              <Maximize2 className="w-3.5 h-3.5" />
              <span>Open Interactive Topology</span>
            </button>
          )}
        </div>

        {/* Refined Legend */}
        <div className="flex items-center gap-3 text-xs font-mono text-slate-400 select-none">
          <span className="flex items-center gap-1.5 text-blue-400">
            <span className="w-2.5 h-2.5 rounded bg-blue-600 border border-blue-400 inline-block" /> Subnet Hub
          </span>
          <span className="flex items-center gap-1.5 text-purple-400">
            <span className="w-2.5 h-2.5 rotate-45 bg-purple-600 border border-purple-400 inline-block" /> Router
          </span>
          <span className="flex items-center gap-1.5 text-emerald-400">
            <span className="w-2.5 h-2.5 rounded-sm bg-emerald-700 border border-emerald-400 inline-block" /> Asset Node
          </span>
          <span className="flex items-center gap-1.5 text-amber-400">
            <span className="w-2 h-2 rounded-full bg-amber-500 inline-block" /> Service
          </span>
        </div>
      </div>

      {/* Main Grid: SVG Canvas + Inspector Drawer */}
      <div
        className={`grid grid-cols-1 ${
          inspectorOpen ? 'lg:grid-cols-4' : 'grid-cols-1'
        } gap-4 ${isModal ? 'flex-1 min-h-0 h-full' : ''}`}
      >
        {/* SVG Graph Canvas Container */}
        <div
          ref={containerRef}
          className={`${
            inspectorOpen ? 'lg:col-span-3' : 'col-span-full'
          } bg-[#080c14] border border-slate-800 rounded-xl relative ${
            isModal ? 'h-full min-h-[460px]' : 'min-h-[560px] h-[640px]'
          } flex items-center justify-center overflow-hidden shadow-inner transition-all duration-150 ${
            isPanning ? 'cursor-grabbing' : 'cursor-grab'
          }`}
        >
          {/* Subtle Canvas Status Indicator */}
          <div className="absolute top-3 left-3 z-10 flex items-center gap-2 text-[10px] font-mono text-slate-400 bg-slate-900/90 border border-slate-800 px-2.5 py-1 rounded-md shadow-sm select-none pointer-events-none">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
            <span>Interactive Twin: Drag Pan • Scroll Zoom • Click Node or Flow</span>
          </div>

          {searchQuery && (
            <div className="absolute top-3 right-3 z-10 text-[10px] font-mono text-amber-300 bg-amber-950/80 border border-amber-800/80 px-2.5 py-1 rounded-md shadow select-none">
              Found {matchingNodeIds.size} matching node{matchingNodeIds.size === 1 ? '' : 's'}
            </div>
          )}

          {topology && (topology.nodes || []).length > 0 ? (
            <svg
              ref={svgRef}
              className="w-full h-full select-none"
              onMouseDown={handleMouseDown}
              onMouseMove={handleMouseMove}
              onMouseUp={handleMouseUp}
              onMouseLeave={handleMouseUp}
            >
              <defs>
                {/* Arrowhead Markers */}
                <marker
                  id="arrow-cyan"
                  viewBox="0 0 10 10"
                  refX="10"
                  refY="5"
                  markerWidth="6"
                  markerHeight="6"
                  orient="auto-start-reverse"
                >
                  <path d="M 0 0 L 10 5 L 0 10 z" fill="#06b6d4" />
                </marker>
                <marker
                  id="arrow-amber"
                  viewBox="0 0 10 10"
                  refX="10"
                  refY="5"
                  markerWidth="6"
                  markerHeight="6"
                  orient="auto-start-reverse"
                >
                  <path d="M 0 0 L 10 5 L 0 10 z" fill="#f59e0b" />
                </marker>
                <marker
                  id="arrow-purple"
                  viewBox="0 0 10 10"
                  refX="10"
                  refY="5"
                  markerWidth="6"
                  markerHeight="6"
                  orient="auto-start-reverse"
                >
                  <path d="M 0 0 L 10 5 L 0 10 z" fill="#a855f7" />
                </marker>
                <marker
                  id="arrow-selected"
                  viewBox="0 0 10 10"
                  refX="10"
                  refY="5"
                  markerWidth="7"
                  markerHeight="7"
                  orient="auto-start-reverse"
                >
                  <path d="M 0 0 L 10 5 L 0 10 z" fill="#60a5fa" />
                </marker>

                {/* Subtle dark canvas grid texture */}
                <pattern id="twin-dot-grid" width="36" height="36" patternUnits="userSpaceOnUse">
                  <circle cx="18" cy="18" r="0.75" fill="#334155" opacity="0.4" />
                </pattern>
              </defs>

              {/* Background Canvas Drag Surface */}
              <rect
                data-bg="true"
                x="-10000"
                y="-10000"
                width="20000"
                height="20000"
                fill="url(#twin-dot-grid)"
              />

              {/* Pan & Zoom Group */}
              <g transform={`translate(${panOffset.x}, ${panOffset.y}) scale(${zoomLevel})`}>
                {/* 1. SUBNET CONTAINERS */}
                {layout.subnetContainers.map((sc) => {
                  return (
                    <g key={sc.subnetId} className="transition-all duration-200">
                      <title>{`Subnet CIDR: ${sc.cidr}\nHosts: ${sc.hostCount}`}</title>
                      {/* Container Background Box */}
                      <rect
                        x={sc.x}
                        y={sc.y}
                        width={sc.width}
                        height={sc.height}
                        rx="10"
                        fill="#0a1224"
                        stroke="#1e293b"
                        strokeWidth="1.5"
                        className="transition hover:border-slate-700"
                      />

                      {/* Container Header Bar */}
                      <rect
                        x={sc.x}
                        y={sc.y}
                        width={sc.width}
                        height="46"
                        rx="10"
                        fill="#0f1d3d"
                        stroke="#1e3a8a"
                        strokeWidth="1"
                      />
                      {/* Square off bottom corners of header */}
                      <rect
                        x={sc.x}
                        y={sc.y + 32}
                        width={sc.width}
                        height="14"
                        fill="#0f1d3d"
                      />
                      <line
                        x1={sc.x}
                        y1={sc.y + 46}
                        x2={sc.x + sc.width}
                        y2={sc.y + 46}
                        stroke="#1e3a8a"
                        strokeWidth="1"
                        opacity="0.8"
                      />

                      {/* Subnet Icon Box */}
                      <g transform={`translate(${sc.x + 14}, ${sc.y + 13})`}>
                        <rect x="0" y="0" width="20" height="20" rx="4" fill="#1d4ed8" fillOpacity="0.3" stroke="#3b82f6" strokeWidth="1" />
                        <path d="M 5 10 L 15 10 M 10 5 L 10 15" stroke="#60a5fa" strokeWidth="1.5" strokeLinecap="round" />
                      </g>

                      {/* Monospace CIDR Title */}
                      <text
                        x={sc.x + 42}
                        y={sc.y + 27}
                        fill="#93c5fd"
                        fontSize="12.5"
                        fontFamily="monospace"
                        fontWeight="bold"
                        className="select-none"
                      >
                        {sc.cidr}
                      </text>

                      {/* Subnet Label / Name if different from CIDR */}
                      {sc.label && !sc.label.includes(sc.cidr) && (
                        <text
                          x={sc.x + 42}
                          y={sc.y + 39}
                          fill="#64748b"
                          fontSize="9.5"
                          fontFamily="sans-serif"
                          className="select-none"
                        >
                          {sc.label.length > 22 ? sc.label.slice(0, 20) + '...' : sc.label}
                        </text>
                      )}

                      {/* Host count & services badge pill */}
                      <g transform={`translate(${sc.x + sc.width - 65}, ${sc.y + 14})`}>
                        <rect x="-65" y="0" width="90" height="18" rx="9" fill="#1e293b" fillOpacity="0.8" stroke="#334155" strokeWidth="1" />
                        <text
                          x="-20"
                          y="12"
                          fill="#94a3b8"
                          fontSize="9.5"
                          fontFamily="monospace"
                          textAnchor="middle"
                          className="select-none font-semibold"
                        >
                          {sc.hostCount} {sc.hostCount === 1 ? 'host' : 'hosts'}
                        </text>
                      </g>

                      {/* Collapse / Expand Toggle Button */}
                      <g
                        transform={`translate(${sc.x + sc.width - 32}, ${sc.y + 13})`}
                        onClick={(ev) => {
                          ev.stopPropagation();
                          toggleSubnetCollapse(sc.subnetId);
                        }}
                        className="cursor-pointer group/btn"
                      >
                        <title>{sc.isCollapsed ? 'Expand Subnet' : 'Collapse Subnet'}</title>
                        <rect
                          x="0"
                          y="0"
                          width="20"
                          height="20"
                          rx="4"
                          fill="#1e293b"
                          stroke="#334155"
                          className="group-hover/btn:fill-blue-900 group-hover/btn:stroke-blue-500 transition"
                        />
                        <text
                          x="10"
                          y="14"
                          fill="#cbd5e1"
                          fontSize="13"
                          fontFamily="monospace"
                          fontWeight="bold"
                          textAnchor="middle"
                          className="select-none group-hover/btn:fill-white"
                        >
                          {sc.isCollapsed ? '+' : '−'}
                        </text>
                      </g>
                    </g>
                  );
                })}

                {/* 2. TRANSIT / ROUTING TIER CONTAINER */}
                {layout.transitTier && (
                  <g className="select-none">
                    <rect
                      x={layout.transitTier.x}
                      y={layout.transitTier.y}
                      width={layout.transitTier.width}
                      height={layout.transitTier.height}
                      rx="10"
                      fill="#120924"
                      stroke="#4c1d95"
                      strokeWidth="1.2"
                      strokeDasharray="6,4"
                    />
                    <text
                      x={layout.transitTier.x + 16}
                      y={layout.transitTier.y + 26}
                      fill="#c084fc"
                      fontSize="11"
                      fontFamily="monospace"
                      fontWeight="bold"
                    >
                      Transit & Routing Tier
                    </text>
                  </g>
                )}

                {/* 3. EXTERNAL / UNRESOLVED CONTAINER */}
                {layout.unresolvedContainer && (
                  <g className="select-none">
                    <rect
                      x={layout.unresolvedContainer.x}
                      y={layout.unresolvedContainer.y}
                      width={layout.unresolvedContainer.width}
                      height={layout.unresolvedContainer.height}
                      rx="10"
                      fill="#111217"
                      stroke="#3f3f46"
                      strokeWidth="1.2"
                      strokeDasharray="5,4"
                    />
                    <text
                      x={layout.unresolvedContainer.x + 16}
                      y={layout.unresolvedContainer.y + 26}
                      fill="#a1a1aa"
                      fontSize="11"
                      fontFamily="monospace"
                      fontWeight="bold"
                    >
                      External & Inferred Entities
                    </text>
                  </g>
                )}

                {/* 4. EDGES */}
                {layout.routedEdges
                  .filter((re) => {
                    if (evidenceClassFilter === 'ALL') return true;
                    return re.edge.evidence_class === evidenceClassFilter;
                  })
                  .map((re) => {
                    const isSelected =
                      selectedEdge && (selectedEdge.edge_id || selectedEdge.id) === re.edgeId;
                    const isConnected =
                      connectedEdgeIds.has(re.edgeId) || connectedEdgeIds.has(re.edge.id || '');
                    const hasFocus = Boolean(activeFocusId);
                    const isDimmed = hasFocus && !isConnected && !isSelected;

                    const markerUrl = isSelected
                      ? 'url(#arrow-selected)'
                      : isConnected
                      ? 'url(#arrow-cyan)'
                      : re.strokeColor === '#06b6d4'
                      ? 'url(#arrow-cyan)'
                      : re.strokeColor === '#f59e0b'
                      ? 'url(#arrow-amber)'
                      : re.strokeColor === '#a855f7'
                      ? 'url(#arrow-purple)'
                      : 'url(#arrow-cyan)';

                    return (
                      <g
                        key={re.edgeId}
                        onClick={(ev) => {
                          ev.stopPropagation();
                          onSelectEdge(re.edge);
                          onSelectNode(null);
                        }}
                        className="cursor-pointer group"
                        opacity={isDimmed ? 0.12 : isSelected || isConnected ? 1 : 0.65}
                      >
                        <title>
                          {`Edge: ${re.sourceNodeId} -> ${re.targetNodeId}\nProtocol: ${re.protocol}\nPackets: ${re.edge.packet_count}\nBytes: ${re.edge.byte_count}`}
                        </title>
                        {/* Hover hit area */}
                        <path
                          d={re.pathData}
                          fill="none"
                          stroke="transparent"
                          strokeWidth={16}
                        />
                        {/* Soft glow halo for selected/connected edge */}
                        {(isSelected || isConnected) && (
                          <path
                            d={re.pathData}
                            fill="none"
                            stroke={isSelected ? '#60a5fa' : '#38bdf8'}
                            strokeWidth={isSelected ? 6 : 4}
                            opacity={0.35}
                          />
                        )}
                        {/* Core visible connection line */}
                        <path
                          d={re.pathData}
                          fill="none"
                          stroke={isSelected ? '#60a5fa' : isConnected ? '#38bdf8' : re.strokeColor}
                          strokeWidth={isSelected ? 3 : isConnected ? 2.5 : re.strokeWidth}
                          strokeDasharray={re.isDashed ? '5,4' : undefined}
                          markerEnd={markerUrl}
                          className="group-hover:stroke-blue-300 transition"
                        />
                      </g>
                    );
                  })}

                {/* 5. NODES */}
                {Array.from(layout.placedNodes.values())
                  .filter((pn) => !pn.isCollapsed)
                  .filter((pn) => {
                    if (nodeTypeFilter === 'ALL') return true;
                    return pn.node.node_type === nodeTypeFilter;
                  })
                  .map((pn) => {
                    const isSelected =
                      selectedNode && (selectedNode.node_id || selectedNode.id) === pn.nodeId;
                    const isHovered = hoveredNodeId === pn.nodeId;
                    const isConnected = connectedNodeIds.has(pn.nodeId);
                    const isMatched = matchingNodeIds.has(pn.nodeId);
                    const hasFocus = Boolean(activeFocusId);
                    const isDimmed = hasFocus && !isConnected && !isSelected && !isHovered && !isMatched;

                    // If node is a Subnet root, skip rendering since container header already represents it
                    if (pn.node.node_type === 'SUBNET') return null;

                    const primaryLabel = pn.node.label || pn.nodeId;
                    const ipAddresses =
                      (pn.node.properties?.ip_addresses as string[]) || pn.node.ip_addresses || [];
                    const macAddresses =
                      (pn.node.properties?.mac_addresses as string[]) || pn.node.mac_addresses || [];
                    const secondaryLabel =
                      macAddresses[0] || ipAddresses[0] || 'Host Endpoint';

                    return (
                      <g
                        key={pn.nodeId}
                        transform={`translate(${pn.box.x}, ${pn.box.y})`}
                        onClick={(ev) => {
                          ev.stopPropagation();
                          onSelectNode(pn.node);
                          onSelectEdge(null);
                        }}
                        onMouseEnter={() => setHoveredNodeId(pn.nodeId)}
                        onMouseLeave={() => setHoveredNodeId(null)}
                        className="cursor-pointer group"
                        opacity={isDimmed ? 0.2 : 1}
                      >
                        <title>
                          {`Node: ${pn.node.label}\nType: ${pn.node.node_type}\nID: ${pn.nodeId}`}
                        </title>

                        {/* Search match highlight halo */}
                        {isMatched && (
                          <rect
                            x="-4"
                            y="-4"
                            width={pn.box.width + 8}
                            height={pn.box.height + 8}
                            rx="10"
                            fill="none"
                            stroke="#f59e0b"
                            strokeWidth="2.5"
                            className="animate-pulse"
                          />
                        )}

                        {/* ROUTER CARD */}
                        {pn.node.node_type === 'ROUTER' ? (
                          <g>
                            <rect
                              x="0"
                              y="0"
                              width={pn.box.width}
                              height={pn.box.height}
                              rx="8"
                              fill="#180e29"
                              stroke={isSelected ? '#c084fc' : isConnected ? '#a855f7' : isHovered ? '#7e22ce' : '#4c1d95'}
                              strokeWidth={isSelected ? '2.5' : isConnected ? '1.8' : '1.2'}
                              className="transition"
                            />
                            {/* Router Gateway Icon */}
                            <g transform="translate(10, 12)">
                              <rect x="0" y="0" width="24" height="24" rx="5" fill="#2e1065" stroke="#6b21a8" strokeWidth="1" />
                              <polygon points="12,5 19,12 12,19 5,12" fill="none" stroke="#e9d5ff" strokeWidth="1.5" />
                              <circle cx="12" cy="12" r="2" fill="#c084fc" />
                            </g>
                            <text
                              x="42"
                              y="23"
                              fill="#f3e8ff"
                              fontSize="11.5"
                              fontFamily="monospace"
                              fontWeight="bold"
                              className="select-none"
                            >
                              {primaryLabel.length > 18 ? primaryLabel.slice(0, 16) + '..' : primaryLabel}
                            </text>
                            <text
                              x="42"
                              y="37"
                              fill="#c084fc"
                              fontSize="9.5"
                              fontFamily="monospace"
                              className="select-none"
                            >
                              {ipAddresses[0] || 'Default Gateway'}
                            </text>
                          </g>
                        ) : pn.node.node_type === 'SERVICE' ? (
                          /* DOCKED SERVICE CHIP */
                          <g>
                            <rect
                              x="0"
                              y="0"
                              width={pn.box.width}
                              height={pn.box.height}
                              rx="4"
                              fill="#1c1103"
                              stroke={isSelected ? '#fde047' : isHovered ? '#d97706' : '#78350f'}
                              strokeWidth={isSelected ? '2' : '1'}
                              className="transition"
                            />
                            <text
                              x="8"
                              y="15"
                              fill="#fef08a"
                              fontSize="10"
                              fontFamily="monospace"
                              fontWeight="semibold"
                              className="select-none"
                            >
                              {primaryLabel.length > 22 ? primaryLabel.slice(0, 20) + '..' : primaryLabel}
                            </text>
                          </g>
                        ) : (
                          /* STANDARD ASSET CARD */
                          <g>
                            <rect
                              x="0"
                              y="0"
                              width={pn.box.width}
                              height={pn.box.height}
                              rx="8"
                              fill="#0f172a"
                              stroke={
                                isSelected
                                  ? '#3b82f6'
                                  : isConnected
                                  ? '#10b981'
                                  : isHovered
                                  ? '#334155'
                                  : '#1e293b'
                              }
                              strokeWidth={isSelected ? '2.5' : isConnected ? '1.8' : '1.2'}
                              className="transition"
                            />
                            {/* Device Icon Tile */}
                            <rect
                              x="10"
                              y="12"
                              width="24"
                              height="24"
                              rx="5"
                              fill="#1e293b"
                              stroke="#334155"
                              strokeWidth="1"
                            />
                            {/* Status dot in corner of icon tile */}
                            <circle
                              cx="31"
                              cy="15"
                              r="3.5"
                              fill={
                                pn.node.properties?.identity_status === 'CONFIRMED'
                                  ? '#10b981'
                                  : pn.node.properties?.identity_status === 'PROBABLE'
                                  ? '#06b6d4'
                                  : '#f59e0b'
                              }
                              stroke="#0f172a"
                              strokeWidth="1.5"
                            />
                            {/* Server / Device glyph inside icon box */}
                            <path
                              d="M 15 19 L 29 19 M 15 24 L 29 24 M 15 29 L 29 29"
                              stroke="#94a3b8"
                              strokeWidth="1.5"
                              strokeLinecap="round"
                            />

                            {/* Primary Label */}
                            <text
                              x="42"
                              y="23"
                              fill="#f8fafc"
                              fontSize="11.5"
                              fontFamily="monospace"
                              fontWeight="bold"
                              className="select-none"
                            >
                              {primaryLabel.length > 17 ? primaryLabel.slice(0, 15) + '..' : primaryLabel}
                            </text>

                            {/* Secondary Label */}
                            <text
                              x="42"
                              y="37"
                              fill="#94a3b8"
                              fontSize="9.5"
                              fontFamily="monospace"
                              className="select-none"
                            >
                              {secondaryLabel.length > 20 ? secondaryLabel.slice(0, 18) + '..' : secondaryLabel}
                            </text>
                          </g>
                        )}
                      </g>
                    );
                  })}
              </g>
            </svg>
          ) : (
            <div className="text-slate-500 text-xs">
              No topology graph elements available. Run capture analysis or import configurations to reconstruct the graph.
            </div>
          )}
        </div>

        {/* Comprehensive Detail Inspector Panel */}
        {inspectorOpen && (
          <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 space-y-4 shadow-sm flex flex-col">
          {selectedNode ? (
            <div>
              <div className="flex items-start justify-between border-b border-slate-800 pb-3">
                <div>
                  <div className="text-[10px] uppercase font-mono text-slate-400">Topology Node</div>
                  <h4 className="text-sm font-bold text-white font-mono mt-0.5 break-all">{selectedNode.label}</h4>
                </div>
                <div className="flex items-center gap-2">
                  {renderBadge(selectedNode.evidence_class)}
                  <button
                    onClick={() => onSelectNode(null)}
                    title="Close Inspector & Return to Full Graph"
                    className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white transition"
                  >
                    <X className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>

              <div className="mt-3 space-y-3 text-xs">
                <div>
                  <span className="text-slate-400 font-medium">Type:</span>{' '}
                  <span className="font-mono text-indigo-400 uppercase font-semibold">
                    {selectedNode.node_type}
                  </span>
                </div>

                <div>
                  <span className="text-slate-400 font-medium">Node ID:</span>{' '}
                  <span className="font-mono text-slate-300 break-all">{selectedNode.node_id || selectedNode.id}</span>
                </div>

                {((selectedNode.properties?.ip_addresses as string[]) || selectedNode.ip_addresses || []).length > 0 && (
                  <div>
                    <div className="text-slate-400 font-medium mb-1">IP Addresses:</div>
                    <div className="flex flex-wrap gap-1 font-mono">
                      {((selectedNode.properties?.ip_addresses as string[]) || selectedNode.ip_addresses || []).map((ip) => (
                        <span key={ip} className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-200 text-[10px]">
                          {ip}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {(selectedNode.properties?.cidr_prefix || selectedNode.subnet_cidr) && (
                  <div>
                    <span className="text-slate-400 font-medium">Subnet CIDR:</span>{' '}
                    <span className="font-mono text-cyan-400">
                      {String(selectedNode.properties?.cidr_prefix || selectedNode.subnet_cidr)}
                    </span>
                  </div>
                )}

                {(selectedNode.properties?.port || selectedNode.service_port) && (
                  <div>
                    <span className="text-slate-400 font-medium">Service Port:</span>{' '}
                    <span className="font-mono text-amber-400">
                      {String(selectedNode.properties?.port || selectedNode.service_port)}
                    </span>
                  </div>
                )}

                {((selectedNode.properties?.mac_addresses as string[]) || selectedNode.mac_addresses || []).length > 0 && (
                  <div>
                    <span className="text-slate-400 font-medium">MACs:</span>{' '}
                    <span className="font-mono text-slate-400">
                      {((selectedNode.properties?.mac_addresses as string[]) || selectedNode.mac_addresses || []).join(', ')}
                    </span>
                  </div>
                )}

                <div className="pt-2 border-t border-slate-800">
                  <div className="text-slate-400 font-medium mb-1">Adjacent Relationships:</div>
                  {(topology?.edges || []).filter(
                    (e) =>
                      e.source_node_id === (selectedNode.node_id || selectedNode.id) ||
                      e.target_node_id === (selectedNode.node_id || selectedNode.id)
                  ).length === 0 ? (
                    <div className="text-slate-500 italic text-[11px]">No adjacent graph edges.</div>
                  ) : (
                    <div className="space-y-1 max-h-44 overflow-y-auto font-mono text-[10px]">
                      {(topology?.edges || [])
                        .filter(
                          (e) =>
                            e.source_node_id === (selectedNode.node_id || selectedNode.id) ||
                            e.target_node_id === (selectedNode.node_id || selectedNode.id)
                        )
                        .map((e, idx) => (
                          <div
                            key={e.edge_id || e.id || idx}
                            onClick={() => {
                              onSelectEdge(e);
                              onSelectNode(null);
                            }}
                            className="p-1.5 bg-slate-950 border border-slate-800 hover:border-slate-700 rounded flex items-center justify-between cursor-pointer transition"
                          >
                            <span className="text-slate-300">{e.edge_type}</span>
                            {renderBadge(e.evidence_class)}
                          </div>
                        ))}
                    </div>
                  )}
                </div>

                {/* Collapsible Technical Metadata */}
                {selectedNode.properties && Object.keys(selectedNode.properties).length > 0 && (
                  <div className="pt-2 border-t border-slate-800">
                    <button
                      type="button"
                      onClick={() => setShowRawProperties((p) => !p)}
                      className="flex items-center gap-1 text-[11px] text-slate-400 hover:text-slate-200 transition font-mono"
                    >
                      {showRawProperties ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
                      <span>Technical Properties</span>
                    </button>
                    {showRawProperties && (
                      <div className="mt-1.5 p-2 rounded bg-slate-950 border border-slate-800 font-mono text-[10px] space-y-1 max-h-36 overflow-y-auto">
                        {Object.entries(selectedNode.properties).map(([k, v]) => (
                          <div key={k} className="flex justify-between gap-2">
                            <span className="text-slate-400 truncate">{k}:</span>
                            <span className="text-slate-200 text-right truncate">
                              {typeof v === 'object' ? JSON.stringify(v) : String(v)}
                            </span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}

                <div className="pt-3 border-t border-slate-800">
                  <button
                    type="button"
                    onClick={() => onSelectNode(null)}
                    className="w-full py-1.5 px-3 bg-slate-800 hover:bg-slate-700 text-slate-200 hover:text-white rounded text-xs font-mono transition text-center"
                  >
                    Return to Full Graph
                  </button>
                </div>
              </div>
            </div>
          ) : selectedEdge ? (
            <div>
              <div className="flex items-start justify-between border-b border-slate-800 pb-3">
                <div>
                  <div className="text-[10px] uppercase font-mono text-slate-400">Topology Edge</div>
                  <h4 className="text-sm font-bold text-white font-mono mt-0.5">{selectedEdge.edge_type}</h4>
                </div>
                <div className="flex items-center gap-2">
                  {renderBadge(selectedEdge.evidence_class)}
                  <button
                    onClick={() => onSelectEdge(null)}
                    title="Close Inspector & Return to Full Graph"
                    className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white transition"
                  >
                    <X className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>

              <div className="mt-3 space-y-3 text-xs">
                <div>
                  <span className="text-slate-400 font-medium">Edge ID:</span>{' '}
                  <span className="font-mono text-slate-300 break-all">{selectedEdge.edge_id || selectedEdge.id}</span>
                </div>

                <div className="space-y-1 bg-slate-950 p-2.5 rounded-lg border border-slate-800">
                  <div className="flex items-center justify-between text-[11px]">
                    <span className="text-slate-400">Source:</span>
                    <span className="font-mono text-cyan-400 font-semibold truncate max-w-[150px]">
                      {selectedEdge.source_node_id}
                    </span>
                  </div>
                  <div className="flex items-center justify-between text-[11px]">
                    <span className="text-slate-400">Target:</span>
                    <span className="font-mono text-emerald-400 font-semibold truncate max-w-[150px]">
                      {selectedEdge.target_node_id}
                    </span>
                  </div>
                </div>

                <div>
                  <span className="text-slate-400 font-medium">Protocol:</span>{' '}
                  <span className="font-mono text-amber-400">
                    {selectedEdge.primary_protocol || selectedEdge.protocol || 'IP'}
                  </span>
                </div>

                <div className="grid grid-cols-2 gap-2 pt-1">
                  <div className="p-2 bg-slate-950 rounded border border-slate-800">
                    <div className="text-[10px] text-slate-400">Packets</div>
                    <div className="font-mono font-bold text-white">{selectedEdge.packet_count}</div>
                  </div>
                  <div className="p-2 bg-slate-950 rounded border border-slate-800">
                    <div className="text-[10px] text-slate-400">Bytes</div>
                    <div className="font-mono font-bold text-white">{selectedEdge.byte_count}</div>
                  </div>
                </div>

                {(selectedEdge.evidence_ids || []).length > 0 && (
                  <div className="pt-2 border-t border-slate-800">
                    <div className="text-slate-400 font-medium mb-1">Backing Evidence IDs:</div>
                    <div className="space-y-1 max-h-32 overflow-y-auto font-mono text-[10px]">
                      {(selectedEdge.evidence_ids || []).map((eid: string) => (
                        <div key={eid} className="p-1 rounded bg-slate-950 border border-slate-800 text-indigo-300">
                          {eid}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                <div className="pt-3 border-t border-slate-800">
                  <button
                    type="button"
                    onClick={() => onSelectEdge(null)}
                    className="w-full py-1.5 px-3 bg-slate-800 hover:bg-slate-700 text-slate-200 hover:text-white rounded text-xs font-mono transition text-center"
                  >
                    Return to Full Graph
                  </button>
                </div>
              </div>
            </div>
          ) : (
            /* Attractive Onboarding & Digital Twin Overview Card */
            <div className="space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <div className="flex items-center gap-2">
                  <div className="p-1.5 rounded bg-indigo-950/80 border border-indigo-800/60 text-indigo-400">
                    <Layers className="w-4 h-4" />
                  </div>
                  <span className="text-xs font-bold text-white font-mono">Topology Inspector</span>
                </div>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-medium bg-emerald-950/80 text-emerald-400 border border-emerald-800/60">
                  Ready
                </span>
              </div>

              {/* Digital Twin Summary Stats */}
              <div className="grid grid-cols-2 gap-2 text-xs">
                <div className="p-2 bg-slate-950/80 rounded-lg border border-slate-800">
                  <div className="text-[10px] text-slate-400">Known Subnets</div>
                  <div className="text-base font-bold font-mono text-cyan-400 mt-0.5">{subnetCount}</div>
                </div>
                <div className="p-2 bg-slate-950/80 rounded-lg border border-slate-800">
                  <div className="text-[10px] text-slate-400">Transit Routers</div>
                  <div className="text-base font-bold font-mono text-purple-400 mt-0.5">{routerCount}</div>
                </div>
                <div className="p-2 bg-slate-950/80 rounded-lg border border-slate-800">
                  <div className="text-[10px] text-slate-400">Host Assets</div>
                  <div className="text-base font-bold font-mono text-emerald-400 mt-0.5">{assetCount}</div>
                </div>
                <div className="p-2 bg-slate-950/80 rounded-lg border border-slate-800">
                  <div className="text-[10px] text-slate-400">Discovered Services</div>
                  <div className="text-base font-bold font-mono text-amber-400 mt-0.5">{serviceCount}</div>
                </div>
                <div className="p-2 bg-slate-950/80 rounded-lg border border-slate-800 col-span-2">
                  <div className="text-[10px] text-slate-400">Observed Flows</div>
                  <div className="text-base font-bold font-mono text-indigo-400 mt-0.5">{flowCount}</div>
                </div>
              </div>

              {/* Helpful Interaction Guide */}
              <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/80 space-y-2 text-[11px] text-slate-400">
                <div className="font-semibold text-slate-300 flex items-center gap-1.5">
                  <Info className="w-3.5 h-3.5 text-indigo-400" />
                  <span>Interaction Guide</span>
                </div>
                <ul className="space-y-1.5 pl-1 leading-relaxed">
                  <li className="flex items-start gap-1.5">
                    <span className="text-indigo-400 font-bold">•</span>
                    <span>Click any device card to inspect identity, interfaces, and active communication flows.</span>
                  </li>
                  <li className="flex items-start gap-1.5">
                    <span className="text-indigo-400 font-bold">•</span>
                    <span>Click any communication edge to view transport protocol, packet count, and evidence provenance.</span>
                  </li>
                  <li className="flex items-start gap-1.5">
                    <span className="text-indigo-400 font-bold">•</span>
                    <span>Use the search bar or type filters to highlight specific CIDRs, IPs, or services.</span>
                  </li>
                </ul>
              </div>
            </div>
          )}
        </div>
        )}
      </div>
    </div>
  );
};
