import React, { useState, useMemo, useRef, useEffect, useCallback } from 'react';
import {
  ZoomIn,
  ZoomOut,
  Maximize2,
  RotateCcw,
  Search,
  X,
  Layers,
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
  const [zoomLevel, setZoomLevel] = useState<number>(1);
  const [panOffset, setPanOffset] = useState<{ x: number; y: number }>({ x: 0, y: 0 });
  const [isPanning, setIsPanning] = useState<boolean>(false);
  const [panStart, setPanStart] = useState<{ x: number; y: number }>({ x: 0, y: 0 });

  // Filtering & Search states
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [nodeTypeFilter, setNodeTypeFilter] = useState<string>('ALL');
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);
  const [inspectorOpen, setInspectorOpen] = useState<boolean>(true);

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
    return (
      <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium bg-gray-800 text-gray-400 border border-gray-700 font-mono">
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

  // Fit to View Calculation
  const handleFitToView = useCallback(() => {
    if (!containerRef.current || !layout.bounds) return;
    const { clientWidth, clientHeight } = containerRef.current;
    if (clientWidth === 0 || clientHeight === 0) return;

    const b = layout.bounds;
    const scaleX = (clientWidth - 60) / Math.max(b.width, 100);
    const scaleY = (clientHeight - 60) / Math.max(b.height, 100);
    const optimalScale = Math.min(Math.max(0.3, Math.min(scaleX, scaleY)), 1.25);

    const roundedScale = Number(optimalScale.toFixed(2));
    setZoomLevel(roundedScale);

    // Center layout in viewport
    const offsetX = Math.round(clientWidth / 2 - b.centerX * roundedScale);
    const offsetY = Math.round(clientHeight / 2 - b.centerY * roundedScale);
    setPanOffset({ x: offsetX, y: offsetY });
  }, [layout.bounds]);

  // Automatically center on initial load
  useEffect(() => {
    if (topology && (topology.nodes || []).length > 0) {
      handleFitToView();
    }
  }, [topology, handleFitToView]);

  // Zoom and Pan Controls
  const handleZoomIn = () => setZoomLevel((z) => Math.min(3.0, Number((z + 0.15).toFixed(2))));
  const handleZoomOut = () => setZoomLevel((z) => Math.max(0.25, Number((z - 0.15).toFixed(2))));
  const handleResetZoom = () => {
    setZoomLevel(1);
    if (containerRef.current) {
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
    const targetTag = (e.target as HTMLElement).tagName?.toLowerCase();
    if (
      targetTag === 'svg' ||
      (e.target as HTMLElement).getAttribute('data-bg') === 'true' ||
      targetTag === 'rect' && (e.target as HTMLElement).getAttribute('data-bg') === 'true'
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

  const handleWheel = (e: React.WheelEvent<SVGSVGElement>) => {
    e.preventDefault();
    const delta = e.deltaY < 0 ? 0.1 : -0.1;
    setZoomLevel((z) => Math.min(3.0, Math.max(0.25, Number((z + delta).toFixed(2)))));
  };

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
        (n.properties?.primary_ip as string) || '',
      ].map((ip) => ip.toLowerCase());
      const macs = [
        ...(n.mac_addresses || []),
        ...((n.properties?.mac_addresses as string[]) || []),
      ].map((m) => m.toLowerCase());
      const hostnames = ((n.properties?.hostnames as string[]) || []).map((h) => h.toLowerCase());

      if (
        nId.includes(q) ||
        label.includes(q) ||
        ips.some((ip) => ip.includes(q)) ||
        macs.some((m) => m.includes(q)) ||
        hostnames.some((h) => h.includes(q))
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

  return (
    <div
      className={`space-y-3 ${isModal ? 'h-full flex flex-col min-h-0' : ''}`}
      data-testid="topology-graph-container"
    >
      {/* Top Toolbar: Search, Filters, Viewport Controls, Actions, Legend */}
      <div className="flex flex-wrap items-center justify-between gap-3 bg-surface/60 p-2.5 sm:p-3 rounded-lg border border-gray-800 shadow-sm shrink-0">
        <div className="flex flex-wrap items-center gap-2 sm:gap-3">
          {/* Search box with Clear button */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-gray-500 pointer-events-none" />
            <input
              type="text"
              placeholder="Search IP, Host, MAC, ID..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-8 pr-7 py-1 text-xs bg-slate-950/80 border border-gray-800 rounded text-gray-200 placeholder-gray-500 focus:outline-none focus:border-indigo-500 font-mono w-48 sm:w-60"
            />
            {searchQuery && (
              <button
                type="button"
                onClick={() => setSearchQuery('')}
                aria-label="Clear search"
                title="Clear search"
                className="absolute right-2 top-2 text-gray-400 hover:text-white transition"
              >
                <X className="w-3 h-3" />
              </button>
            )}
          </div>

          {/* Node Type Filter */}
          <div className="flex items-center gap-1.5 text-xs text-gray-400">
            <span>Type:</span>
            <select
              value={nodeTypeFilter}
              onChange={(e) => setNodeTypeFilter(e.target.value)}
              className="bg-slate-950/80 border border-gray-800 rounded px-2 py-1 text-xs text-gray-300 focus:outline-none focus:border-indigo-500 font-mono"
            >
              <option value="ALL">All Nodes</option>
              <option value="SUBNET">Subnets Only</option>
              <option value="ROUTER">Routers Only</option>
              <option value="ASSET">Assets Only</option>
              <option value="SERVICE">Services Only</option>
            </select>
          </div>

          {/* Evidence Class Filter */}
          <div className="flex items-center gap-1.5 text-xs text-gray-400">
            <span>Evidence:</span>
            <select
              value={evidenceClassFilter}
              onChange={(e) => onChangeEvidenceFilter(e.target.value)}
              className="bg-slate-950/80 border border-gray-800 rounded px-2 py-1 text-xs text-gray-300 focus:outline-none focus:border-indigo-500 font-mono"
            >
              <option value="ALL">All Relationships</option>
              <option value="DIRECTLY_OBSERVED">Observed Only</option>
              <option value="CONFIGURED">Configured Only</option>
              <option value="INFERRED">Inferred Only</option>
            </select>
          </div>

          {/* Subnet Expand/Collapse All */}
          <div className="flex items-center gap-1 border-l border-gray-800 pl-2 sm:pl-3">
            <button
              onClick={expandAll}
              title="Expand All Subnets"
              className="px-2 py-1 bg-surface-raised hover:bg-gray-800 rounded text-[11px] font-mono text-gray-300 hover:text-white border border-gray-800 transition"
            >
              Expand All
            </button>
            <button
              onClick={collapseAll}
              title="Collapse All Subnets"
              className="px-2 py-1 bg-surface-raised hover:bg-gray-800 rounded text-[11px] font-mono text-gray-300 hover:text-white border border-gray-800 transition"
            >
              Collapse All
            </button>
          </div>

          {/* Canvas Zoom & View Controls */}
          <div className="flex items-center gap-1 bg-slate-950/80 border border-gray-800 rounded px-1.5 py-0.5">
            <button
              type="button"
              onClick={handleZoomIn}
              title="Zoom In (+)"
              className="p-1 hover:bg-gray-800 rounded text-gray-300 hover:text-white transition"
            >
              <ZoomIn className="w-3.5 h-3.5" />
            </button>
            <button
              type="button"
              onClick={handleZoomOut}
              title="Zoom Out (-)"
              className="p-1 hover:bg-gray-800 rounded text-gray-300 hover:text-white transition"
            >
              <ZoomOut className="w-3.5 h-3.5" />
            </button>
            <button
              type="button"
              onClick={handleFitToView}
              title="Fit Entire Topology to View"
              className="p-1 hover:bg-gray-800 rounded text-gray-300 hover:text-white transition"
            >
              <Maximize2 className="w-3.5 h-3.5 text-indigo-400" />
            </button>
            <button
              type="button"
              onClick={handleResetZoom}
              title="Reset 100%"
              className="px-1.5 py-0.5 hover:bg-gray-800 rounded text-[10px] font-mono text-gray-300 hover:text-white transition"
            >
              {(zoomLevel * 100).toFixed(0)}%
            </button>
          </div>

          {/* Reset All Filters & Viewport */}
          <button
            type="button"
            onClick={handleResetAll}
            title="Reset All Filters, Search, and Viewport"
            className="px-2 py-1 bg-surface-raised hover:bg-gray-800 rounded text-[11px] font-mono text-gray-300 hover:text-white border border-gray-800 transition flex items-center gap-1"
          >
            <RotateCcw className="w-3 h-3 text-gray-400" />
            <span>Reset All</span>
          </button>

          {/* Details Inspector Toggle */}
          <button
            type="button"
            onClick={() => setInspectorOpen((prev) => !prev)}
            title={inspectorOpen ? 'Hide Details Inspector' : 'Show Details Inspector'}
            className={`px-2 py-1 rounded text-[11px] font-mono border transition flex items-center gap-1.5 ${
              inspectorOpen
                ? 'bg-indigo-950/70 border-indigo-700/60 text-indigo-300'
                : 'bg-surface-raised border-gray-800 text-gray-400 hover:text-white'
            }`}
          >
            <Layers className="w-3 h-3" />
            <span className="hidden sm:inline">{inspectorOpen ? 'Hide Details' : 'Show Details'}</span>
          </button>

          {/* In-Page Open Modal Action */}
          {!isModal && onOpenModal && (
            <button
              type="button"
              onClick={onOpenModal}
              title="Open Interactive Full-Screen Topology Workspace"
              className="px-2.5 py-1 bg-indigo-600 hover:bg-indigo-500 text-white rounded text-xs font-semibold flex items-center gap-1.5 shadow-sm transition active:scale-95"
            >
              <Maximize2 className="w-3.5 h-3.5" />
              <span>Open Interactive Topology</span>
            </button>
          )}
        </div>

        {/* Legend */}
        <div className="flex items-center gap-3 sm:gap-4 text-xs font-mono">
          <span className="flex items-center gap-1.5 text-blue-400">
            <span className="w-2.5 h-2.5 rounded bg-blue-600 border border-blue-400 inline-block" /> Subnet Hub
          </span>
          <span className="flex items-center gap-1.5 text-purple-400">
            <span className="w-2.5 h-2.5 rotate-45 bg-purple-600 border border-purple-400 inline-block" /> Router
          </span>
          <span className="flex items-center gap-1.5 text-emerald-400">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-600 border border-emerald-400 inline-block" /> Asset Node
          </span>
          <span className="flex items-center gap-1.5 text-amber-400">
            <span className="w-2.5 h-2.5 rounded bg-amber-600 border border-amber-400 inline-block" /> Service
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
          } bg-slate-950 border border-gray-800 rounded-lg relative ${
            isModal ? 'h-full min-h-[460px]' : 'min-h-[560px] h-[640px]'
          } flex items-center justify-center overflow-hidden shadow-inner transition-all duration-150 ${
            isPanning ? 'cursor-grabbing' : 'cursor-grab'
          }`}
        >
          {/* Interaction status banner */}
          <div className="absolute top-3 left-3 z-10 flex items-center gap-2 text-[10px] font-mono text-gray-400 bg-slate-900/90 border border-gray-800 px-2.5 py-1 rounded shadow select-none pointer-events-none">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
            <span>Interactive Clustered Canvas: Drag Pan | Scroll Zoom | Click Node or Edge</span>
          </div>

          {searchQuery && (
            <div className="absolute top-3 right-3 z-10 text-[10px] font-mono text-amber-300 bg-amber-950/80 border border-amber-800/80 px-2.5 py-1 rounded shadow select-none">
              Found {matchingNodeIds.size} matching node{matchingNodeIds.size === 1 ? '' : 's'}
            </div>
          )}

          {topology && (topology.nodes || []).length > 0 ? (
            <svg
              className="w-full h-full select-none"
              onMouseDown={handleMouseDown}
              onMouseMove={handleMouseMove}
              onMouseUp={handleMouseUp}
              onMouseLeave={handleMouseUp}
              onWheel={handleWheel}
            >
              <defs>
                {/* Arrowhead Markers for Protocols */}
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

                {/* Canvas grid pattern */}
                <pattern id="twin-dot-grid" width="36" height="36" patternUnits="userSpaceOnUse">
                  <circle cx="18" cy="18" r="0.75" fill="#334155" opacity="0.6" />
                </pattern>
              </defs>

              {/* Background Canvas Drag Surface */}
              <rect
                data-bg="true"
                x="-5000"
                y="-5000"
                width="10000"
                height="10000"
                fill="url(#twin-dot-grid)"
              />

              {/* Pan & Zoom Group */}
              <g transform={`translate(${panOffset.x}, ${panOffset.y}) scale(${zoomLevel})`}>
                {/* 1. SUBNET CONTAINERS */}
                {layout.subnetContainers.map((sc) => {
                  return (
                    <g key={sc.subnetId} className="transition-all duration-200">
                      <title>{`Subnet: ${sc.label} (${sc.cidr})\nHosts: ${sc.hostCount}`}</title>
                      {/* Container Background Box */}
                      <rect
                        x={sc.x}
                        y={sc.y}
                        width={sc.width}
                        height={sc.height}
                        rx="10"
                        fill="#0b1329"
                        stroke="#1e293b"
                        strokeWidth="1.5"
                        className="transition hover:border-blue-500/40"
                      />

                      {/* Container Header Bar */}
                      <rect
                        x={sc.x}
                        y={sc.y}
                        width={sc.width}
                        height="44"
                        rx="10"
                        fill="#0f1d40"
                        stroke="#1e3a8a"
                        strokeWidth="1"
                      />
                      {/* Square off bottom corners of header */}
                      <rect
                        x={sc.x}
                        y={sc.y + 30}
                        width={sc.width}
                        height="14"
                        fill="#0f1d40"
                      />

                      {/* Subnet Icon */}
                      <g transform={`translate(${sc.x + 14}, ${sc.y + 14})`}>
                        <rect x="0" y="0" width="16" height="16" rx="3" fill="#2563eb" />
                        <path d="M 4 8 L 12 8 M 8 4 L 8 12" stroke="#ffffff" strokeWidth="1.5" />
                      </g>

                      {/* Header Title */}
                      <text
                        x={sc.x + 38}
                        y={sc.y + 26}
                        fill="#93c5fd"
                        fontSize="12"
                        fontFamily="monospace"
                        fontWeight="bold"
                        className="select-none"
                      >
                        {sc.cidr}
                      </text>

                      {/* Host count badge */}
                      <text
                        x={sc.x + sc.width - 55}
                        y={sc.y + 26}
                        fill="#64748b"
                        fontSize="10"
                        fontFamily="monospace"
                        textAnchor="end"
                        className="select-none font-medium"
                      >
                        {sc.hostCount} {sc.hostCount === 1 ? 'host' : 'hosts'}
                      </text>

                      {/* Collapse / Expand Toggle Button */}
                      <g
                        transform={`translate(${sc.x + sc.width - 34}, ${sc.y + 12})`}
                        onClick={(ev) => {
                          ev.stopPropagation();
                          toggleSubnetCollapse(sc.subnetId);
                        }}
                        className="cursor-pointer"
                      >
                        <title>{sc.isCollapsed ? 'Expand Subnet' : 'Collapse Subnet'}</title>
                        <rect x="0" y="0" width="20" height="20" rx="4" fill="#1e293b" stroke="#334155" />
                        <text
                          x="10"
                          y="14"
                          fill="#cbd5e1"
                          fontSize="12"
                          fontFamily="monospace"
                          fontWeight="bold"
                          textAnchor="middle"
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
                      fill="#1e1035"
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
                      fill="#18181b"
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
                      External & Unresolved
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
                        opacity={isDimmed ? 0.2 : 1}
                      >
                        <title>
                          {`Edge: ${re.sourceNodeId} -> ${re.targetNodeId}\nProtocol: ${re.protocol}\nPackets: ${re.edge.packet_count}\nBytes: ${re.edge.byte_count}`}
                        </title>
                        {/* Hover hit area */}
                        <path
                          d={re.pathData}
                          fill="none"
                          stroke="transparent"
                          strokeWidth={14}
                        />
                        {/* Glow for selected/connected edge */}
                        {(isSelected || isConnected) && (
                          <path
                            d={re.pathData}
                            fill="none"
                            stroke={isSelected ? '#60a5fa' : '#38bdf8'}
                            strokeWidth={isSelected ? 5 : 4}
                            opacity={0.4}
                          />
                        )}
                        {/* Visible Line */}
                        <path
                          d={re.pathData}
                          fill="none"
                          stroke={isSelected ? '#60a5fa' : re.strokeColor}
                          strokeWidth={isSelected ? 3 : re.strokeWidth}
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
                        opacity={isDimmed ? 0.25 : 1}
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
                              fill="#2e1065"
                              stroke={isSelected ? '#c084fc' : '#7e22ce'}
                              strokeWidth={isSelected ? '2.5' : '1.5'}
                              className="group-hover:stroke-purple-300 transition"
                            />
                            {/* Router Icon */}
                            <g transform="translate(10, 14)">
                              <rect x="0" y="0" width="20" height="20" rx="4" fill="#6b21a8" />
                              <polygon points="5,15 15,15 10,5" fill="#f3e8ff" />
                            </g>
                            <text
                              x="38"
                              y="24"
                              fill="#f3e8ff"
                              fontSize="11"
                              fontFamily="monospace"
                              fontWeight="bold"
                            >
                              {pn.node.label.length > 18 ? pn.node.label.slice(0, 16) + '..' : pn.node.label}
                            </text>
                            <text
                              x="38"
                              y="42"
                              fill="#c084fc"
                              fontSize="9"
                              fontFamily="monospace"
                            >
                              {((pn.node.properties?.ip_addresses as string[]) || pn.node.ip_addresses || [])[0] || 'Default Gateway'}
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
                              fill="#451a03"
                              stroke={isSelected ? '#fde047' : '#b45309'}
                              strokeWidth={isSelected ? '2' : '1'}
                              className="group-hover:stroke-amber-400 transition"
                            />
                            <text
                              x="8"
                              y="16"
                              fill="#fde68a"
                              fontSize="10"
                              fontFamily="monospace"
                              fontWeight="semibold"
                            >
                              {pn.node.label.length > 22 ? pn.node.label.slice(0, 20) + '..' : pn.node.label}
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
                              fill="#031f18"
                              stroke={isSelected ? '#34d399' : isConnected ? '#10b981' : '#065f46'}
                              strokeWidth={isSelected ? '2.5' : '1.2'}
                              className="group-hover:stroke-emerald-400 transition"
                            />
                            {/* Status indicator dot */}
                            <circle
                              cx="14"
                              cy="22"
                              r="4.5"
                              fill={
                                pn.node.properties?.identity_status === 'CONFIRMED'
                                  ? '#10b981'
                                  : pn.node.properties?.identity_status === 'PROBABLE'
                                  ? '#06b6d4'
                                  : '#f59e0b'
                              }
                            />
                            {/* Primary Label (IP or Hostname) */}
                            <text
                              x="26"
                              y="26"
                              fill="#ecfdf5"
                              fontSize="11"
                              fontFamily="monospace"
                              fontWeight="bold"
                            >
                              {pn.node.label.length > 18 ? pn.node.label.slice(0, 16) + '..' : pn.node.label}
                            </text>
                            {/* Secondary Label (MAC or Secondary IP) */}
                            <text
                              x="26"
                              y="44"
                              fill="#6ee7b7"
                              fontSize="9"
                              fontFamily="monospace"
                              opacity="0.8"
                            >
                              {((pn.node.properties?.mac_addresses as string[]) || pn.node.mac_addresses || [])[0] ||
                                ((pn.node.properties?.ip_addresses as string[]) || pn.node.ip_addresses || [])[0] ||
                                'Host Endpoint'}
                            </text>
                          </g>
                        )}
                      </g>
                    );
                  })}
              </g>
            </svg>
          ) : (
            <div className="text-gray-500 text-xs">
              No topology graph elements available. Run capture analysis or import configurations to reconstruct the graph.
            </div>
          )}
        </div>

        {/* Comprehensive Detail Inspector Panel */}
        <div className="bg-surface/50 border border-gray-800 rounded-lg p-4 space-y-4 shadow-sm">
          {selectedNode ? (
            <div>
              <div className="flex items-start justify-between border-b border-gray-800 pb-3">
                <div>
                  <div className="text-[10px] uppercase font-mono text-gray-400">Topology Node</div>
                  <h4 className="text-sm font-bold text-white font-mono mt-0.5 break-all">{selectedNode.label}</h4>
                </div>
                <div className="flex items-center gap-2">
                  {renderBadge(selectedNode.evidence_class)}
                  <button
                    onClick={() => onSelectNode(null)}
                    title="Close Inspector & Return to Full Graph"
                    className="p-1 rounded bg-gray-800 hover:bg-gray-700 text-gray-400 hover:text-white transition"
                  >
                    <X className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>

              <div className="mt-3 space-y-3 text-xs">
                <div>
                  <span className="text-gray-400 font-medium">Type:</span>{' '}
                  <span className="font-mono text-indigo-400 uppercase font-semibold">
                    {selectedNode.node_type}
                  </span>
                </div>

                <div>
                  <span className="text-gray-400 font-medium">Node ID:</span>{' '}
                  <span className="font-mono text-gray-300 break-all">{selectedNode.node_id || selectedNode.id}</span>
                </div>

                {((selectedNode.properties?.ip_addresses as string[]) || selectedNode.ip_addresses || []).length > 0 && (
                  <div>
                    <div className="text-gray-400 font-medium mb-1">IP Addresses:</div>
                    <div className="flex flex-wrap gap-1 font-mono">
                      {((selectedNode.properties?.ip_addresses as string[]) || selectedNode.ip_addresses || []).map((ip) => (
                        <span key={ip} className="px-1.5 py-0.5 rounded bg-gray-800 text-gray-200 text-[10px]">
                          {ip}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {(selectedNode.properties?.cidr_prefix || selectedNode.subnet_cidr) && (
                  <div>
                    <span className="text-gray-400 font-medium">Subnet CIDR:</span>{' '}
                    <span className="font-mono text-cyan-400">
                      {String(selectedNode.properties?.cidr_prefix || selectedNode.subnet_cidr)}
                    </span>
                  </div>
                )}

                {(selectedNode.properties?.port || selectedNode.service_port) && (
                  <div>
                    <span className="text-gray-400 font-medium">Service Port:</span>{' '}
                    <span className="font-mono text-amber-400">
                      {String(selectedNode.properties?.port || selectedNode.service_port)}
                    </span>
                  </div>
                )}

                {((selectedNode.properties?.mac_addresses as string[]) || selectedNode.mac_addresses || []).length > 0 && (
                  <div>
                    <span className="text-gray-400 font-medium">MACs:</span>{' '}
                    <span className="font-mono text-gray-400">
                      {((selectedNode.properties?.mac_addresses as string[]) || selectedNode.mac_addresses || []).join(', ')}
                    </span>
                  </div>
                )}

                <div className="pt-2 border-t border-gray-800">
                  <div className="text-gray-400 font-medium mb-1">Adjacent Relationships:</div>
                  {(topology?.edges || []).filter(
                    (e) =>
                      e.source_node_id === (selectedNode.node_id || selectedNode.id) ||
                      e.target_node_id === (selectedNode.node_id || selectedNode.id)
                  ).length === 0 ? (
                    <div className="text-gray-500 italic text-[11px]">No adjacent graph edges.</div>
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
                            className="p-1.5 bg-gray-900 border border-gray-800 hover:border-gray-700 rounded flex items-center justify-between cursor-pointer transition"
                          >
                            <span className="text-gray-300">{e.edge_type}</span>
                            {renderBadge(e.evidence_class)}
                          </div>
                        ))}
                    </div>
                  )}
                </div>

                <div className="pt-3 border-t border-gray-800">
                  <button
                    type="button"
                    onClick={() => onSelectNode(null)}
                    className="w-full py-1.5 px-3 bg-gray-800 hover:bg-gray-700 text-gray-200 hover:text-white rounded text-xs font-mono transition text-center"
                  >
                    Return to Full Graph
                  </button>
                </div>
              </div>
            </div>
          ) : selectedEdge ? (
            <div>
              <div className="flex items-start justify-between border-b border-gray-800 pb-3">
                <div>
                  <div className="text-[10px] uppercase font-mono text-gray-400">Topology Edge</div>
                  <h4 className="text-sm font-bold text-white font-mono mt-0.5">{selectedEdge.edge_type}</h4>
                </div>
                <div className="flex items-center gap-2">
                  {renderBadge(selectedEdge.evidence_class)}
                  <button
                    onClick={() => onSelectEdge(null)}
                    title="Close Inspector & Return to Full Graph"
                    className="p-1 rounded bg-gray-800 hover:bg-gray-700 text-gray-400 hover:text-white transition"
                  >
                    <X className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>

              <div className="mt-3 space-y-3 text-xs">
                <div>
                  <span className="text-gray-400 font-medium">Edge ID:</span>{' '}
                  <span className="font-mono text-gray-300 break-all">{selectedEdge.edge_id || selectedEdge.id}</span>
                </div>

                <div>
                  <span className="text-gray-400 font-medium">Source:</span>{' '}
                  <span className="font-mono text-cyan-400 break-all">{selectedEdge.source_node_id}</span>
                </div>

                <div>
                  <span className="text-gray-400 font-medium">Target:</span>{' '}
                  <span className="font-mono text-emerald-400 break-all">{selectedEdge.target_node_id}</span>
                </div>

                <div>
                  <span className="text-gray-400 font-medium">Protocol:</span>{' '}
                  <span className="font-mono text-amber-400">
                    {selectedEdge.primary_protocol || selectedEdge.protocol || 'IP'}
                  </span>
                </div>

                <div className="grid grid-cols-2 gap-2 pt-1">
                  <div className="p-2 bg-gray-900/80 rounded border border-gray-800">
                    <div className="text-[10px] text-gray-400">Packets</div>
                    <div className="font-mono font-bold text-white">{selectedEdge.packet_count}</div>
                  </div>
                  <div className="p-2 bg-gray-900/80 rounded border border-gray-800">
                    <div className="text-[10px] text-gray-400">Bytes</div>
                    <div className="font-mono font-bold text-white">{selectedEdge.byte_count}</div>
                  </div>
                </div>

                {(selectedEdge.evidence_ids || []).length > 0 && (
                  <div className="pt-2 border-t border-gray-800">
                    <div className="text-gray-400 font-medium mb-1">Backing Evidence IDs:</div>
                    <div className="space-y-1 max-h-32 overflow-y-auto font-mono text-[10px]">
                      {(selectedEdge.evidence_ids || []).map((eid: string) => (
                        <div key={eid} className="p-1 rounded bg-gray-900 border border-gray-800 text-indigo-300">
                          {eid}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                <div className="pt-3 border-t border-gray-800">
                  <button
                    type="button"
                    onClick={() => onSelectEdge(null)}
                    className="w-full py-1.5 px-3 bg-gray-800 hover:bg-gray-700 text-gray-200 hover:text-white rounded text-xs font-mono transition text-center"
                  >
                    Return to Full Graph
                  </button>
                </div>
              </div>
            </div>
          ) : (
            <div className="py-14 text-center text-gray-500 text-xs">
              <Layers className="w-8 h-8 mx-auto text-gray-600 mb-2" />
              <div className="text-gray-300 font-medium mb-1">Topology Inspector</div>
              <p className="text-gray-500 text-[11px] max-w-xs mx-auto leading-relaxed">
                Click any subnet, router, asset, or edge in the graph to inspect detailed attributes, addressing, flow metrics, and evidence provenance.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
