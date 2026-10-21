import React from 'react';
import {
  GitCompare,
  ArrowRight,
  Info,
  RefreshCw,
  AlertTriangle,
  CheckCircle2,
  Layers,
  Network,
} from 'lucide-react';
import type {
  TopologySnapshot,
  SnapshotComparisonDiff,
} from '../../types/intelligence';
import { DiffChangeCard } from './DiffChangeCard';

export interface SnapshotComparisonViewProps {
  snapshots: TopologySnapshot[];
  baseSnapshotId: string;
  targetSnapshotId: string;
  setBaseSnapshotId: (id: string) => void;
  setTargetSnapshotId: (id: string) => void;
  comparisonDiff: SnapshotComparisonDiff | null;
  comparing: boolean;
  diffError: string | null;
  onCompare: () => void;
}

export const SnapshotComparisonView: React.FC<SnapshotComparisonViewProps> = ({
  snapshots,
  baseSnapshotId,
  targetSnapshotId,
  setBaseSnapshotId,
  setTargetSnapshotId,
  comparisonDiff,
  comparing,
  diffError,
  onCompare,
}) => {
  const addedNodesCount = comparisonDiff?.added_nodes?.length || 0;
  const removedNodesCount = comparisonDiff?.removed_nodes?.length || 0;
  const modifiedNodesCount =
    (comparisonDiff?.modified_nodes?.length || 0) +
    (comparisonDiff?.changed_nodes?.length || 0);

  const addedEdgesCount = comparisonDiff?.added_edges?.length || 0;
  const removedEdgesCount = comparisonDiff?.removed_edges?.length || 0;
  const modifiedEdgesCount =
    (comparisonDiff?.modified_edges?.length || 0) +
    (comparisonDiff?.changed_edges?.length || 0);

  const explanationsCount = comparisonDiff?.evidence_explanations?.length || 0;

  const totalDifferences =
    addedNodesCount +
    removedNodesCount +
    modifiedNodesCount +
    addedEdgesCount +
    removedEdgesCount +
    modifiedEdgesCount +
    explanationsCount;

  return (
    <div className="space-y-6">
      {/* Configuration Card */}
      <div className="bg-surface/40 border border-gray-800 rounded-lg p-4">
        <h3 className="text-sm font-semibold text-white mb-1 flex items-center gap-2">
          <GitCompare className="w-4 h-4 text-indigo-400" />
          <span>Differential Topology Comparison</span>
        </h3>
        <p className="text-xs text-gray-400 mb-4">
          Select two immutable snapshots to compute structural diffs with evidence-backed explanations.
        </p>

        <div className="flex flex-col sm:flex-row items-center gap-4">
          <div className="flex-1 w-full">
            <label className="block text-[11px] font-medium text-gray-400 mb-1">
              Base Snapshot (A)
            </label>
            <select
              value={baseSnapshotId}
              onChange={(e) => setBaseSnapshotId(e.target.value)}
              className="w-full bg-surface/80 border border-gray-800 rounded px-3 py-1.5 text-xs text-gray-200 focus:outline-none focus:border-indigo-500 font-mono"
            >
              <option value="">Select Base Snapshot</option>
              {snapshots.map((s) => (
                <option key={s.snapshot_id} value={s.snapshot_id}>
                  {s.name} ({(s.created_at_iso || (s.created_at ? String(s.created_at) : '')).slice(0, 19)}) - {s.node_count} nodes
                </option>
              ))}
            </select>
          </div>

          <div className="flex items-center justify-center p-2 text-gray-500">
            <ArrowRight className="w-4 h-4" />
          </div>

          <div className="flex-1 w-full">
            <label className="block text-[11px] font-medium text-gray-400 mb-1">
              Target Snapshot (B)
            </label>
            <select
              value={targetSnapshotId}
              onChange={(e) => setTargetSnapshotId(e.target.value)}
              className="w-full bg-surface/80 border border-gray-800 rounded px-3 py-1.5 text-xs text-gray-200 focus:outline-none focus:border-indigo-500 font-mono"
            >
              <option value="">Select Target Snapshot</option>
              {snapshots.map((s) => (
                <option key={s.snapshot_id} value={s.snapshot_id}>
                  {s.name} ({(s.created_at_iso || (s.created_at ? String(s.created_at) : '')).slice(0, 19)}) - {s.node_count} nodes
                </option>
              ))}
            </select>
          </div>

          <button
            type="button"
            onClick={onCompare}
            disabled={!baseSnapshotId || !targetSnapshotId || comparing}
            className="mt-5 px-4 py-2 rounded bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold shadow-sm transition disabled:opacity-50 flex items-center gap-2 shrink-0"
          >
            <GitCompare className={`w-4 h-4 ${comparing ? 'animate-spin' : ''}`} />
            <span>{comparing ? 'Comparing...' : 'Run Diff'}</span>
          </button>
        </div>
      </div>

      {/* Error State */}
      {diffError && (
        <div className="p-4 bg-rose-950/40 border border-rose-800/60 rounded-lg text-xs text-rose-300 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
            <span>{diffError}</span>
          </div>
          <button
            type="button"
            onClick={onCompare}
            className="px-2.5 py-1 rounded bg-rose-900/60 hover:bg-rose-800/80 text-rose-200 text-xs font-medium border border-rose-700/60 transition"
          >
            Retry Diff
          </button>
        </div>
      )}

      {/* Loading State */}
      {comparing && (
        <div className="p-8 bg-surface/30 border border-gray-800 rounded-lg flex flex-col items-center justify-center text-center space-y-3">
          <RefreshCw className="w-7 h-7 text-indigo-400 animate-spin" />
          <div className="text-sm font-semibold text-white">Computing Differential Topology Analysis...</div>
          <p className="text-xs text-gray-400 max-w-md">
            Analyzing node presence, topological graph edges, forwarding flow transitions, and cross-referencing auditable evidence lineage.
          </p>
        </div>
      )}

      {/* Idle / Uncompared State */}
      {!comparing && !comparisonDiff && !diffError && (
        <div className="p-10 bg-surface/20 border border-dashed border-gray-800 rounded-lg text-center space-y-2">
          <GitCompare className="w-8 h-8 text-gray-600 mx-auto" />
          <div className="text-sm font-medium text-gray-300">Differential Analysis Ready</div>
          <p className="text-xs text-gray-500 max-w-sm mx-auto">
            Choose a baseline snapshot and a comparison target above, then click <span className="text-indigo-400 font-semibold">Run Diff</span> to inspect structural and relationship deltas.
          </p>
        </div>
      )}

      {/* Results View */}
      {!comparing && comparisonDiff && (
        <div className="space-y-6">
          {/* Diff Summary Badges */}
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
            <div className="p-3 bg-surface/40 border border-gray-800 rounded-lg">
              <span className="text-[10px] text-gray-400 font-medium uppercase tracking-wider">Added Nodes</span>
              <div className="text-xl font-bold font-mono text-emerald-400 mt-0.5">
                +{addedNodesCount}
              </div>
            </div>

            <div className="p-3 bg-surface/40 border border-gray-800 rounded-lg">
              <span className="text-[10px] text-gray-400 font-medium uppercase tracking-wider">Removed Nodes</span>
              <div className="text-xl font-bold font-mono text-rose-400 mt-0.5">
                -{removedNodesCount}
              </div>
            </div>

            <div className="p-3 bg-surface/40 border border-gray-800 rounded-lg">
              <span className="text-[10px] text-gray-400 font-medium uppercase tracking-wider">Modified Nodes</span>
              <div className="text-xl font-bold font-mono text-amber-400 mt-0.5">
                ~{modifiedNodesCount}
              </div>
            </div>

            <div className="p-3 bg-surface/40 border border-gray-800 rounded-lg">
              <span className="text-[10px] text-gray-400 font-medium uppercase tracking-wider">Added Edges</span>
              <div className="text-xl font-bold font-mono text-emerald-400 mt-0.5">
                +{addedEdgesCount}
              </div>
            </div>

            <div className="p-3 bg-surface/40 border border-gray-800 rounded-lg">
              <span className="text-[10px] text-gray-400 font-medium uppercase tracking-wider">Removed Edges</span>
              <div className="text-xl font-bold font-mono text-rose-400 mt-0.5">
                -{removedEdgesCount}
              </div>
            </div>

            <div className="p-3 bg-surface/40 border border-gray-800 rounded-lg">
              <span className="text-[10px] text-gray-400 font-medium uppercase tracking-wider">Modified Edges</span>
              <div className="text-xl font-bold font-mono text-amber-400 mt-0.5">
                ~{modifiedEdgesCount}
              </div>
            </div>
          </div>

          {/* Empty State: Identical Snapshots */}
          {totalDifferences === 0 ? (
            <div className="p-8 bg-surface/30 border border-emerald-900/40 rounded-lg text-center space-y-2.5">
              <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto" />
              <div className="text-sm font-semibold text-emerald-300">Identical Topologies Detected</div>
              <p className="text-xs text-gray-400 max-w-lg mx-auto">
                No structural modifications, added entities, or behavioral edge changes were detected between base snapshot{' '}
                <span className="font-mono text-gray-200 font-semibold">{comparisonDiff.base_snapshot_id}</span> and target snapshot{' '}
                <span className="font-mono text-gray-200 font-semibold">{comparisonDiff.target_snapshot_id}</span>.
              </p>
            </div>
          ) : (
            <>
              {/* Evidence Explanations Section */}
              <div className="bg-surface/50 border border-gray-800 rounded-lg p-4">
                <h4 className="text-xs font-semibold text-white uppercase tracking-wider mb-3 flex items-center justify-between">
                  <span className="flex items-center gap-1.5">
                    <Info className="w-3.5 h-3.5 text-indigo-400" />
                    Evidence-Grounded Explanations
                  </span>
                  <span className="text-[11px] font-mono text-gray-400 lowercase font-normal">
                    {explanationsCount} findings
                  </span>
                </h4>

                {explanationsCount === 0 ? (
                  <div className="text-xs text-gray-500 italic p-3 bg-gray-900/40 rounded border border-gray-800">
                    No narrative evidence explanations recorded for this comparison.
                  </div>
                ) : (
                  <div className="space-y-2">
                    {comparisonDiff.evidence_explanations.map((exp, idx) => (
                      <DiffChangeCard key={idx} change={exp} index={idx} />
                    ))}
                  </div>
                )}
              </div>

              {/* Node Diffs Section */}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 text-xs">
                {/* Added Nodes */}
                <div className="bg-surface/40 border border-gray-800 rounded-lg p-3">
                  <div className="font-semibold text-emerald-400 mb-2 flex items-center justify-between">
                    <span className="flex items-center gap-1.5">
                      <Layers className="w-3.5 h-3.5" />
                      Added Nodes
                    </span>
                    <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-emerald-950/60 text-emerald-300 border border-emerald-800/40">
                      {addedNodesCount}
                    </span>
                  </div>

                  {addedNodesCount === 0 ? (
                    <div className="text-gray-500 italic text-[11px]">No new nodes added in target snapshot.</div>
                  ) : (
                    <div className="space-y-1.5 font-mono max-h-56 overflow-y-auto pr-1">
                      {comparisonDiff.added_nodes.map((n) => {
                        const nid = n.node_id || n.id;
                        return (
                          <div
                            key={nid}
                            className="p-2 bg-emerald-950/20 border border-emerald-900/40 rounded flex flex-col gap-0.5"
                          >
                            <div className="flex items-center justify-between">
                              <span className="text-emerald-300 font-semibold truncate" title={n.label}>
                                {n.label}
                              </span>
                              <span className="text-gray-400 text-[10px] uppercase">{n.node_type}</span>
                            </div>
                            <div className="text-[10px] text-gray-500 truncate" title={nid}>
                              {nid}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>

                {/* Removed Nodes */}
                <div className="bg-surface/40 border border-gray-800 rounded-lg p-3">
                  <div className="font-semibold text-rose-400 mb-2 flex items-center justify-between">
                    <span className="flex items-center gap-1.5">
                      <Layers className="w-3.5 h-3.5" />
                      Removed Nodes
                    </span>
                    <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-rose-950/60 text-rose-300 border border-rose-800/40">
                      {removedNodesCount}
                    </span>
                  </div>

                  {removedNodesCount === 0 ? (
                    <div className="text-gray-500 italic text-[11px]">No nodes removed in target snapshot.</div>
                  ) : (
                    <div className="space-y-1.5 font-mono max-h-56 overflow-y-auto pr-1">
                      {comparisonDiff.removed_nodes.map((n) => {
                        const nid = n.node_id || n.id;
                        return (
                          <div
                            key={nid}
                            className="p-2 bg-rose-950/20 border border-rose-900/40 rounded flex flex-col gap-0.5"
                          >
                            <div className="flex items-center justify-between">
                              <span className="text-rose-300 font-semibold truncate" title={n.label}>
                                {n.label}
                              </span>
                              <span className="text-gray-400 text-[10px] uppercase">{n.node_type}</span>
                            </div>
                            <div className="text-[10px] text-gray-500 truncate" title={nid}>
                              {nid}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>

                {/* Modified Nodes */}
                <div className="bg-surface/40 border border-gray-800 rounded-lg p-3">
                  <div className="font-semibold text-amber-400 mb-2 flex items-center justify-between">
                    <span className="flex items-center gap-1.5">
                      <Layers className="w-3.5 h-3.5" />
                      Modified Nodes
                    </span>
                    <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-amber-950/60 text-amber-300 border border-amber-800/40">
                      {modifiedNodesCount}
                    </span>
                  </div>

                  {modifiedNodesCount === 0 ? (
                    <div className="text-gray-500 italic text-[11px]">No node attributes modified.</div>
                  ) : (
                    <div className="space-y-1.5 font-mono max-h-56 overflow-y-auto pr-1">
                      {(comparisonDiff.modified_nodes || []).map((m, idx) => (
                        <div key={idx} className="p-2 bg-amber-950/20 border border-amber-900/40 rounded space-y-1">
                          <div className="text-amber-300 font-semibold truncate" title={m.node_id}>
                            {m.node_id}
                          </div>
                          {m.changes &&
                            Object.entries(m.changes).map(([fKey, fVal]) => (
                              <div key={fKey} className="text-[10px] text-gray-400 flex items-center gap-1">
                                <span>{fKey}:</span>
                                <span className="line-through text-rose-400">{String(fVal?.from)}</span>
                                <ArrowRight className="w-2.5 h-2.5 text-gray-500" />
                                <span className="text-emerald-400">{String(fVal?.to)}</span>
                              </div>
                            ))}
                        </div>
                      ))}
                      {(comparisonDiff.changed_nodes || []).map((cn, idx) => (
                        <div key={`cn-${idx}`} className="p-2 bg-amber-950/20 border border-amber-900/40 rounded space-y-1">
                          <div className="text-amber-300 font-semibold truncate" title={cn.node_id}>
                            {cn.node_id}
                          </div>
                          {cn.field && (
                            <div className="text-[10px] text-gray-400 flex items-center gap-1">
                              <span>{cn.field}:</span>
                              <span className="line-through text-rose-400">{String(cn.base_value)}</span>
                              <ArrowRight className="w-2.5 h-2.5 text-gray-500" />
                              <span className="text-emerald-400">{String(cn.target_value)}</span>
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>

              {/* Edge Diffs Section */}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 text-xs">
                {/* Added Edges */}
                <div className="bg-surface/40 border border-gray-800 rounded-lg p-3">
                  <div className="font-semibold text-emerald-400 mb-2 flex items-center justify-between">
                    <span className="flex items-center gap-1.5">
                      <Network className="w-3.5 h-3.5" />
                      Added Relationships
                    </span>
                    <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-emerald-950/60 text-emerald-300 border border-emerald-800/40">
                      {addedEdgesCount}
                    </span>
                  </div>

                  {addedEdgesCount === 0 ? (
                    <div className="text-gray-500 italic text-[11px]">No relationships added.</div>
                  ) : (
                    <div className="space-y-1.5 font-mono max-h-56 overflow-y-auto pr-1">
                      {comparisonDiff.added_edges.map((e) => {
                        const eid = e.edge_id || e.id;
                        return (
                          <div
                            key={eid}
                            className="p-2 bg-emerald-950/20 border border-emerald-900/40 rounded flex flex-col gap-1"
                          >
                            <div className="flex items-center justify-between text-emerald-300 font-medium">
                              <span className="truncate max-w-[120px]" title={e.source_node_id}>
                                {e.source_node_id}
                              </span>
                              <ArrowRight className="w-3 h-3 text-emerald-500 shrink-0 mx-1" />
                              <span className="truncate max-w-[120px]" title={e.target_node_id}>
                                {e.target_node_id}
                              </span>
                            </div>
                            <div className="flex items-center justify-between text-[10px] text-gray-400">
                              <span>{e.primary_protocol || e.protocol || 'IP'}</span>
                              <span>{e.packet_count} packets</span>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>

                {/* Removed Edges */}
                <div className="bg-surface/40 border border-gray-800 rounded-lg p-3">
                  <div className="font-semibold text-rose-400 mb-2 flex items-center justify-between">
                    <span className="flex items-center gap-1.5">
                      <Network className="w-3.5 h-3.5" />
                      Removed Relationships
                    </span>
                    <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-rose-950/60 text-rose-300 border border-rose-800/40">
                      {removedEdgesCount}
                    </span>
                  </div>

                  {removedEdgesCount === 0 ? (
                    <div className="text-gray-500 italic text-[11px]">No relationships removed.</div>
                  ) : (
                    <div className="space-y-1.5 font-mono max-h-56 overflow-y-auto pr-1">
                      {comparisonDiff.removed_edges.map((e) => {
                        const eid = e.edge_id || e.id;
                        return (
                          <div
                            key={eid}
                            className="p-2 bg-rose-950/20 border border-rose-900/40 rounded flex flex-col gap-1"
                          >
                            <div className="flex items-center justify-between text-rose-300 font-medium">
                              <span className="truncate max-w-[120px]" title={e.source_node_id}>
                                {e.source_node_id}
                              </span>
                              <ArrowRight className="w-3 h-3 text-rose-500 shrink-0 mx-1" />
                              <span className="truncate max-w-[120px]" title={e.target_node_id}>
                                {e.target_node_id}
                              </span>
                            </div>
                            <div className="flex items-center justify-between text-[10px] text-gray-400">
                              <span>{e.primary_protocol || e.protocol || 'IP'}</span>
                              <span>{e.packet_count} packets</span>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>

                {/* Modified Edges */}
                <div className="bg-surface/40 border border-gray-800 rounded-lg p-3">
                  <div className="font-semibold text-amber-400 mb-2 flex items-center justify-between">
                    <span className="flex items-center gap-1.5">
                      <Network className="w-3.5 h-3.5" />
                      Modified Relationships
                    </span>
                    <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-amber-950/60 text-amber-300 border border-amber-800/40">
                      {modifiedEdgesCount}
                    </span>
                  </div>

                  {modifiedEdgesCount === 0 ? (
                    <div className="text-gray-500 italic text-[11px]">No relationship attributes modified.</div>
                  ) : (
                    <div className="space-y-1.5 font-mono max-h-56 overflow-y-auto pr-1">
                      {(comparisonDiff.modified_edges || []).map((m, idx) => (
                        <div key={idx} className="p-2 bg-amber-950/20 border border-amber-900/40 rounded space-y-1">
                          <div className="text-amber-300 font-semibold truncate" title={m.edge_id}>
                            {m.edge_id}
                          </div>
                          {m.changes &&
                            Object.entries(m.changes).map(([fKey, fVal]) => (
                              <div key={fKey} className="text-[10px] text-gray-400 flex items-center gap-1">
                                <span>{fKey}:</span>
                                <span className="line-through text-rose-400">{String(fVal?.from)}</span>
                                <ArrowRight className="w-2.5 h-2.5 text-gray-500" />
                                <span className="text-emerald-400">{String(fVal?.to)}</span>
                              </div>
                            ))}
                        </div>
                      ))}
                      {(comparisonDiff.changed_edges || []).map((ce, idx) => (
                        <div key={`ce-${idx}`} className="p-2 bg-amber-950/20 border border-amber-900/40 rounded space-y-1">
                          <div className="text-amber-300 font-semibold truncate" title={ce.edge_id}>
                            {ce.edge_id}
                          </div>
                          {ce.field && (
                            <div className="text-[10px] text-gray-400 flex items-center gap-1">
                              <span>{ce.field}:</span>
                              <span className="line-through text-rose-400">{String(ce.base_value)}</span>
                              <ArrowRight className="w-2.5 h-2.5 text-gray-500" />
                              <span className="text-emerald-400">{String(ce.target_value)}</span>
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
};
