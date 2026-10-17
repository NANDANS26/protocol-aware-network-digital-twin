import React, { useState } from 'react';
import type {
  NetworkModel,
  ModelNode,
  ModelInterface,
  RouteEntry,
  AccessControlList,
  FirewallRule,
  IPAddressAssignment,
} from '../../types/simulation';
import type { TopologySnapshot } from '../../types/intelligence';
import {
  Cpu,
  Layers,
  Shield,
  Route,
  AlertTriangle,
  Plus,
  Hash,
} from 'lucide-react';

interface Props {
  models: NetworkModel[];
  selectedModelId: string;
  onSelectModel: (modelId: string) => void;
  snapshots: TopologySnapshot[];
  onBuildModel: (snapshotId: string, name?: string) => Promise<void>;
  loading: boolean;
}

export const ModelInspectorView: React.FC<Props> = ({
  models,
  selectedModelId,
  onSelectModel,
  snapshots,
  onBuildModel,
  loading,
}) => {
  const currentModel = models.find((m) => m.model_id === selectedModelId);
  const [selectedNodeId, setSelectedNodeId] = useState<string>('');
  const [showBuildModal, setShowBuildModal] = useState<boolean>(false);
  const [buildSnapshotId, setBuildSnapshotId] = useState<string>(snapshots[0]?.snapshot_id || '');
  const [buildName, setBuildName] = useState<string>('Operational Twin Model');

  const nodeList: ModelNode[] = currentModel ? Object.values(currentModel.nodes) : [];
  const selectedNode: ModelNode | undefined = currentModel?.nodes[selectedNodeId] || nodeList[0];

  const handleBuild = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!buildSnapshotId) return;
    await onBuildModel(buildSnapshotId, buildName.trim());
    setShowBuildModal(false);
  };

  return (
    <div className="space-y-6">
      {/* Control Strip */}
      <div className="bg-surface/60 border border-gray-800 rounded-lg p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-sm font-bold text-white flex items-center gap-2">
            <Cpu className="w-4 h-4 text-purple-400" />
            Executable Formal Model Inspector
          </h2>
          <p className="text-xs text-gray-400 mt-0.5">
            Strongly typed, canonical network models derived from versioned snapshots with deterministic SHA-256 state fingerprints.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-2">
            <label className="text-xs font-medium text-gray-300">Model:</label>
            <select
              value={selectedModelId}
              onChange={(e) => onSelectModel(e.target.value)}
              className="bg-slate-950 border border-gray-700 rounded px-2.5 py-1 text-xs text-gray-200 focus:outline-none focus:border-indigo-500 font-mono"
            >
              {models.length === 0 ? (
                <option value="">No models built</option>
              ) : (
                models.map((m) => (
                  <option key={m.model_id} value={m.model_id}>
                    {m.name} ({m.model_id.slice(0, 10)})
                  </option>
                ))
              )}
            </select>
          </div>

          <button
            onClick={() => setShowBuildModal(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-purple-600 hover:bg-purple-500 text-white text-xs font-medium shadow-sm transition"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Build Model from Snapshot</span>
          </button>
        </div>
      </div>

      {currentModel ? (
        <div className="space-y-5">
          {/* Model Fingerprint & Metadata Card */}
          <div className="bg-surface/50 border border-gray-800 rounded-lg p-4 font-mono text-xs">
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <div>
                <span className="text-gray-400 text-[10px] uppercase block">Model ID & Version</span>
                <span className="text-white font-bold">{currentModel.model_id}</span>
                <span className="text-gray-500 block text-[11px]">v{currentModel.model_version}</span>
              </div>

              <div>
                <span className="text-gray-400 text-[10px] uppercase block">Canonical Fingerprint</span>
                <span className="text-purple-300 font-bold flex items-center gap-1">
                  <Hash className="w-3 h-3 text-purple-400" />
                  {currentModel.fingerprint ? currentModel.fingerprint.slice(0, 16) : 'N/A'}...
                </span>
                <span className="text-[10px] text-gray-500">SHA-256 State Hash</span>
              </div>

              <div>
                <span className="text-gray-400 text-[10px] uppercase block">Source Snapshot</span>
                <span className="text-gray-200">{currentModel.source_snapshot_id}</span>
                <span className="text-gray-500 block text-[10px]">
                  FP: {currentModel.source_snapshot_fingerprint ? currentModel.source_snapshot_fingerprint.slice(0, 10) : 'N/A'}...
                </span>
              </div>

              <div>
                <span className="text-gray-400 text-[10px] uppercase block">Entities</span>
                <span className="text-cyan-400 font-bold">
                  {Object.keys(currentModel.nodes || {}).length} Nodes &bull; {Object.keys(currentModel.zones || {}).length} Zones
                </span>
                <span className="text-gray-500 block text-[10px]">
                  {currentModel.is_counterfactual ? 'Counterfactual Clone' : 'Verified Baseline'}
                </span>
              </div>
            </div>
          </div>

          {/* Known Limitations Ledger */}
          {currentModel.known_limitations.length > 0 && (
            <div className="bg-amber-950/20 border border-amber-900/60 rounded-lg p-4">
              <h3 className="text-xs font-bold text-amber-300 uppercase tracking-wider flex items-center gap-1.5 mb-2">
                <AlertTriangle className="w-4 h-4 text-amber-400" />
                Explicit Model Limitations & Assumptions ({currentModel.known_limitations.length})
              </h3>
              <div className="space-y-2">
                {currentModel.known_limitations.map((lim, idx) => (
                  <div key={idx} className="bg-black/30 p-2.5 rounded border border-amber-800/40 text-xs">
                    <div className="flex items-center justify-between">
                      <span className="font-mono font-bold text-amber-200">{lim.limitation_code}</span>
                      <span className="text-[10px] font-mono text-gray-400">
                        Affects: {lim.affected_entities.slice(0, 3).join(', ')}
                      </span>
                    </div>
                    <p className="text-gray-300 text-[11px] mt-0.5">{lim.description}</p>
                    <p className="text-amber-400 text-[10px] mt-0.5">Impact: {lim.impact}</p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Node and Policy Inspector Split Pane */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            {/* Left: Nodes List */}
            <div className="bg-surface/50 border border-gray-800 rounded-lg p-3">
              <div className="text-xs font-bold text-gray-300 uppercase tracking-wider mb-2">
                Model Nodes ({nodeList.length})
              </div>
              <div className="space-y-1 max-h-96 overflow-y-auto">
                {nodeList.map((node) => (
                  <button
                    key={node.node_id}
                    onClick={() => setSelectedNodeId(node.node_id)}
                    className={`w-full text-left p-2 rounded text-xs transition flex items-center justify-between font-mono ${
                      selectedNode?.node_id === node.node_id
                        ? 'bg-indigo-950/70 border border-indigo-700/60 text-white'
                        : 'hover:bg-slate-900/60 text-gray-300'
                    }`}
                  >
                    <div>
                      <div className="font-semibold">{node.label}</div>
                      <div className="text-[10px] text-gray-400">{node.node_id}</div>
                    </div>
                    <span className="px-1.5 py-0.5 rounded bg-gray-800 text-[10px] font-bold">
                      {node.node_type}
                    </span>
                  </button>
                ))}
              </div>
            </div>

            {/* Right: Selected Node Details */}
            {selectedNode && (
              <div className="lg:col-span-2 bg-surface/50 border border-gray-800 rounded-lg p-4 space-y-4">
                <div className="flex items-center justify-between border-b border-gray-800 pb-3">
                  <div>
                    <h3 className="text-sm font-bold text-white flex items-center gap-2">
                      <Layers className="w-4 h-4 text-indigo-400" />
                      {selectedNode.label}
                    </h3>
                    <p className="text-xs text-gray-400 font-mono mt-0.5">
                      Node ID: {selectedNode.node_id} &bull; Type: {selectedNode.node_type} &bull; Zone:{' '}
                      {selectedNode.zone_id || 'None'}
                    </p>
                  </div>
                  {selectedNode.default_gateway_ip && (
                    <span className="px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800/40 text-xs font-mono">
                      GW: {selectedNode.default_gateway_ip}
                    </span>
                  )}
                </div>

                {/* Interfaces, Routing & ACLs */}
                {(() => {
                  const ifaceList: ModelInterface[] = Array.isArray(selectedNode.interfaces)
                    ? selectedNode.interfaces
                    : Object.values((selectedNode.interfaces || {}) as Record<string, ModelInterface>);
                  const routeList: RouteEntry[] = Array.isArray(selectedNode.routing_table)
                    ? selectedNode.routing_table
                    : Object.values((selectedNode.routing_table || {}) as Record<string, RouteEntry>);
                  const aclList: AccessControlList[] = Array.isArray(selectedNode.acls)
                    ? selectedNode.acls
                    : Object.values((selectedNode.acls || {}) as Record<string, AccessControlList>);

                  return (
                    <>
                      <div>
                        <h4 className="text-[11px] font-bold text-gray-400 uppercase tracking-wider mb-2">
                          Network Interfaces ({ifaceList.length})
                        </h4>
                        <div className="space-y-1.5">
                          {ifaceList.map((iface: ModelInterface) => (
                            <div
                              key={iface.interface_id}
                              className="bg-slate-950 p-2.5 rounded border border-gray-800 flex items-center justify-between text-xs font-mono"
                            >
                              <div>
                                <span className="font-bold text-white">{iface.name}</span>
                                <span className="text-gray-500 text-[11px] ml-2">({iface.interface_id})</span>
                                {iface.mac_address && (
                                  <span className="text-gray-400 text-[11px] block">MAC: {iface.mac_address}</span>
                                )}
                              </div>
                              <div className="text-right">
                                {(Array.isArray(iface.ip_assignments) ? iface.ip_assignments : []).map((assign: IPAddressAssignment, aIdx: number) => (
                                  <span key={aIdx} className="px-2 py-0.5 rounded bg-indigo-950/70 text-indigo-300 block text-[11px]">
                                    {assign.ip_address}/{assign.prefix_length}
                                  </span>
                                ))}
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>

                      {/* Routing Table */}
                      <div>
                        <h4 className="text-[11px] font-bold text-gray-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                          <Route className="w-3.5 h-3.5 text-cyan-400" />
                          Routing Table ({routeList.length})
                        </h4>
                        {routeList.length === 0 ? (
                          <div className="text-gray-500 text-xs italic">No routes defined on this node.</div>
                        ) : (
                          <div className="space-y-1 max-h-48 overflow-y-auto">
                            {routeList.map((r: RouteEntry) => (
                              <div
                                key={r.route_id}
                                className="bg-slate-950 p-2 rounded border border-gray-800/80 flex items-center justify-between text-xs font-mono"
                              >
                                <div>
                                  <span className="text-white font-semibold">{r.destination_prefix}</span>
                                  <span className="text-gray-400 text-[11px] ml-2">
                                    {r.next_hop_ip ? `via ${r.next_hop_ip}` : 'Direct Link'}
                                  </span>
                                </div>
                                <div className="flex items-center gap-2">
                                  <span className="text-[10px] text-gray-400">Metric: {r.metric}</span>
                                  <span className="px-1.5 py-0.5 rounded bg-gray-800 text-[10px] text-gray-300">
                                    {r.route_type}
                                  </span>
                                </div>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>

                      {/* Access Control Lists */}
                      <div>
                        <h4 className="text-[11px] font-bold text-gray-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                          <Shield className="w-3.5 h-3.5 text-rose-400" />
                          Firewall Access Control Lists ({aclList.length})
                        </h4>
                        {aclList.length === 0 ? (
                          <div className="text-gray-500 text-xs italic">No firewall ACLs configured (Implicit Allow).</div>
                        ) : (
                          <div className="space-y-2">
                            {aclList.map((acl: AccessControlList) => (
                              <div key={acl.acl_id} className="bg-slate-950 p-2.5 rounded border border-gray-800 space-y-1.5 text-xs font-mono">
                                <div className="flex items-center justify-between">
                                  <span className="font-bold text-white">{acl.name}</span>
                                  <span className="px-2 py-0.5 rounded bg-gray-800 text-[10px] text-gray-300">
                                    Default: {acl.default_policy}
                                  </span>
                                </div>
                                <div className="space-y-1">
                                  {acl.rules.map((rule: FirewallRule) => (
                                    <div
                                      key={rule.rule_id}
                                      className="bg-black/40 p-1.5 rounded flex items-center justify-between text-[11px]"
                                    >
                                      <div className="flex items-center gap-2">
                                        <span className="text-gray-500">#{rule.rule_number}</span>
                                        <span
                                          className={`px-1.5 py-0.2 rounded font-bold ${
                                            rule.action === 'PERMIT' ? 'text-emerald-400' : 'text-rose-400'
                                          }`}
                                        >
                                          {rule.action}
                                        </span>
                                        <span className="text-gray-300">
                                          {rule.direction} {rule.protocol}
                                          {rule.destination_port ? `:${rule.destination_port}` : ''}
                                        </span>
                                      </div>
                                      {rule.destination_prefix && (
                                        <span className="text-gray-400 text-[10px]">dst: {rule.destination_prefix}</span>
                                      )}
                                    </div>
                                  ))}
                                </div>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    </>
                  );
                })()}
              </div>
            )}
          </div>
        </div>
      ) : (
        <div className="p-8 text-center bg-surface/30 border border-gray-800 rounded-lg text-gray-400 text-xs">
          No formal network model currently loaded. Click "Build Model from Snapshot" to generate an executable digital twin.
        </div>
      )}

      {/* Build Model Modal */}
      {showBuildModal && (
        <div className="fixed inset-0 z-50 bg-black/75 flex items-center justify-center p-4">
          <form
            onSubmit={handleBuild}
            className="bg-surface border border-gray-700 rounded-lg shadow-xl max-w-md w-full p-5 space-y-4"
          >
            <div>
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Cpu className="w-4 h-4 text-purple-400" />
                Build Executable Network Model
              </h3>
              <p className="text-xs text-gray-400 mt-0.5">
                Derive an executable formal state model from an existing persistent topology snapshot.
              </p>
            </div>

            <div className="space-y-3 text-xs">
              <div>
                <label className="block text-gray-300 font-medium mb-1">Model Name</label>
                <input
                  type="text"
                  value={buildName}
                  onChange={(e) => setBuildName(e.target.value)}
                  className="w-full bg-slate-950 border border-gray-700 rounded px-3 py-1.5 text-gray-200 focus:outline-none focus:border-indigo-500 font-mono"
                  required
                />
              </div>

              <div>
                <label className="block text-gray-300 font-medium mb-1">Source Topology Snapshot</label>
                <select
                  value={buildSnapshotId}
                  onChange={(e) => setBuildSnapshotId(e.target.value)}
                  className="w-full bg-slate-950 border border-gray-700 rounded px-3 py-1.5 text-gray-200 focus:outline-none focus:border-indigo-500 font-mono"
                  required
                >
                  {snapshots.map((snap) => (
                    <option key={snap.snapshot_id} value={snap.snapshot_id}>
                      {snap.name} ({snap.snapshot_id})
                    </option>
                  ))}
                </select>
              </div>
            </div>

            <div className="flex justify-end gap-2 pt-3 border-t border-gray-800">
              <button
                type="button"
                onClick={() => setShowBuildModal(false)}
                className="px-3 py-1.5 rounded bg-gray-800 hover:bg-gray-700 text-gray-300 text-xs font-medium"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={loading}
                className="px-4 py-1.5 rounded bg-purple-600 hover:bg-purple-500 text-white text-xs font-medium shadow disabled:opacity-50"
              >
                {loading ? 'Building...' : 'Build Twin Model'}
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
};
