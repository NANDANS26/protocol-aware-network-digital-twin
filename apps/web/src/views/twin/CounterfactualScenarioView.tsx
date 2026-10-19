import React, { useState, useMemo, useEffect } from 'react';
import type {
  NetworkModel,
  SimulationScenario,
  CounterfactualResult,
  SimulationActionType,
  ModelNode,
} from '../../types/simulation';
import {
  GitCompare,
  Play,
  Plus,
  ArrowRight,
  Route,
  ShieldAlert,
} from 'lucide-react';

interface Props {
  models: NetworkModel[];
  selectedModelId: string;
  onSelectModel: (modelId: string) => void;
  scenarios: SimulationScenario[];
  selectedScenarioId: string;
  onSelectScenario: (scenId: string) => void;
  onRunScenario: (scenId: string) => Promise<CounterfactualResult | null>;
  onCreateScenario: (scenario: SimulationScenario) => Promise<void>;
  counterfactualResult: CounterfactualResult | null;
  loading: boolean;
}

export const CounterfactualScenarioView: React.FC<Props> = ({
  models,
  selectedModelId,
  onSelectModel,
  scenarios,
  selectedScenarioId,
  onSelectScenario,
  onRunScenario,
  onCreateScenario,
  counterfactualResult,
  loading,
}) => {
  const [showCreateModal, setShowCreateModal] = useState<boolean>(false);

  // New scenario form
  const [scenName, setScenName] = useState<string>('Emergency External Lockdown');
  const [scenDesc, setScenDesc] = useState<string>('Block all incoming external traffic to port 443');
  const [actionType, setActionType] = useState<SimulationActionType>('ADD_FIREWALL_RULE');
  const [targetNode, setTargetNode] = useState<string>('firewall-1');
  const [actionPort, setActionPort] = useState<number>(443);
  const [actionPrefix, setActionPrefix] = useState<string>('10.0.1.0/24');

  const selectedScenario = scenarios.find((s) => s.scenario_id === selectedScenarioId);
  const selectedModel = useMemo(
    () => models.find((m) => m.model_id === selectedModelId),
    [models, selectedModelId]
  );

  const availableNodes: ModelNode[] = useMemo(() => {
    if (!selectedModel || !selectedModel.nodes) return [];
    const rawNodes = Array.isArray(selectedModel.nodes)
      ? selectedModel.nodes
      : Object.values(selectedModel.nodes);
    return [...rawNodes].sort((a, b) => {
      const typeRank = (t: string) => (t === 'FIREWALL' ? 0 : t === 'ROUTER' ? 1 : t === 'HOST' ? 2 : 3);
      const diff = typeRank(a.node_type) - typeRank(b.node_type);
      if (diff !== 0) return diff;
      return (a.label || a.node_id).localeCompare(b.label || b.node_id);
    });
  }, [selectedModel]);

  // Set intelligent default target node based on available nodes in the selected model
  useEffect(() => {
    if (availableNodes.length > 0) {
      const exists = availableNodes.some((n) => n.node_id === targetNode);
      if (!exists || targetNode === 'firewall-1') {
        const preferred =
          availableNodes.find((n) => n.node_type === 'FIREWALL') ||
          availableNodes.find((n) => n.node_type === 'ROUTER') ||
          availableNodes[0];
        if (preferred) {
          setTargetNode(preferred.node_id);
        }
      }
    }
  }, [availableNodes, targetNode]);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedModelId) return;

    let params: Record<string, any> = {};
    if (actionType === 'ADD_FIREWALL_RULE') {
      params = {
        rule_id: `rule-deny-${actionPort}`,
        action: 'DENY',
        direction: 'INGRESS',
        protocol: 'TCP',
        destination_port: actionPort,
        position: 0,
      };
    } else if (actionType === 'ADD_ROUTE') {
      params = {
        destination_prefix: actionPrefix,
        next_hop_ip: '10.0.1.1',
        metric: 1,
      };
    } else if (actionType === 'REMOVE_ROUTE') {
      params = {
        destination_prefix: actionPrefix,
      };
    }

    const newScen: SimulationScenario = {
      scenario_id: `scen-${Date.now()}`,
      name: scenName.trim(),
      description: scenDesc.trim(),
      base_model_id: selectedModelId,
      actions: [
        {
          action_type: actionType,
          target_node_id: targetNode.trim(),
          parameters: params,
          comment: `Added via Twin Workstation: ${actionType}`,
        },
      ],
    };

    await onCreateScenario(newScen);
    setShowCreateModal(false);
  };

  return (
    <div className="space-y-6">
      {/* Scenario Control Strip */}
      <div className="bg-surface/60 border border-gray-800 rounded-lg p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-sm font-bold text-white flex items-center gap-2">
            <GitCompare className="w-4 h-4 text-cyan-400" />
            Counterfactual Simulation & What-If Matrix Studio
          </h2>
          <p className="text-xs text-gray-400 mt-0.5">
            Test hypothetical routing and ACL modifications in isolated clones without mutating verified baseline models.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-2">
            <label className="text-xs font-medium text-gray-300">Base Model:</label>
            <select
              value={selectedModelId}
              onChange={(e) => onSelectModel(e.target.value)}
              className="bg-slate-950 border border-gray-700 rounded px-2.5 py-1 text-xs text-gray-200 focus:outline-none focus:border-indigo-500 font-mono"
            >
              {models.map((m) => (
                <option key={m.model_id} value={m.model_id}>
                  {m.name} ({m.model_id.slice(0, 10)})
                </option>
              ))}
            </select>
          </div>

          <div className="flex items-center gap-2">
            <label className="text-xs font-medium text-gray-300">Scenario:</label>
            <select
              value={selectedScenarioId}
              onChange={(e) => onSelectScenario(e.target.value)}
              className="bg-slate-950 border border-gray-700 rounded px-2.5 py-1 text-xs text-gray-200 focus:outline-none focus:border-indigo-500 font-mono"
            >
              {scenarios.length === 0 ? (
                <option value="">No scenarios</option>
              ) : (
                scenarios.map((s) => (
                  <option key={s.scenario_id} value={s.scenario_id}>
                    {s.name}
                  </option>
                ))
              )}
            </select>
          </div>

          <button
            onClick={() => setShowCreateModal(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-gray-800 hover:bg-gray-700 text-gray-200 text-xs font-medium border border-gray-700 transition"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>New Scenario</span>
          </button>

          <button
            onClick={() => selectedScenarioId && onRunScenario(selectedScenarioId)}
            disabled={loading || !selectedScenarioId}
            className="flex items-center gap-1.5 px-4 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow-sm transition disabled:opacity-50"
          >
            <Play className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Run Simulation</span>
          </button>
        </div>
      </div>

      {/* Selected Scenario Details */}
      {selectedScenario && (
        <div className="bg-surface/40 border border-gray-800/80 rounded-lg p-4 font-mono text-xs space-y-2">
          <div className="flex items-center justify-between text-gray-400">
            <span className="font-bold text-white text-sm">{selectedScenario.name}</span>
            <span className="text-[11px]">ID: {selectedScenario.scenario_id}</span>
          </div>
          {selectedScenario.description && <p className="text-gray-400 text-xs">{selectedScenario.description}</p>}
          <div className="pt-2">
            <span className="text-gray-400 block text-[10px] uppercase font-bold mb-1">
              Hypothetical Actions ({selectedScenario.actions.length})
            </span>
            <div className="space-y-1.5">
              {selectedScenario.actions.map((act, idx) => {
                const targetMatch = availableNodes.find(
                  (n) => n.node_id === act.target_node_id || n.label === act.target_node_id
                );
                return (
                  <div key={idx} className="bg-slate-950 p-2 rounded border border-gray-800 flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="px-1.5 py-0.5 rounded bg-indigo-950 text-indigo-300 font-bold text-[10px]">
                        {act.action_type}
                      </span>
                      <span className="text-gray-300">
                        Target Node: <span className="font-semibold text-white">{act.target_node_id}</span>
                        {targetMatch && (
                          <span className="ml-1 text-[11px] text-cyan-400">
                            ({targetMatch.label || targetMatch.node_type})
                          </span>
                        )}
                      </span>
                    </div>
                    <span className="text-gray-500 text-[11px]">{JSON.stringify(act.parameters)}</span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}

      {/* Comparative Simulation Results Matrix */}
      {counterfactualResult && (() => {
        const pathDiffs = counterfactualResult.path_differences || counterfactualResult.reachability_diffs || [];
        const invariantDiffs = counterfactualResult.invariant_differences || counterfactualResult.invariant_diffs || [];
        const newlyReachableCount = counterfactualResult.newly_reachable_paths_count ?? counterfactualResult.newly_reachable_count ?? 0;
        const newlyBlockedCount = counterfactualResult.newly_blocked_paths_count ?? counterfactualResult.newly_blocked_count ?? 0;
        const regressionsCount = counterfactualResult.security_regressions_count ?? counterfactualResult.invariant_regressions_count ?? 0;
        const actionsCount = counterfactualResult.applied_actions_count ?? 0;

        return (
          <div className="space-y-4">
            {/* Summary Strip */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              <div className="bg-surface/50 border border-gray-800 p-3 rounded-lg">
                <span className="text-[10px] font-medium text-gray-400 uppercase tracking-wider block">
                  Newly Reachable Paths
                </span>
                <span className="text-xl font-bold font-mono text-emerald-400 mt-1 block">
                  +{newlyReachableCount}
                </span>
              </div>

              <div className="bg-surface/50 border border-gray-800 p-3 rounded-lg">
                <span className="text-[10px] font-medium text-gray-400 uppercase tracking-wider block">
                  Newly Blocked Paths
                </span>
                <span className="text-xl font-bold font-mono text-rose-400 mt-1 block">
                  +{newlyBlockedCount}
                </span>
              </div>

              <div className="bg-surface/50 border border-gray-800 p-3 rounded-lg">
                <span className="text-[10px] font-medium text-gray-400 uppercase tracking-wider block">
                  Security Regressions
                </span>
                <span
                  className={`text-xl font-bold font-mono mt-1 block ${
                    regressionsCount > 0 ? 'text-rose-400' : 'text-gray-400'
                  }`}
                >
                  {regressionsCount}
                </span>
              </div>

              <div className="bg-surface/50 border border-gray-800 p-3 rounded-lg">
                <span className="text-[10px] font-medium text-gray-400 uppercase tracking-wider block">
                  Applied Actions
                </span>
                <span className="text-xl font-bold font-mono text-cyan-400 mt-1 block">
                  {actionsCount}
                </span>
              </div>
            </div>

            {/* Fingerprint delta */}
            <div className="bg-surface/30 border border-gray-800 p-3 rounded-lg font-mono text-xs flex flex-wrap items-center justify-between gap-2">
              <div>
                <span className="text-gray-400 text-[10px] uppercase block">Baseline Fingerprint</span>
                <span className="text-gray-200">{(counterfactualResult.baseline_fingerprint || '').slice(0, 16)}...</span>
              </div>
              <ArrowRight className="w-4 h-4 text-cyan-400" />
              <div>
                <span className="text-gray-400 text-[10px] uppercase block">Counterfactual Fingerprint</span>
                <span className="text-cyan-300">{(counterfactualResult.counterfactual_fingerprint || '').slice(0, 16)}...</span>
              </div>
            </div>

            {/* Path Differences Table */}
            {pathDiffs.length > 0 && (
              <div className="bg-surface/50 border border-gray-800 rounded-lg overflow-hidden">
                <div className="p-3 border-b border-gray-800 flex items-center justify-between">
                  <h3 className="text-xs font-bold text-gray-300 uppercase tracking-wider flex items-center gap-1.5">
                    <Route className="w-3.5 h-3.5 text-indigo-400" />
                    Path Reachability Status Shifts ({pathDiffs.length})
                  </h3>
                </div>
                <div className="divide-y divide-gray-800 text-xs font-mono">
                  {pathDiffs.map((diff, idx) => (
                    <div key={idx} className="p-3 flex items-center justify-between hover:bg-slate-900/30">
                      <div className="flex items-center gap-2">
                        <span className="text-white font-semibold">
                          {diff.source_ip} &rarr; {diff.destination_ip}:{diff.destination_port || diff.protocol}
                        </span>
                        <span className="text-gray-400 text-[11px] font-normal">({diff.explanation})</span>
                      </div>

                      <div className="flex items-center gap-2">
                        <span className="px-2 py-0.5 rounded bg-gray-800 text-gray-400 text-[10px]">
                          {diff.baseline_status}
                        </span>
                        <ArrowRight className="w-3 h-3 text-gray-500" />
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            diff.change_type === 'NEWLY_REACHABLE'
                              ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                              : 'bg-rose-950 text-rose-300 border border-rose-800'
                          }`}
                        >
                          {diff.counterfactual_status}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Invariant Differences Table */}
            {invariantDiffs.length > 0 && (
              <div className="bg-surface/50 border border-gray-800 rounded-lg overflow-hidden">
                <div className="p-3 border-b border-gray-800 flex items-center justify-between">
                  <h3 className="text-xs font-bold text-gray-300 uppercase tracking-wider flex items-center gap-1.5">
                    <ShieldAlert className="w-3.5 h-3.5 text-amber-400" />
                    Security Invariant State Transitions ({invariantDiffs.length})
                  </h3>
                </div>
                <div className="divide-y divide-gray-800 text-xs font-mono">
                  {invariantDiffs.map((diff, idx) => (
                    <div key={idx} className="p-3 flex items-center justify-between hover:bg-slate-900/30">
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="text-white font-semibold">{diff.invariant_name}</span>
                          {diff.severity && (
                            <span className="px-1.5 py-0.2 rounded text-[9px] font-bold bg-amber-950/80 text-amber-300 border border-amber-800/60">
                              {diff.severity}
                            </span>
                          )}
                        </div>
                        <p className="text-gray-400 text-[11px] mt-0.5">{diff.explanation}</p>
                      </div>

                      <div className="flex items-center gap-2 font-bold text-[10px]">
                        <span className="px-2 py-0.5 rounded bg-gray-800 text-gray-400">{diff.baseline_status}</span>
                        <ArrowRight className="w-3 h-3 text-gray-500" />
                        <span
                          className={`px-2 py-0.5 rounded ${
                            diff.counterfactual_status === 'PASS'
                              ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                              : 'bg-rose-950 text-rose-300 border border-rose-800'
                          }`}
                        >
                          {diff.counterfactual_status}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        );
      })()}

      {/* Create Scenario Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 bg-black/75 flex items-center justify-center p-4">
          <form
            onSubmit={handleCreate}
            className="bg-surface border border-gray-700 rounded-lg shadow-xl max-w-lg w-full p-5 space-y-4"
          >
            <div>
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Plus className="w-4 h-4 text-cyan-400" />
                Construct Counterfactual Scenario
              </h3>
              <p className="text-xs text-gray-400 mt-0.5">
                Define hypothetical mutations against the baseline network state.
              </p>
            </div>

            <div className="space-y-3 text-xs">
              <div>
                <label className="block text-gray-300 font-medium mb-1">Scenario Name</label>
                <input
                  type="text"
                  value={scenName}
                  onChange={(e) => setScenName(e.target.value)}
                  className="w-full bg-slate-950 border border-gray-700 rounded px-3 py-1.5 text-gray-200 focus:outline-none focus:border-indigo-500 font-mono"
                  required
                />
              </div>

              <div>
                <label className="block text-gray-300 font-medium mb-1">Description</label>
                <input
                  type="text"
                  value={scenDesc}
                  onChange={(e) => setScenDesc(e.target.value)}
                  className="w-full bg-slate-950 border border-gray-700 rounded px-3 py-1.5 text-gray-200 focus:outline-none focus:border-indigo-500"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-gray-300 font-medium mb-1">Action Type</label>
                  <select
                    value={actionType}
                    onChange={(e) => setActionType(e.target.value as SimulationActionType)}
                    className="w-full bg-slate-950 border border-gray-700 rounded px-3 py-1.5 text-gray-200 focus:outline-none focus:border-indigo-500 font-mono"
                  >
                    <option value="ADD_FIREWALL_RULE">ADD_FIREWALL_RULE</option>
                    <option value="ADD_ROUTE">ADD_ROUTE</option>
                    <option value="REMOVE_ROUTE">REMOVE_ROUTE</option>
                  </select>
                </div>

                <div>
                  <label className="block text-gray-300 font-medium mb-1">Target Node</label>
                  {availableNodes.length > 0 ? (
                    <select
                      value={targetNode}
                      onChange={(e) => setTargetNode(e.target.value)}
                      className="w-full bg-slate-950 border border-gray-700 rounded px-3 py-1.5 text-gray-200 focus:outline-none focus:border-indigo-500 font-mono text-xs"
                      required
                    >
                      {availableNodes.map((n) => (
                        <option key={n.node_id} value={n.node_id}>
                          {n.label ? `${n.label} (${n.node_type})` : `${n.node_id} (${n.node_type})`}
                        </option>
                      ))}
                    </select>
                  ) : (
                    <input
                      type="text"
                      value={targetNode}
                      onChange={(e) => setTargetNode(e.target.value)}
                      placeholder="e.g. router-1 or node-asset-..."
                      className="w-full bg-slate-950 border border-gray-700 rounded px-3 py-1.5 text-gray-200 focus:outline-none focus:border-indigo-500 font-mono"
                      required
                    />
                  )}
                </div>
              </div>

              {actionType === 'ADD_FIREWALL_RULE' && (
                <div>
                  <label className="block text-gray-300 font-medium mb-1">Drop Port</label>
                  <input
                    type="number"
                    value={actionPort}
                    onChange={(e) => setActionPort(parseInt(e.target.value) || 443)}
                    className="w-full bg-slate-950 border border-gray-700 rounded px-3 py-1.5 text-gray-200 focus:outline-none focus:border-indigo-500 font-mono"
                  />
                </div>
              )}

              {actionType.includes('ROUTE') && (
                <div>
                  <label className="block text-gray-300 font-medium mb-1">Destination Prefix</label>
                  <input
                    type="text"
                    value={actionPrefix}
                    onChange={(e) => setActionPrefix(e.target.value)}
                    placeholder="e.g. 10.0.1.0/24"
                    className="w-full bg-slate-950 border border-gray-700 rounded px-3 py-1.5 text-gray-200 focus:outline-none focus:border-indigo-500 font-mono"
                  />
                </div>
              )}
            </div>

            <div className="flex justify-end gap-2 pt-3 border-t border-gray-800">
              <button
                type="button"
                onClick={() => setShowCreateModal(false)}
                className="px-3 py-1.5 rounded bg-gray-800 hover:bg-gray-700 text-gray-300 text-xs font-medium"
              >
                Cancel
              </button>
              <button
                type="submit"
                className="px-4 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-medium shadow"
              >
                Create Scenario
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
};
