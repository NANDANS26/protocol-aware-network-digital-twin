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
  ShieldCheck,
  AlertTriangle,
  Info,
  CheckCircle2,
  XCircle,
  HelpCircle,
  Layers,
  ChevronDown,
  ChevronUp,
  Cpu,
  RefreshCw,
  Eye,
  History,
} from 'lucide-react';
import type { PathDifference } from '../../types/simulation';

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
  runError?: string | null;
  lastLiveRunId?: string | null;
  onClearError?: () => void;
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
  runError,
  lastLiveRunId,
  onClearError,
}) => {
  const [showCreateModal, setShowCreateModal] = useState<boolean>(false);
  const [includeDerivedModels, setIncludeDerivedModels] = useState<boolean>(false);
  const [showModelDetails, setShowModelDetails] = useState<boolean>(false);
  const [showEvidenceAccordion, setShowEvidenceAccordion] = useState<boolean>(true);
  const [pathFilter, setPathFilter] = useState<string>('');
  const [expandedPathIdx, setExpandedPathIdx] = useState<number | null>(null);

  // Form states for New Scenario Modal
  const [scenName, setScenName] = useState<string>('Emergency External Lockdown');
  const [scenDesc, setScenDesc] = useState<string>('Block all incoming external traffic to port 443');
  const [actionType, setActionType] = useState<SimulationActionType>('ADD_FIREWALL_RULE');
  const [targetNode, setTargetNode] = useState<string>('router-1');
  const [actionPort, setActionPort] = useState<number>(443);
  const [actionProtocol, setActionProtocol] = useState<'TCP' | 'UDP' | 'ANY'>('TCP');
  const [actionDirection, setActionDirection] = useState<'INGRESS' | 'EGRESS'>('INGRESS');
  const [actionPolicy, setActionPolicy] = useState<'DENY' | 'ALLOW'>('DENY');
  const [actionPrefix, setActionPrefix] = useState<string>('10.0.1.0/24');
  const [actionNextHop, setActionNextHop] = useState<string>('10.0.1.1');

  // Filter models into genuine baselines and derived counterfactuals
  const baselineModels = useMemo(
    () => models.filter((m) => !m.is_counterfactual),
    [models]
  );
  const derivedModels = useMemo(
    () => models.filter((m) => m.is_counterfactual),
    [models]
  );

  const displayModels = useMemo(() => {
    return includeDerivedModels ? models : baselineModels;
  }, [includeDerivedModels, models, baselineModels]);

  const selectedModel = useMemo(
    () => models.find((m) => m.model_id === selectedModelId),
    [models, selectedModelId]
  );

  const selectedScenario = useMemo(
    () => scenarios.find((s) => s.scenario_id === selectedScenarioId),
    [scenarios, selectedScenarioId]
  );

  // Scenarios matching the selected baseline model
  const matchingScenarios = useMemo(
    () => scenarios.filter((s) => s.base_model_id === selectedModelId),
    [scenarios, selectedModelId]
  );

  // Available nodes in currently selected model
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

  // Set smart default target node based on available nodes
  useEffect(() => {
    if (availableNodes.length > 0) {
      const exists = availableNodes.some((n) => n.node_id === targetNode);
      if (!exists) {
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

  // Check if counterfactualResult matches selectedModelId and selectedScenarioId
  const isResultMatching = useMemo(() => {
    if (!counterfactualResult) return false;
    const modelMatches = counterfactualResult.base_model_id === selectedModelId;
    const scenarioMatches = counterfactualResult.scenario_id === selectedScenarioId;
    return modelMatches && scenarioMatches;
  }, [counterfactualResult, selectedModelId, selectedScenarioId]);

  // Handle Scenario Creation
  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedModelId) return;

    let params: Record<string, any> = {};
    if (actionType === 'ADD_FIREWALL_RULE') {
      params = {
        rule_id: `rule-${actionPolicy.toLowerCase()}-${actionPort}`,
        action: actionPolicy,
        direction: actionDirection,
        protocol: actionProtocol,
        destination_port: actionPort,
        position: 0,
      };
    } else if (actionType === 'ADD_ROUTE') {
      params = {
        destination_prefix: actionPrefix.trim(),
        next_hop_ip: actionNextHop.trim(),
        metric: 1,
      };
    } else if (actionType === 'REMOVE_ROUTE') {
      params = {
        destination_prefix: actionPrefix.trim(),
      };
    } else if (actionType === 'MODIFY_ROUTE') {
      params = {
        destination_prefix: actionPrefix.trim(),
        next_hop_ip: actionNextHop.trim(),
        metric: 1,
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
          comment: `Added via Scenario Laboratory: ${actionType} on ${targetNode.trim()}`,
        },
      ],
    };

    await onCreateScenario(newScen);
    setShowCreateModal(false);
  };

  // Helper to format node representation
  const getNodeRepresentation = (targetId: string) => {
    const match = availableNodes.find((n) => n.node_id === targetId || n.label === targetId);
    if (match) {
      return {
        label: match.label || match.node_id,
        nodeType: match.node_type,
        nodeId: match.node_id,
        isAlias: match.label && match.label !== match.node_id,
      };
    }
    // Check if target is an alias for router/firewall
    if (targetId.toLowerCase().includes('firewall')) {
      const routerMatch = availableNodes.find((n) => n.node_type === 'ROUTER');
      if (routerMatch) {
        return {
          label: routerMatch.label || routerMatch.node_id,
          nodeType: routerMatch.node_type,
          nodeId: routerMatch.node_id,
          isAlias: true,
          resolvedFrom: targetId,
        };
      }
    }
    return {
      label: targetId,
      nodeType: 'UNKNOWN',
      nodeId: targetId,
      isAlias: false,
    };
  };

  return (
    <div className="space-y-6 min-w-0" data-testid="counterfactual-scenario-view">
      {/* ========================================================================= */}
      {/* SECTION A: Scenario Setup & Model Grounding                              */}
      {/* ========================================================================= */}
      <section className="bg-surface border border-surface-border rounded-lg p-5 shadow-sm space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-surface-border pb-3">
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <span className="px-2 py-0.5 rounded bg-indigo-900/50 text-indigo-300 font-mono text-[11px] font-semibold border border-indigo-700/40">
                Section A
              </span>
              <h3 className="text-sm font-bold text-gray-100 flex items-center gap-2 truncate">
                <GitCompare className="w-4 h-4 text-cyan-400 shrink-0" />
                Counterfactual Simulation & What-If Matrix Studio
              </h3>
            </div>
            <p className="text-xs text-gray-400 mt-1 leading-relaxed">
              Select an authoritative baseline network model and an isolated what-if scenario. Simulations execute against clones without modifying baseline topology state.
            </p>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            {isResultMatching ? (
              <span className="px-2.5 py-1 rounded bg-emerald-950/60 border border-emerald-800 text-emerald-300 text-xs font-mono font-medium flex items-center gap-1.5">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                <span>Simulated (Synchronized)</span>
              </span>
            ) : counterfactualResult ? (
              <span className="px-2.5 py-1 rounded bg-amber-950/60 border border-amber-800 text-amber-300 text-xs font-mono font-medium flex items-center gap-1.5">
                <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                <span>Result Mismatches Current Baseline</span>
              </span>
            ) : (
              <span className="px-2.5 py-1 rounded bg-surface-raised border border-surface-border text-gray-300 text-xs font-mono font-medium flex items-center gap-1.5">
                <HelpCircle className="w-3.5 h-3.5 text-indigo-400" />
                <span>Ready to Simulate</span>
              </span>
            )}
          </div>
        </div>

        {/* Selection Controls Grid */}
        <div className="grid grid-cols-1 md:grid-cols-12 gap-4 items-end">
          {/* Baseline Model Selector */}
          <div className="md:col-span-5 min-w-0 space-y-1.5">
            <div className="flex items-center justify-between text-xs">
              <label htmlFor="base-model-select" className="font-medium text-gray-300 flex items-center gap-1.5">
                <Cpu className="w-3.5 h-3.5 text-indigo-400 shrink-0" />
                <span>Authoritative Baseline Model</span>
              </label>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => setShowModelDetails(!showModelDetails)}
                  className="text-[11px] text-cyan-400 hover:text-cyan-300 font-mono flex items-center gap-0.5"
                >
                  <Info className="w-3 h-3" />
                  <span>{showModelDetails ? 'Hide Info' : 'Model Info'}</span>
                </button>
              </div>
            </div>

            <select
              id="base-model-select"
              value={selectedModelId}
              onChange={(e) => onSelectModel(e.target.value)}
              className="w-full bg-slate-950 border border-surface-border rounded px-3 py-2 text-xs text-gray-200 focus:outline-none focus:border-cyan-500 font-mono transition"
            >
              {displayModels.length === 0 ? (
                <option value="">No baseline models available</option>
              ) : (
                displayModels.map((m) => (
                  <option key={m.model_id} value={m.model_id}>
                    {m.name} ({m.model_id.slice(0, 16)})
                    {m.is_counterfactual ? ' [Derived]' : ' [Baseline]'}
                  </option>
                ))
              )}
            </select>

            <div className="flex items-center justify-between text-[11px] text-gray-400 pt-0.5">
              <span>{baselineModels.length} genuine baseline(s) available</span>
              {derivedModels.length > 0 && (
                <label className="flex items-center gap-1.5 cursor-pointer text-gray-400 hover:text-gray-300">
                  <input
                    type="checkbox"
                    checked={includeDerivedModels}
                    onChange={(e) => setIncludeDerivedModels(e.target.checked)}
                    className="rounded bg-slate-950 border-surface-border text-cyan-600 focus:ring-0 w-3 h-3"
                  />
                  <span>Show {derivedModels.length} derived model(s)</span>
                </label>
              )}
            </div>
          </div>

          {/* Scenario Selector */}
          <div className="md:col-span-4 min-w-0 space-y-1.5">
            <div className="flex items-center justify-between text-xs">
              <label htmlFor="scenario-select" className="font-medium text-gray-300 flex items-center gap-1.5">
                <Layers className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                <span>Simulation Scenario</span>
              </label>
              <span className="text-[11px] font-mono text-gray-400">
                {matchingScenarios.length} for current model
              </span>
            </div>

            <select
              id="scenario-select"
              value={selectedScenarioId}
              onChange={(e) => onSelectScenario(e.target.value)}
              className="w-full bg-slate-950 border border-surface-border rounded px-3 py-2 text-xs text-gray-200 focus:outline-none focus:border-cyan-500 font-mono transition"
            >
              {scenarios.length === 0 ? (
                <option value="">No scenarios available</option>
              ) : (
                scenarios.map((s) => (
                  <option key={s.scenario_id} value={s.scenario_id}>
                    {s.name}
                  </option>
                ))
              )}
            </select>

            <div className="text-[11px] text-gray-400 truncate">
              {selectedScenario?.description || 'Select or create a scenario'}
            </div>
          </div>

          {/* Action Buttons */}
          <div className="md:col-span-3 flex items-center gap-2">
            <button
              type="button"
              onClick={() => setShowCreateModal(true)}
              className="flex-1 flex items-center justify-center gap-1.5 px-3 py-2 rounded bg-surface-raised hover:bg-surface border border-surface-border text-gray-200 text-xs font-medium transition"
              title="Author new counterfactual scenario"
            >
              <Plus className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
              <span>New Scenario</span>
            </button>

            <button
              type="button"
              onClick={() => selectedScenarioId && onRunScenario(selectedScenarioId)}
              disabled={loading || !selectedScenarioId}
              className="flex-1 flex items-center justify-center gap-1.5 px-3.5 py-2 rounded bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow-sm transition disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <Play className={`w-3.5 h-3.5 shrink-0 ${loading ? 'animate-spin' : ''}`} />
              <span>{loading ? 'Running...' : 'Run Simulation'}</span>
            </button>
          </div>
        </div>

        {/* Selected Model Details Inspector Popover */}
        {showModelDetails && selectedModel && (
          <div className="p-3.5 rounded bg-slate-950 border border-surface-border text-xs font-mono space-y-2 mt-2">
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-gray-800 pb-2">
              <span className="font-bold text-gray-200">{selectedModel.name}</span>
              <span className="text-gray-400 text-[11px]">Schema v{selectedModel.schema_version}</span>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-2 text-[11px] text-gray-300">
              <div>
                <span className="text-gray-500 block">Model ID:</span>
                <span className="truncate block" title={selectedModel.model_id}>{selectedModel.model_id}</span>
              </div>
              <div>
                <span className="text-gray-500 block">Fingerprint:</span>
                <span className="truncate block" title={selectedModel.fingerprint}>{selectedModel.fingerprint.slice(0, 16)}...</span>
              </div>
              <div>
                <span className="text-gray-500 block">Source Snapshot:</span>
                <span className="truncate block" title={selectedModel.source_snapshot_id}>{selectedModel.source_snapshot_id}</span>
              </div>
              <div>
                <span className="text-gray-500 block">Nodes & Interfaces:</span>
                <span>{availableNodes.length} nodes, {selectedModel.nodes ? Object.values(selectedModel.nodes).reduce((acc, n) => acc + (n.interfaces?.length || 0), 0) : 0} ifaces</span>
              </div>
            </div>
          </div>
        )}
      </section>

      {/* ========================================================================= */}
      {/* SECTION B: Proposed Changes & Action Specification                       */}
      {/* ========================================================================= */}
      {selectedScenario && (
        <section className="bg-surface border border-surface-border rounded-lg p-5 shadow-sm space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-surface-border pb-3">
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <span className="px-2 py-0.5 rounded bg-blue-900/50 text-blue-300 font-mono text-[11px] font-semibold border border-blue-700/40">
                  Section B
                </span>
                <h3 className="text-sm font-bold text-gray-100 flex items-center gap-2 truncate">
                  <Layers className="w-4 h-4 text-indigo-400 shrink-0" />
                  Proposed Hypothetical Changes: {selectedScenario.name}
                </h3>
              </div>
              {selectedScenario.description && (
                <p className="text-xs text-gray-400 mt-1 leading-relaxed">
                  {selectedScenario.description}
                </p>
              )}
            </div>

            <div className="flex items-center gap-2 text-[11px] font-mono text-gray-400 shrink-0">
              <span>Scenario ID:</span>
              <span className="px-1.5 py-0.5 rounded bg-slate-950 border border-surface-border text-gray-200">
                {selectedScenario.scenario_id}
              </span>
            </div>
          </div>

          {/* Model Mismatch Notice if scenario belongs to a different baseline */}
          {selectedScenario.base_model_id !== selectedModelId && (
            <div className="p-3 rounded-lg bg-amber-950/40 border border-amber-800/60 flex items-start gap-2.5 text-xs text-amber-300">
              <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
              <div className="leading-relaxed">
                <span className="font-semibold">Authoring Baseline Mismatch:</span> This scenario was configured with base model{' '}
                <code className="px-1 py-0.5 rounded bg-amber-900/40 text-amber-200 font-mono text-[11px]">
                  {selectedScenario.base_model_id}
                </code>
                , but your current selection is{' '}
                <code className="px-1 py-0.5 rounded bg-amber-900/40 text-amber-200 font-mono text-[11px]">
                  {selectedModelId}
                </code>
                . Running the simulation now will apply these actions against the currently selected model.
              </div>
            </div>
          )}

          {/* Structured Action Cards */}
          <div className="space-y-3">
            <div className="text-xs font-semibold text-gray-300 flex items-center justify-between">
              <span>Configured Mutations ({selectedScenario.actions.length})</span>
              <span className="text-[11px] text-gray-500 font-mono">Isolated Transaction Layer</span>
            </div>

            <div className="grid grid-cols-1 gap-3">
              {selectedScenario.actions.map((act, idx) => {
                const rep = getNodeRepresentation(act.target_node_id);
                return (
                  <div
                    key={idx}
                    className="p-3.5 rounded-lg bg-slate-950 border border-surface-border hover:border-gray-700 transition space-y-2.5"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <span className="px-2 py-0.5 rounded text-[11px] font-bold font-mono bg-indigo-950 text-indigo-300 border border-indigo-800">
                          #{idx + 1} {act.action_type}
                        </span>
                        <div className="text-xs text-gray-200 font-medium flex items-center gap-1.5">
                          <span className="text-gray-400">Target:</span>
                          <span className="font-bold text-white font-mono">{act.target_node_id}</span>
                          {rep.label && rep.label !== act.target_node_id && (
                            <span className="text-cyan-400 font-mono text-[11px]">({rep.label})</span>
                          )}
                        </div>
                      </div>

                      {rep.isAlias && (
                        <span className="px-2 py-0.5 rounded bg-cyan-950/60 text-cyan-300 border border-cyan-800 text-[10px] font-mono">
                          Resolved to: {rep.label} ({rep.nodeType})
                        </span>
                      )}
                    </div>

                    {/* Parameter Badges */}
                    <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
                      {act.parameters.action && (
                        <span
                          className={`px-2 py-0.5 rounded border text-[11px] font-bold ${
                            act.parameters.action === 'DENY'
                              ? 'bg-rose-950/80 text-rose-300 border-rose-800'
                              : 'bg-emerald-950/80 text-emerald-300 border-emerald-800'
                          }`}
                        >
                          Policy: {act.parameters.action}
                        </span>
                      )}
                      {act.parameters.direction && (
                        <span className="px-2 py-0.5 rounded bg-gray-900 border border-gray-800 text-gray-300 text-[11px]">
                          Direction: {act.parameters.direction}
                        </span>
                      )}
                      {act.parameters.protocol && (
                        <span className="px-2 py-0.5 rounded bg-cyan-950/60 border border-cyan-800 text-cyan-300 text-[11px]">
                          Protocol: {act.parameters.protocol}
                        </span>
                      )}
                      {act.parameters.destination_port && (
                        <span className="px-2 py-0.5 rounded bg-purple-950/60 border border-purple-800 text-purple-300 text-[11px]">
                          Port: {act.parameters.destination_port}
                        </span>
                      )}
                      {act.parameters.destination_prefix && (
                        <span className="px-2 py-0.5 rounded bg-blue-950/60 border border-blue-800 text-blue-300 text-[11px]">
                          Prefix: {act.parameters.destination_prefix}
                        </span>
                      )}
                      {act.parameters.next_hop_ip && (
                        <span className="px-2 py-0.5 rounded bg-gray-900 border border-gray-800 text-gray-300 text-[11px]">
                          Next Hop: {act.parameters.next_hop_ip}
                        </span>
                      )}
                    </div>

                    {act.comment && (
                      <p className="text-[11px] text-gray-400 italic">
                        {act.comment}
                      </p>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        </section>
      )}

      {/* ========================================================================= */}
      {/* SECTION C: Deterministic Execution Results & Reachability Shifts         */}
      {/* ========================================================================= */}
      {(() => {
        // Discrete Loading State
        if (loading) {
          return (
            <section
              className="bg-surface border border-surface-border rounded-lg p-5 shadow-sm space-y-4"
              data-testid="section-c-loading"
            >
              <div className="flex items-center justify-between border-b border-surface-border pb-3">
                <div className="flex items-center gap-2">
                  <span className="px-2 py-0.5 rounded bg-purple-900/50 text-purple-300 font-mono text-[11px] font-semibold border border-purple-700/40">
                    Section C
                  </span>
                  <h3 className="text-sm font-bold text-gray-100 flex items-center gap-2">
                    <Route className="w-4 h-4 text-purple-400" />
                    <span>Deterministic Execution Results & Reachability Shifts</span>
                  </h3>
                </div>
                <span className="text-xs font-mono text-cyan-400 flex items-center gap-1.5">
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  <span>Simulating...</span>
                </span>
              </div>

              <div className="py-10 px-4 flex flex-col items-center justify-center text-center space-y-3">
                <div className="w-12 h-12 rounded-full border-2 border-purple-500/30 border-t-purple-400 animate-spin flex items-center justify-center">
                  <Route className="w-5 h-5 text-purple-400 animate-pulse" />
                </div>
                <div className="space-y-1">
                  <h4 className="text-sm font-semibold text-gray-100">
                    Simulating Hop-by-Hop Packet Forwarding...
                  </h4>
                  <p className="text-xs text-gray-400 max-w-lg leading-relaxed">
                    Evaluating longest-prefix match (LPM) routing tables, evaluating ingress/egress ACL policy rules, and verifying formal security invariants against counterfactual model clone.
                  </p>
                </div>
                <div className="w-full max-w-xs h-1.5 bg-slate-900 rounded-full overflow-hidden border border-surface-border">
                  <div className="h-full bg-gradient-to-r from-purple-500 via-cyan-400 to-emerald-400 animate-pulse rounded-full w-3/4 mx-auto" />
                </div>
              </div>
            </section>
          );
        }

        // Discrete Execution Error State
        if (runError) {
          return (
            <section
              className="bg-surface border border-surface-border rounded-lg p-5 shadow-sm space-y-4"
              data-testid="section-c-error"
            >
              <div className="flex items-center justify-between border-b border-surface-border pb-3">
                <div className="flex items-center gap-2">
                  <span className="px-2 py-0.5 rounded bg-rose-900/50 text-rose-300 font-mono text-[11px] font-semibold border border-rose-700/40">
                    Section C
                  </span>
                  <h3 className="text-sm font-bold text-gray-100 flex items-center gap-2">
                    <Route className="w-4 h-4 text-rose-400" />
                    <span>Deterministic Execution Results & Reachability Shifts</span>
                  </h3>
                </div>
              </div>

              <div className="p-4 rounded-lg bg-rose-950/40 border border-rose-800/80 space-y-3">
                <div className="flex items-start gap-3">
                  <XCircle className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
                  <div className="space-y-1 min-w-0">
                    <h4 className="text-xs font-bold text-rose-200 uppercase tracking-wider">
                      Scenario Simulation Execution Failed
                    </h4>
                    <p className="text-xs text-rose-300 font-mono break-words leading-relaxed">
                      {runError}
                    </p>
                  </div>
                </div>

                <div className="pl-8 text-xs text-gray-400 border-t border-rose-900/40 pt-2 space-y-2">
                  <p className="leading-relaxed">
                    <strong className="text-rose-200">Remediation Advice:</strong> Verify that the target node ID specified in the scenario action exists in the selected base model ({selectedModel?.name || selectedModelId}) and that all network parameters (IP assignments, CIDR prefixes, destination ports) are valid.
                  </p>
                  <div className="flex items-center gap-2 pt-1">
                    {selectedScenarioId && (
                      <button
                        type="button"
                        onClick={() => onRunScenario(selectedScenarioId)}
                        className="px-3 py-1.5 rounded bg-rose-900 hover:bg-rose-800 text-rose-100 font-mono text-xs flex items-center gap-1.5 border border-rose-700 transition"
                      >
                        <RefreshCw className="w-3.5 h-3.5" />
                        <span>Retry Simulation</span>
                      </button>
                    )}
                    {onClearError && (
                      <button
                        type="button"
                        onClick={onClearError}
                        className="px-3 py-1.5 rounded bg-surface hover:bg-surface-raised text-gray-300 text-xs border border-surface-border transition"
                      >
                        Dismiss
                      </button>
                    )}
                  </div>
                </div>
              </div>
            </section>
          );
        }

        // Discrete Empty State
        if (!counterfactualResult) {
          return (
            <section
              className="bg-surface border border-surface-border rounded-lg p-5 shadow-sm space-y-4"
              data-testid="section-c-empty"
            >
              <div className="flex items-center justify-between border-b border-surface-border pb-3">
                <div className="flex items-center gap-2">
                  <span className="px-2 py-0.5 rounded bg-purple-900/50 text-purple-300 font-mono text-[11px] font-semibold border border-purple-700/40">
                    Section C
                  </span>
                  <h3 className="text-sm font-bold text-gray-100 flex items-center gap-2">
                    <Route className="w-4 h-4 text-purple-400" />
                    <span>Deterministic Execution Results & Reachability Shifts</span>
                  </h3>
                </div>
              </div>

              <div className="py-10 px-4 rounded-lg bg-slate-950/60 border border-dashed border-surface-border flex flex-col items-center justify-center text-center space-y-3">
                <div className="p-3 rounded-full bg-surface border border-surface-border text-gray-500">
                  <Route className="w-6 h-6" />
                </div>
                <div className="space-y-1">
                  <h4 className="text-sm font-semibold text-gray-200">
                    No Simulation Results Available
                  </h4>
                  <p className="text-xs text-gray-400 max-w-md leading-relaxed">
                    Select an authoritative baseline model and a counterfactual scenario above, then execute the simulation to calculate hop-by-hop forwarding reachability shifts, invariant status transitions, and path differences.
                  </p>
                </div>
                {selectedScenarioId && (
                  <button
                    type="button"
                    onClick={() => onRunScenario(selectedScenarioId)}
                    className="mt-2 px-4 py-2 rounded bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow transition flex items-center gap-2"
                  >
                    <Play className="w-3.5 h-3.5 fill-current" />
                    <span>Execute Scenario Simulation</span>
                  </button>
                )}
              </div>
            </section>
          );
        }

        // Helper to extract reason code
        const getReasonCode = (diff: PathDifference): string => {
          if (diff.counterfactual_reason) return diff.counterfactual_reason;
          if (diff.baseline_reason) return diff.baseline_reason;
          const match = diff.explanation?.match(/\(([A-Z0-9_]+)\)/);
          if (match && match[1]) return match[1];
          if (diff.explanation?.includes('FIREWALL')) return 'DROPPED_BY_FIREWALL';
          if (diff.explanation?.includes('NO_ROUTE')) return 'NO_ROUTE_TO_HOST';
          if (diff.explanation?.includes('UNMODELED') || diff.explanation?.includes('NO_EGRESS_INTERFACE')) return 'NO_EGRESS_INTERFACE';
          if (diff.explanation?.includes('PORT_NOT_LISTENING')) return 'PORT_NOT_LISTENING';
          return diff.counterfactual_status === 'BLOCKED' ? 'DROPPED_BY_FIREWALL' : 'ROUTED_LPM';
        };

        const findNodeByIp = (ip: string): ModelNode | null => {
          if (!selectedModel?.nodes) return null;
          for (const node of Object.values(selectedModel.nodes)) {
            if (node.interfaces?.some((iface) => iface.ip_assignments?.some((asgn) => asgn.ip_address === ip))) {
              return node;
            }
          }
          return null;
        };

        const isLiveRun = Boolean(
          lastLiveRunId &&
          (counterfactualResult.run_id === lastLiveRunId || counterfactualResult.result_id === lastLiveRunId)
        );

        const pathDiffs = counterfactualResult.path_differences || counterfactualResult.reachability_diffs || [];
        const invariantDiffs = counterfactualResult.invariant_differences || counterfactualResult.invariant_diffs || [];
        const newlyReachableCount =
          counterfactualResult.newly_reachable_paths_count ?? counterfactualResult.newly_reachable_count ?? 0;
        const newlyBlockedCount =
          counterfactualResult.newly_blocked_paths_count ?? counterfactualResult.newly_blocked_count ?? 0;
        const regressionsCount =
          counterfactualResult.security_regressions_count ?? counterfactualResult.invariant_regressions_count ?? 0;
        const actionsCount = counterfactualResult.applied_actions_count ?? 0;

        const filteredPaths = pathDiffs.filter(
          (p) =>
            !pathFilter ||
            p.source_ip.includes(pathFilter) ||
            p.destination_ip.includes(pathFilter) ||
            (p.explanation && p.explanation.toLowerCase().includes(pathFilter.toLowerCase()))
        );

        return (
          <section className="bg-surface border border-surface-border rounded-lg p-5 shadow-sm space-y-4" data-testid="section-c-results">
            {/* Header with Title and Live vs Historical Badge */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-surface-border pb-3">
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <span className="px-2 py-0.5 rounded bg-purple-900/50 text-purple-300 font-mono text-[11px] font-semibold border border-purple-700/40">
                    Section C
                  </span>
                  <h3 className="text-sm font-bold text-gray-100 flex items-center gap-2 truncate">
                    <Route className="w-4 h-4 text-purple-400 shrink-0" />
                    <span>Deterministic Execution Results & Reachability Shifts</span>
                  </h3>
                </div>
                <p className="text-xs text-gray-400 mt-1 leading-relaxed">
                  Comparison of hop-by-hop packet forwarding and security invariants between verified baseline state and counterfactual clone.
                </p>
              </div>

              <div className="flex items-center gap-2.5 font-mono text-xs shrink-0 flex-wrap">
                {isLiveRun ? (
                  <span className="px-2.5 py-1 rounded-full bg-emerald-950/80 text-emerald-300 border border-emerald-600/60 flex items-center gap-1.5 text-[11px] font-semibold">
                    <span className="w-2 h-2 rounded-full bg-emerald-400 inline-block animate-ping" />
                    <span>LATEST SIMULATION RESULT (LIVE)</span>
                  </span>
                ) : (
                  <span className="px-2.5 py-1 rounded-full bg-slate-900 text-gray-300 border border-surface-border flex items-center gap-1.5 text-[11px]">
                    <History className="w-3.5 h-3.5 text-cyan-400" />
                    <span>HISTORICAL RECORD</span>
                    {counterfactualResult.executed_at_iso && (
                      <span className="text-gray-400">
                        ({new Date(counterfactualResult.executed_at_iso).toLocaleTimeString()})
                      </span>
                    )}
                  </span>
                )}

                <div className="flex items-center gap-1 text-gray-400 bg-slate-950 border border-surface-border px-2 py-0.5 rounded text-[11px]">
                  <span>Run ID:</span>
                  <span className="text-gray-200">
                    {counterfactualResult.run_id || counterfactualResult.result_id}
                  </span>
                </div>
              </div>
            </div>

            {/* Mismatch Warning Banner if user changed baseline/scenario without re-running */}
            {!isResultMatching && (
              <div className="p-4 rounded-lg bg-amber-950/40 border border-amber-800 flex items-start gap-3 text-xs text-amber-200">
                <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                <div>
                  <p className="font-semibold text-amber-300">
                    Displaying Stored Results from a Different Baseline or Scenario
                  </p>
                  <p className="mt-1 text-gray-300 leading-relaxed">
                    The results below correspond to baseline model{' '}
                    <code className="text-cyan-300 font-mono font-semibold">{counterfactualResult.base_model_id}</code> and scenario{' '}
                    <code className="text-cyan-300 font-mono font-semibold">{counterfactualResult.scenario_id}</code>. To view results for your current selection ({selectedModelId} / {selectedScenarioId}), click{' '}
                    <span className="font-semibold text-white">"Run Simulation"</span> above.
                  </p>
                </div>
              </div>
            )}

            <div className="space-y-4">
              {/* 4-Column KPI Summary Matrix */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <div className="bg-slate-950 border border-surface-border p-3.5 rounded-lg space-y-1">
                  <span className="text-[10px] font-medium text-gray-400 uppercase tracking-wider block">
                    Newly Reachable Paths
                  </span>
                  <span className="text-2xl font-bold font-mono text-emerald-400 block">
                    +{newlyReachableCount}
                  </span>
                  <span className="text-[10px] text-gray-500 block">Previously blocked/dropped</span>
                </div>

                <div className="bg-slate-950 border border-surface-border p-3.5 rounded-lg space-y-1">
                  <span className="text-[10px] font-medium text-gray-400 uppercase tracking-wider block">
                    Newly Blocked Paths
                  </span>
                  <span className="text-2xl font-bold font-mono text-rose-400 block">
                    +{newlyBlockedCount}
                  </span>
                  <span className="text-[10px] text-gray-500 block">Expected policy effect</span>
                </div>

                <div className="bg-slate-950 border border-surface-border p-3.5 rounded-lg space-y-1">
                  <span className="text-[10px] font-medium text-gray-400 uppercase tracking-wider block">
                    Security Regressions
                  </span>
                  <span
                    className={`text-2xl font-bold font-mono block ${
                      regressionsCount > 0 ? 'text-rose-400' : 'text-emerald-400'
                    }`}
                  >
                    {regressionsCount}
                  </span>
                  <span className="text-[10px] text-gray-500 block">
                    {regressionsCount === 0 ? 'Zero policy violations' : 'Invariants shifted to FAIL'}
                  </span>
                </div>

                <div className="bg-slate-950 border border-surface-border p-3.5 rounded-lg space-y-1">
                  <span className="text-[10px] font-medium text-gray-400 uppercase tracking-wider block">
                    Applied Actions
                  </span>
                  <span className="text-2xl font-bold font-mono text-cyan-400 block">
                    {actionsCount}
                  </span>
                  <span className="text-[10px] text-gray-500 block">Transactional mutations</span>
                </div>
              </div>

              {/* Expected Policy Effect vs Invariant Regression Explanation */}
              <div className="p-3.5 rounded-lg bg-slate-950 border border-surface-border text-xs space-y-2">
                <div className="font-semibold text-gray-200 flex items-center gap-2">
                  <Info className="w-4 h-4 text-cyan-400 shrink-0" />
                  <span>Executive Simulation Analysis: Expected Effects vs Regressions</span>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-1 text-[11px] leading-relaxed">
                  <div className="p-2.5 rounded bg-surface border border-surface-border space-y-1">
                    <span className="font-semibold text-rose-400 font-mono block">
                      [Expected Policy Impact] Ingress Restriction
                    </span>
                    <p className="text-gray-300">
                      {newlyBlockedCount > 0
                        ? `The scenario successfully blocked ${newlyBlockedCount} communication path(s) matching the intended ACL lockdown parameters.`
                        : 'No communication paths were blocked by this scenario run.'}
                    </p>
                  </div>

                  <div className="p-2.5 rounded bg-surface border border-surface-border space-y-1">
                    <span
                      className={`font-semibold font-mono block ${
                        regressionsCount > 0 ? 'text-rose-400' : 'text-emerald-400'
                      }`}
                    >
                      {regressionsCount > 0
                        ? '[CRITICAL REGRESSION] Unintended Side Effect'
                        : '[VERIFIED SAFE] Zero Security Regressions'}
                    </span>
                    <p className="text-gray-300">
                      {regressionsCount > 0
                        ? `Alert: ${regressionsCount} security invariant(s) shifted from PASS to FAIL, indicating collateral policy breakdown.`
                        : 'All formal security invariants maintained integrity. No unauthorized reachability or isolation breaches were introduced.'}
                    </p>
                  </div>
                </div>
              </div>

              {/* Fingerprint Transition Card */}
              <div className="bg-slate-950 border border-surface-border p-3 rounded-lg font-mono text-xs flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div className="min-w-0">
                  <span className="text-gray-500 text-[10px] uppercase block">Baseline Model Fingerprint</span>
                  <span className="text-gray-200 truncate block" title={counterfactualResult.baseline_fingerprint}>
                    {counterfactualResult.baseline_fingerprint}
                  </span>
                </div>

                <ArrowRight className="w-4 h-4 text-cyan-400 shrink-0 hidden sm:block" />

                <div className="min-w-0">
                  <span className="text-gray-500 text-[10px] uppercase block">Counterfactual Model Fingerprint</span>
                  <span className="text-cyan-300 truncate block" title={counterfactualResult.counterfactual_fingerprint}>
                    {counterfactualResult.counterfactual_fingerprint}
                  </span>
                </div>
              </div>

              {/* Path Differences Table with Deep Inspectable Drawer */}
              <div className="bg-slate-950 border border-surface-border rounded-lg overflow-hidden">
                <div className="p-3 border-b border-surface-border flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <h4 className="text-xs font-bold text-gray-200 uppercase tracking-wider flex items-center gap-1.5">
                      <Route className="w-3.5 h-3.5 text-indigo-400" />
                      <span>Path Reachability Status Shifts ({pathDiffs.length})</span>
                    </h4>
                    <span className="text-[10px] text-gray-400 font-mono">
                      (Click row to inspect route & boundary details)
                    </span>
                  </div>

                  {pathDiffs.length > 3 && (
                    <div className="relative">
                      <input
                        type="text"
                        value={pathFilter}
                        onChange={(e) => setPathFilter(e.target.value)}
                        placeholder="Filter IP or explanation..."
                        className="bg-surface border border-surface-border rounded px-2.5 py-1 text-xs text-gray-200 font-mono focus:outline-none focus:border-cyan-500 w-48"
                      />
                    </div>
                  )}
                </div>

                {filteredPaths.length === 0 ? (
                  <div className="p-6 text-center text-xs text-gray-400">
                    {pathDiffs.length === 0
                      ? 'No reachability status shifts detected between baseline and counterfactual state.'
                      : 'No path shifts match your filter query.'}
                  </div>
                ) : (
                  <div className="divide-y divide-surface-border text-xs font-mono">
                    {filteredPaths.map((diff, idx) => {
                      const isExpanded = expandedPathIdx === idx;
                      const reasonCode = getReasonCode(diff);
                      const srcNode = findNodeByIp(diff.source_ip);
                      const dstNode = findNodeByIp(diff.destination_ip);

                      return (
                        <div key={idx} className="transition">
                          <div
                            onClick={() => setExpandedPathIdx(isExpanded ? null : idx)}
                            className="p-3.5 flex flex-col md:flex-row md:items-center justify-between gap-3 hover:bg-surface-raised/50 cursor-pointer select-none"
                          >
                            <div className="space-y-1 min-w-0">
                              <div className="flex flex-wrap items-center gap-2">
                                <span className="text-gray-400 hover:text-white transition">
                                  {isExpanded ? (
                                    <ChevronUp className="w-3.5 h-3.5 text-cyan-400" />
                                  ) : (
                                    <ChevronDown className="w-3.5 h-3.5 text-gray-500" />
                                  )}
                                </span>
                                <span className="text-white font-semibold">
                                  {diff.source_ip} &rarr; {diff.destination_ip}
                                  {diff.destination_port ? `:${diff.destination_port}` : ''}
                                </span>
                                <span className="px-1.5 py-0.2 rounded text-[10px] bg-slate-900 border border-gray-800 text-gray-400">
                                  {diff.protocol}
                                </span>
                                <span
                                  className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                                    diff.change_type === 'NEWLY_BLOCKED'
                                      ? 'bg-rose-950 text-rose-300 border border-rose-800'
                                      : diff.change_type === 'NEWLY_REACHABLE'
                                      ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                                      : 'bg-purple-950 text-purple-300 border border-purple-800'
                                  }`}
                                >
                                  {diff.change_type}
                                </span>
                                <span className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-cyan-950/60 text-cyan-300 border border-cyan-800/60">
                                  {reasonCode}
                                </span>
                              </div>
                              <p className="text-gray-400 text-[11px] font-sans leading-relaxed pl-5">
                                {diff.explanation}
                              </p>
                            </div>

                            <div className="flex items-center gap-2 shrink-0 pl-5 md:pl-0">
                              <span className="px-2 py-1 rounded bg-surface border border-surface-border text-gray-400 text-[11px]">
                                {diff.baseline_status}
                              </span>
                              <ArrowRight className="w-3.5 h-3.5 text-gray-500" />
                              <span
                                className={`px-2 py-1 rounded text-[11px] font-bold ${
                                  diff.counterfactual_status === 'REACHABLE'
                                    ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                                    : diff.counterfactual_status === 'BLOCKED'
                                    ? 'bg-rose-950 text-rose-300 border border-rose-800'
                                    : 'bg-amber-950 text-amber-300 border border-amber-800'
                                }`}
                              >
                                {diff.counterfactual_status}
                              </span>
                              <button
                                type="button"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  setExpandedPathIdx(isExpanded ? null : idx);
                                }}
                                className="ml-2 px-2 py-1 rounded bg-surface hover:bg-surface-raised border border-surface-border text-gray-300 text-[11px] flex items-center gap-1 transition"
                              >
                                <Eye className="w-3 h-3 text-cyan-400" />
                                <span>{isExpanded ? 'Collapse' : 'Inspect'}</span>
                              </button>
                            </div>
                          </div>

                          {/* Expanded Inspection Drawer */}
                          {isExpanded && (
                            <div className="bg-slate-900/90 border-t border-surface-border p-4 space-y-3 font-sans text-xs">
                              <div className="flex items-center justify-between border-b border-surface-border pb-2">
                                <span className="text-xs font-semibold text-cyan-300 font-mono flex items-center gap-1.5">
                                  <Info className="w-3.5 h-3.5 text-cyan-400" />
                                  <span>Path Forwarding & Policy Trace Inspection</span>
                                </span>
                                <span className="text-[10px] font-mono text-gray-500">
                                  Index: #{idx + 1}
                                </span>
                              </div>

                              <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
                                {/* Panel 1: Endpoints */}
                                <div className="p-3 rounded bg-surface border border-surface-border space-y-2">
                                  <span className="text-[10px] font-semibold text-gray-400 uppercase font-mono block">
                                    1. Traffic Endpoints
                                  </span>
                                  <div className="space-y-1.5 text-gray-300">
                                    <div>
                                      <span className="text-gray-500 block text-[10px]">Source Endpoint:</span>
                                      <span className="font-mono text-white font-semibold">{diff.source_ip}</span>
                                      {srcNode && (
                                        <span className="text-[11px] text-cyan-400 block font-mono">
                                          &bull; {srcNode.label || srcNode.node_id} ({srcNode.node_type})
                                        </span>
                                      )}
                                    </div>
                                    <div>
                                      <span className="text-gray-500 block text-[10px]">Destination Endpoint:</span>
                                      <span className="font-mono text-white font-semibold">
                                        {diff.destination_ip}:{diff.destination_port || '*'}
                                      </span>
                                      {dstNode && (
                                        <span className="text-[11px] text-cyan-400 block font-mono">
                                          &bull; {dstNode.label || dstNode.node_id} ({dstNode.node_type})
                                        </span>
                                      )}
                                    </div>
                                    <div>
                                      <span className="text-gray-500 block text-[10px]">Protocol:</span>
                                      <span className="font-mono text-gray-200">{diff.protocol}</span>
                                    </div>
                                  </div>
                                </div>

                                {/* Panel 2: Transition */}
                                <div className="p-3 rounded bg-surface border border-surface-border space-y-2">
                                  <span className="text-[10px] font-semibold text-gray-400 uppercase font-mono block">
                                    2. Deterministic State Transition
                                  </span>
                                  <div className="space-y-2">
                                    <div>
                                      <span className="text-gray-500 block text-[10px]">Baseline Model Status:</span>
                                      <div className="flex items-center gap-1.5 mt-0.5">
                                        <span className="px-2 py-0.5 rounded bg-slate-950 border border-surface-border font-mono text-gray-300 text-[11px]">
                                          {diff.baseline_status}
                                        </span>
                                        {diff.baseline_reason && (
                                          <span className="text-[10px] font-mono text-gray-400">
                                            ({diff.baseline_reason})
                                          </span>
                                        )}
                                      </div>
                                    </div>

                                    <div>
                                      <span className="text-gray-500 block text-[10px]">Counterfactual Model Status:</span>
                                      <div className="flex items-center gap-1.5 mt-0.5">
                                        <span
                                          className={`px-2 py-0.5 rounded font-mono text-[11px] font-bold ${
                                            diff.counterfactual_status === 'REACHABLE'
                                              ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                                              : diff.counterfactual_status === 'BLOCKED'
                                              ? 'bg-rose-950 text-rose-300 border border-rose-800'
                                              : 'bg-amber-950 text-amber-300 border border-amber-800'
                                          }`}
                                        >
                                          {diff.counterfactual_status}
                                        </span>
                                        {diff.counterfactual_reason && (
                                          <span className="text-[10px] font-mono text-gray-400">
                                            ({diff.counterfactual_reason})
                                          </span>
                                        )}
                                      </div>
                                    </div>

                                    <div>
                                      <span className="text-gray-500 block text-[10px]">Shift Classification:</span>
                                      <span className="font-mono text-cyan-300 font-semibold">{diff.change_type}</span>
                                    </div>
                                  </div>
                                </div>

                                {/* Panel 3: Root Cause & Rules */}
                                <div className="p-3 rounded bg-surface border border-surface-border space-y-2">
                                  <span className="text-[10px] font-semibold text-gray-400 uppercase font-mono block">
                                    3. Reason Code & Provenance
                                  </span>
                                  <div className="space-y-1.5">
                                    <div>
                                      <span className="text-gray-500 block text-[10px]">Engine Reason Code:</span>
                                      <span className="px-2 py-0.5 rounded bg-slate-950 border border-surface-border font-mono text-cyan-300 font-semibold text-[11px] inline-block mt-0.5">
                                        {reasonCode}
                                      </span>
                                    </div>
                                    <div>
                                      <span className="text-gray-500 block text-[10px]">Engine Explanation:</span>
                                      <p className="text-gray-300 text-[11px] leading-relaxed mt-0.5">
                                        {diff.explanation}
                                      </p>
                                    </div>
                                  </div>
                                </div>
                              </div>

                              {/* INDETERMINATE Disclaimer if relevant */}
                              {(diff.baseline_status === 'INDETERMINATE' || diff.counterfactual_status === 'INDETERMINATE') && (
                                <div className="p-3 rounded bg-amber-950/40 border border-amber-800/80 text-xs text-amber-200 flex items-start gap-2.5">
                                  <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                                  <div>
                                    <span className="font-semibold text-amber-300 block font-mono text-[11px]">
                                      [Deterministic Boundary Constraint] Unmodeled Interface
                                    </span>
                                    <p className="text-gray-300 text-[11px] leading-relaxed mt-0.5">
                                      Destination IP <code className="text-amber-300 font-mono">{diff.destination_ip}</code> is not assigned to an active interface inside this snapshot. In a deterministic digital twin, <strong className="text-amber-200">INDETERMINATE does NOT mean secure or blocked</strong>; it reflects an unmodeled boundary where packet delivery cannot be authoritatively proven.
                                    </p>
                                  </div>
                                </div>
                              )}
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>

              {/* Invariant Differences Table */}
              {invariantDiffs.length > 0 && (
                <div className="bg-slate-950 border border-surface-border rounded-lg overflow-hidden">
                  <div className="p-3 border-b border-surface-border flex items-center justify-between">
                    <h4 className="text-xs font-bold text-gray-200 uppercase tracking-wider flex items-center gap-1.5">
                      <ShieldAlert className="w-3.5 h-3.5 text-amber-400" />
                      Formal Security Invariant State Transitions ({invariantDiffs.length})
                    </h4>
                  </div>

                  <div className="divide-y divide-surface-border text-xs font-mono">
                    {invariantDiffs.map((diff, idx) => (
                      <div
                        key={idx}
                        className="p-3.5 flex flex-col md:flex-row md:items-center justify-between gap-3 hover:bg-surface-raised/40 transition"
                      >
                        <div className="space-y-1 min-w-0">
                          <div className="flex items-center gap-2">
                            <span className="text-white font-semibold">{diff.invariant_name}</span>
                            <span className="px-1.5 py-0.2 rounded text-[9px] font-bold bg-amber-950/80 text-amber-300 border border-amber-800/60">
                              {diff.severity}
                            </span>
                          </div>
                          <p className="text-gray-400 text-[11px] font-sans leading-relaxed">
                            {diff.explanation}
                          </p>
                        </div>

                        <div className="flex items-center gap-2 font-bold text-xs shrink-0">
                          <span className="px-2 py-1 rounded bg-surface border border-surface-border text-gray-400">
                            {diff.baseline_status}
                          </span>
                          <ArrowRight className="w-3.5 h-3.5 text-gray-500" />
                          <span
                            className={`px-2 py-1 rounded ${
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
          </section>
        );
      })()}

      {/* ========================================================================= */}
      {/* SECTION D: Model Evidence, Limitations & Operational Boundaries           */}
      {/* ========================================================================= */}
      <section className="bg-surface border border-surface-border rounded-lg p-5 shadow-sm space-y-4">
        <div className="flex items-center justify-between border-b border-surface-border pb-3">
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <span className="px-2 py-0.5 rounded bg-emerald-900/50 text-emerald-300 font-mono text-[11px] font-semibold border border-emerald-700/40">
                Section D
              </span>
              <h3 className="text-sm font-bold text-gray-100 flex items-center gap-2 truncate">
                <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
                Evidence Grounding, Known Limitations & Boundary Specifications
              </h3>
            </div>
            <p className="text-xs text-gray-400 mt-1 leading-relaxed">
              Grounding disclosures and strict semantic boundary limits governing simulation interpretation.
            </p>
          </div>

          <button
            type="button"
            onClick={() => setShowEvidenceAccordion(!showEvidenceAccordion)}
            className="p-1.5 rounded hover:bg-surface-raised text-gray-400 hover:text-gray-200 transition"
          >
            {showEvidenceAccordion ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </button>
        </div>

        {showEvidenceAccordion && (
          <div className="space-y-4 pt-1">
            {/* Status Code Plain English Explanation Reference */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
              <div className="p-3 rounded-lg bg-slate-950 border border-surface-border space-y-1.5">
                <div className="flex items-center gap-1.5 text-emerald-400 font-semibold font-mono">
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  <span>REACHABLE</span>
                </div>
                <p className="text-gray-300 text-[11px] leading-relaxed">
                  Traffic traverses deterministic longest-prefix match (LPM) routing tables and passes all ingress/egress ACL rules to reach the destination interface.
                </p>
              </div>

              <div className="p-3 rounded-lg bg-slate-950 border border-surface-border space-y-1.5">
                <div className="flex items-center gap-1.5 text-rose-400 font-semibold font-mono">
                  <XCircle className="w-3.5 h-3.5" />
                  <span>BLOCKED</span>
                </div>
                <p className="text-gray-300 text-[11px] leading-relaxed">
                  Traffic is explicitly discarded by an active firewall access-control entry (ACE) with rule action DENY, or encounters an explicit blackhole/null route.
                </p>
              </div>

              <div className="p-3 rounded-lg bg-slate-950 border border-surface-border space-y-1.5">
                <div className="flex items-center gap-1.5 text-amber-400 font-semibold font-mono">
                  <AlertTriangle className="w-3.5 h-3.5" />
                  <span>INDETERMINATE</span>
                </div>
                <p className="text-gray-300 text-[11px] leading-relaxed">
                  The query targets an IP address that is not assigned to a known modeled interface in this digital twin model. <strong className="text-amber-200">Note: INDETERMINATE does NOT mean secure or blocked; it reflects an unmodeled boundary.</strong>
                </p>
              </div>
            </div>

            {/* Model Limitations List */}
            {selectedModel && selectedModel.known_limitations && selectedModel.known_limitations.length > 0 && (
              <div className="p-3.5 rounded-lg bg-slate-950 border border-surface-border space-y-2">
                <span className="text-xs font-semibold text-gray-200 flex items-center gap-2">
                  <Info className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Explicit Known Model Limitations ({selectedModel.known_limitations.length})</span>
                </span>
                <div className="space-y-1.5 text-xs text-gray-300 font-mono">
                  {selectedModel.known_limitations.map((lim, idx) => (
                    <div key={idx} className="flex items-start gap-2 text-[11px]">
                      <span className="text-amber-400 shrink-0">•</span>
                      <div>
                        <span className="font-bold text-gray-200 font-mono">{lim.limitation_code}</span>
                        {lim.impact && (
                          <span className="ml-1 px-1.5 py-0.2 rounded text-[10px] bg-amber-950/70 border border-amber-800/60 text-amber-300 font-mono">
                            {lim.impact}
                          </span>
                        )}
                        :{' '}
                        <span className="text-gray-400 font-sans">{lim.description}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Formal Twin Operational Disclaimer */}
            <div className="p-4 rounded-lg bg-indigo-950/20 border border-indigo-900/40 text-xs text-indigo-200 space-y-1.5">
              <span className="font-semibold text-indigo-300 flex items-center gap-1.5">
                <ShieldCheck className="w-4 h-4 text-indigo-400" />
                <span>Deterministic Digital Twin Boundary Disclaimer</span>
              </span>
              <p className="text-[11px] text-gray-300 leading-relaxed">
                The Scenario Laboratory operates exclusively on verifiable, deterministic models extracted from real topology snapshots or imported device configurations. It does not use generative heuristics or synthetic metric fabrication. Forwarding traces simulate packet traversal against exact longest-prefix match (LPM) routing tables and static ACL rulesets. Live physical hardware ASIC timings, fiber optical characteristics, and unmodeled dynamic routing flaps are strictly outside the formal model boundary.
              </p>
            </div>
          </div>
        )}
      </section>

      {/* ========================================================================= */}
      {/* Modal: Construct Counterfactual Scenario                                 */}
      {/* ========================================================================= */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 bg-black/80 flex items-center justify-center p-4">
          <form
            onSubmit={handleCreate}
            className="bg-surface border border-surface-border rounded-lg shadow-2xl max-w-lg w-full p-6 space-y-4"
          >
            <div className="border-b border-surface-border pb-3">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Plus className="w-4 h-4 text-cyan-400" />
                <span>Construct Counterfactual Scenario</span>
              </h3>
              <p className="text-xs text-gray-400 mt-1">
                Define hypothetical mutations against base model:{' '}
                <span className="text-gray-200 font-mono font-semibold">
                  {selectedModel?.name || selectedModelId}
                </span>
              </p>
            </div>

            <div className="space-y-3.5 text-xs">
              <div>
                <label className="block text-gray-300 font-medium mb-1">Scenario Name</label>
                <input
                  type="text"
                  value={scenName}
                  onChange={(e) => setScenName(e.target.value)}
                  className="w-full bg-slate-950 border border-surface-border rounded px-3 py-2 text-gray-200 focus:outline-none focus:border-cyan-500 font-mono"
                  placeholder="e.g. Emergency External Lockdown"
                  required
                />
              </div>

              <div>
                <label className="block text-gray-300 font-medium mb-1">Description & Purpose</label>
                <textarea
                  value={scenDesc}
                  onChange={(e) => setScenDesc(e.target.value)}
                  rows={2}
                  className="w-full bg-slate-950 border border-surface-border rounded px-3 py-1.5 text-gray-200 focus:outline-none focus:border-cyan-500"
                  placeholder="Explain the security intention or operational goal"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-gray-300 font-medium mb-1">Action Type</label>
                  <select
                    value={actionType}
                    onChange={(e) => setActionType(e.target.value as SimulationActionType)}
                    className="w-full bg-slate-950 border border-surface-border rounded px-3 py-2 text-gray-200 focus:outline-none focus:border-cyan-500 font-mono"
                  >
                    <option value="ADD_FIREWALL_RULE">ADD_FIREWALL_RULE</option>
                    <option value="ADD_ROUTE">ADD_ROUTE</option>
                    <option value="REMOVE_ROUTE">REMOVE_ROUTE</option>
                    <option value="MODIFY_ROUTE">MODIFY_ROUTE</option>
                  </select>
                </div>

                <div>
                  <label className="block text-gray-300 font-medium mb-1">Target Device / Node</label>
                  {availableNodes.length > 0 ? (
                    <select
                      value={targetNode}
                      onChange={(e) => setTargetNode(e.target.value)}
                      className="w-full bg-slate-950 border border-surface-border rounded px-3 py-2 text-gray-200 focus:outline-none focus:border-cyan-500 font-mono text-xs"
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
                      placeholder="e.g. router-1"
                      className="w-full bg-slate-950 border border-surface-border rounded px-3 py-2 text-gray-200 focus:outline-none focus:border-cyan-500 font-mono"
                      required
                    />
                  )}
                </div>
              </div>

              {actionType === 'ADD_FIREWALL_RULE' && (
                <div className="p-3 rounded bg-slate-950 border border-surface-border space-y-3">
                  <span className="text-[11px] font-semibold text-cyan-400 font-mono uppercase block">
                    Firewall Rule Parameters
                  </span>
                  <div className="grid grid-cols-3 gap-2">
                    <div>
                      <label className="block text-gray-400 text-[11px] mb-1">Policy</label>
                      <select
                        value={actionPolicy}
                        onChange={(e) => setActionPolicy(e.target.value as 'DENY' | 'ALLOW')}
                        className="w-full bg-surface border border-surface-border rounded px-2.5 py-1.5 text-gray-200 font-mono"
                      >
                        <option value="DENY">DENY</option>
                        <option value="ALLOW">ALLOW</option>
                      </select>
                    </div>

                    <div>
                      <label className="block text-gray-400 text-[11px] mb-1">Direction</label>
                      <select
                        value={actionDirection}
                        onChange={(e) => setActionDirection(e.target.value as 'INGRESS' | 'EGRESS')}
                        className="w-full bg-surface border border-surface-border rounded px-2.5 py-1.5 text-gray-200 font-mono"
                      >
                        <option value="INGRESS">INGRESS</option>
                        <option value="EGRESS">EGRESS</option>
                      </select>
                    </div>

                    <div>
                      <label className="block text-gray-400 text-[11px] mb-1">Protocol</label>
                      <select
                        value={actionProtocol}
                        onChange={(e) => setActionProtocol(e.target.value as 'TCP' | 'UDP' | 'ANY')}
                        className="w-full bg-surface border border-surface-border rounded px-2.5 py-1.5 text-gray-200 font-mono"
                      >
                        <option value="TCP">TCP</option>
                        <option value="UDP">UDP</option>
                        <option value="ANY">ANY</option>
                      </select>
                    </div>
                  </div>

                  <div>
                    <label className="block text-gray-400 text-[11px] mb-1">Destination Port</label>
                    <input
                      type="number"
                      value={actionPort}
                      onChange={(e) => setActionPort(parseInt(e.target.value, 10) || 443)}
                      className="w-full bg-surface border border-surface-border rounded px-2.5 py-1.5 text-gray-200 font-mono"
                    />
                  </div>
                </div>
              )}

              {actionType.includes('ROUTE') && (
                <div className="p-3 rounded bg-slate-950 border border-surface-border space-y-3">
                  <span className="text-[11px] font-semibold text-cyan-400 font-mono uppercase block">
                    Routing Parameters
                  </span>
                  <div>
                    <label className="block text-gray-400 text-[11px] mb-1">Destination Prefix (CIDR)</label>
                    <input
                      type="text"
                      value={actionPrefix}
                      onChange={(e) => setActionPrefix(e.target.value)}
                      placeholder="e.g. 10.0.1.0/24"
                      className="w-full bg-surface border border-surface-border rounded px-2.5 py-1.5 text-gray-200 font-mono"
                      required
                    />
                  </div>

                  {actionType !== 'REMOVE_ROUTE' && (
                    <div>
                      <label className="block text-gray-400 text-[11px] mb-1">Next Hop IP</label>
                      <input
                        type="text"
                        value={actionNextHop}
                        onChange={(e) => setActionNextHop(e.target.value)}
                        placeholder="e.g. 10.0.1.1"
                        className="w-full bg-surface border border-surface-border rounded px-2.5 py-1.5 text-gray-200 font-mono"
                        required
                      />
                    </div>
                  )}
                </div>
              )}
            </div>

            <div className="flex justify-end gap-2 pt-3 border-t border-surface-border">
              <button
                type="button"
                onClick={() => setShowCreateModal(false)}
                className="px-3.5 py-1.5 rounded bg-surface-raised hover:bg-surface text-gray-300 text-xs font-medium border border-surface-border transition"
              >
                Cancel
              </button>
              <button
                type="submit"
                className="px-4 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow transition"
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
