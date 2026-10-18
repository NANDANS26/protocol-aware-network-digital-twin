import React, { useState, useEffect, useCallback } from 'react';
import {
  GitCompare,
  ShieldCheck,
  Route,
  FileCheck2,
  AlertTriangle,
  Info,
  RefreshCw,
} from 'lucide-react';
import { apiClient } from '../api/client';
import { CounterfactualScenarioView } from './twin/CounterfactualScenarioView';
import { SecurityVerificationView } from './twin/SecurityVerificationView';
import { ReachabilityWorkbench } from './twin/ReachabilityWorkbench';
import type {
  NetworkModel,
  SimulationScenario,
  CounterfactualResult,
  SecurityInvariant,
  VerificationResult,
  ReachabilityQuery,
  ReachabilityResult,
} from '../types/simulation';

export const ScenarioLaboratoryView: React.FC = () => {
  const [activeSubTab, setActiveSubTab] = useState<'scenarios' | 'invariants' | 'reachability' | 'boundaries'>('scenarios');
  const [models, setModels] = useState<NetworkModel[]>([]);
  const [selectedModelId, setSelectedModelId] = useState<string>('');
  const [scenarios, setScenarios] = useState<SimulationScenario[]>([]);
  const [selectedScenarioId, setSelectedScenarioId] = useState<string>('');
  const [counterfactualResult, setCounterfactualResult] = useState<CounterfactualResult | null>(null);
  const [invariants, setInvariants] = useState<SecurityInvariant[]>([]);
  const [verificationResults, setVerificationResults] = useState<VerificationResult[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [actionLoading, setActionLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const loadData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [modelsData, scenariosData, invariantsData] = await Promise.all([
        apiClient.listModels ? apiClient.listModels().catch(() => []) : Promise.resolve([]),
        apiClient.listScenarios ? apiClient.listScenarios().catch(() => []) : Promise.resolve([]),
        apiClient.listInvariants ? apiClient.listInvariants().catch(() => []) : Promise.resolve([]),
      ]);

      setModels(modelsData);
      if (modelsData.length > 0 && !selectedModelId && modelsData[0]) {
        setSelectedModelId(modelsData[0].model_id);
      }

      setScenarios(scenariosData);
      if (scenariosData.length > 0 && !selectedScenarioId && scenariosData[0]) {
        setSelectedScenarioId(scenariosData[0].scenario_id);
      }

      setInvariants(invariantsData);
    } catch (err: unknown) {
      setError((err as Error).message || 'Failed to load scenario laboratory data');
    } finally {
      setLoading(false);
    }
  }, [selectedModelId, selectedScenarioId]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleRunScenario = async (scenId: string): Promise<CounterfactualResult | null> => {
    setActionLoading(true);
    try {
      const res = await apiClient.runScenario(scenId);
      setCounterfactualResult(res);
      return res;
    } catch (err: unknown) {
      setError((err as Error).message || 'Failed to run scenario');
      return null;
    } finally {
      setActionLoading(false);
    }
  };

  const handleCreateScenario = async (scenario: SimulationScenario): Promise<void> => {
    setActionLoading(true);
    try {
      const created = await apiClient.createScenario(scenario);
      setScenarios((prev) => [created, ...prev]);
      setSelectedScenarioId(created.scenario_id);
    } catch (err: unknown) {
      setError((err as Error).message || 'Failed to create scenario');
    } finally {
      setActionLoading(false);
    }
  };

  const handleRunVerification = async (modelId: string): Promise<VerificationResult[]> => {
    setActionLoading(true);
    try {
      const results = await apiClient.runVerification({ model_id: modelId });
      setVerificationResults(results);
      return results;
    } catch (err: unknown) {
      setError((err as Error).message || 'Failed to run verification');
      return [];
    } finally {
      setActionLoading(false);
    }
  };

  const handleCreateInvariant = async (inv: SecurityInvariant): Promise<void> => {
    setActionLoading(true);
    try {
      const saved = await apiClient.createInvariant(inv);
      setInvariants((prev) => [saved, ...prev]);
    } catch (err: unknown) {
      setError((err as Error).message || 'Failed to create invariant');
    } finally {
      setActionLoading(false);
    }
  };

  const handleEvaluateReachability = async (query: ReachabilityQuery): Promise<ReachabilityResult | null> => {
    setActionLoading(true);
    try {
      const res = await apiClient.evaluateReachability(query);
      return res;
    } catch (err: unknown) {
      setError((err as Error).message || 'Failed to evaluate reachability');
      return null;
    } finally {
      setActionLoading(false);
    }
  };

  return (
    <div className="space-y-6" data-testid="scenario-laboratory">
      {/* Header Banner */}
      <div className="p-5 rounded-lg border border-indigo-900/40 bg-gradient-to-r from-indigo-950/40 to-surface-raised flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="px-2 py-0.5 rounded bg-indigo-600/30 text-indigo-300 text-xs font-mono font-medium border border-indigo-500/30">
              Scenario Laboratory
            </span>
            <h2 className="text-base font-semibold text-gray-100">
              Deterministic Security Verification & What-If Simulation
            </h2>
            <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-semibold">
              Verified Engine
            </span>
          </div>
          <p className="text-xs text-gray-300 max-w-3xl leading-relaxed">
            Deterministic evaluation of policy invariants, counterfactual network topology mutations, and hop-by-hop forwarding reachability traces grounded in verified models.
          </p>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <button
            onClick={loadData}
            disabled={loading}
            className="px-3 py-1.5 rounded bg-surface hover:bg-surface-raised border border-surface-border text-xs font-mono text-gray-300 flex items-center gap-1.5 transition"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-indigo-400' : ''}`} />
            <span>Reload</span>
          </button>
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-lg bg-rose-950/40 border border-rose-800/50 flex items-start gap-3 text-rose-300 text-xs">
          <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
          <span>{error}</span>
        </div>
      )}

      {/* Navigation Subtabs */}
      <div className="flex items-center gap-2 border-b border-surface-border pb-2 overflow-x-auto">
        <button
          onClick={() => setActiveSubTab('scenarios')}
          className={`flex items-center gap-2 px-3 py-2 rounded text-xs font-medium font-mono transition ${
            activeSubTab === 'scenarios'
              ? 'bg-indigo-600/20 text-indigo-300 border border-indigo-500/30'
              : 'text-gray-400 hover:text-gray-200 hover:bg-surface-raised'
          }`}
        >
          <GitCompare className="w-3.5 h-3.5" />
          <span>What-If Scenarios ({scenarios.length})</span>
        </button>

        <button
          onClick={() => setActiveSubTab('invariants')}
          className={`flex items-center gap-2 px-3 py-2 rounded text-xs font-medium font-mono transition ${
            activeSubTab === 'invariants'
              ? 'bg-indigo-600/20 text-indigo-300 border border-indigo-500/30'
              : 'text-gray-400 hover:text-gray-200 hover:bg-surface-raised'
          }`}
        >
          <ShieldCheck className="w-3.5 h-3.5" />
          <span>Policy Invariants ({invariants.length})</span>
        </button>

        <button
          onClick={() => setActiveSubTab('reachability')}
          className={`flex items-center gap-2 px-3 py-2 rounded text-xs font-medium font-mono transition ${
            activeSubTab === 'reachability'
              ? 'bg-indigo-600/20 text-indigo-300 border border-indigo-500/30'
              : 'text-gray-400 hover:text-gray-200 hover:bg-surface-raised'
          }`}
        >
          <Route className="w-3.5 h-3.5" />
          <span>Reachability Tracer</span>
        </button>

        <button
          onClick={() => setActiveSubTab('boundaries')}
          className={`flex items-center gap-2 px-3 py-2 rounded text-xs font-medium font-mono transition ${
            activeSubTab === 'boundaries'
              ? 'bg-indigo-600/20 text-indigo-300 border border-indigo-500/30'
              : 'text-gray-400 hover:text-gray-200 hover:bg-surface-raised'
          }`}
        >
          <Info className="w-3.5 h-3.5" />
          <span>Operational Boundaries</span>
        </button>
      </div>

      {/* Subtab Contents */}
      {activeSubTab === 'scenarios' && (
        <CounterfactualScenarioView
          models={models}
          selectedModelId={selectedModelId}
          onSelectModel={setSelectedModelId}
          scenarios={scenarios}
          selectedScenarioId={selectedScenarioId}
          onSelectScenario={setSelectedScenarioId}
          onRunScenario={handleRunScenario}
          onCreateScenario={handleCreateScenario}
          counterfactualResult={counterfactualResult}
          loading={actionLoading || loading}
        />
      )}

      {activeSubTab === 'invariants' && (
        <SecurityVerificationView
          models={models}
          selectedModelId={selectedModelId}
          onSelectModel={setSelectedModelId}
          invariants={invariants}
          verificationResults={verificationResults}
          onRunVerification={handleRunVerification}
          onCreateInvariant={handleCreateInvariant}
          loading={actionLoading || loading}
        />
      )}

      {activeSubTab === 'reachability' && (
        <ReachabilityWorkbench
          models={models}
          selectedModelId={selectedModelId}
          onSelectModel={setSelectedModelId}
          onEvaluate={handleEvaluateReachability}
          loading={actionLoading || loading}
        />
      )}

      {activeSubTab === 'boundaries' && (
        <div className="bg-surface/50 border border-gray-800 rounded-lg p-6 space-y-6">
          <div className="flex items-start gap-3">
            <div className="p-2 rounded bg-indigo-500/10 border border-indigo-500/20 text-indigo-400 shrink-0">
              <FileCheck2 className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-gray-100">
                Deterministic Verification Principles & Boundary Specifications
              </h3>
              <p className="text-xs text-gray-400 mt-1 leading-relaxed">
                The Scenario Laboratory operates exclusively on verifiable, deterministic models extracted from real topology snapshots or imported device configurations. It does not use generative heuristics or synthetic metric fabrication.
              </p>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-4 rounded-lg bg-surface border border-gray-800 space-y-2">
              <div className="text-xs font-semibold text-emerald-400 font-mono">
                [Guaranteed Capability] Deterministic Forwarding Simulation
              </div>
              <p className="text-xs text-gray-300 leading-relaxed">
                Forwarding traces simulate hop-by-hop packet evaluation against exact longest-prefix match (LPM) routing tables and firewall rulesets. Hop counts are bounded to detect forwarding loops without unbounded recursion.
              </p>
            </div>

            <div className="p-4 rounded-lg bg-surface border border-gray-800 space-y-2">
              <div className="text-xs font-semibold text-blue-400 font-mono">
                [Guaranteed Capability] Formal Policy Invariant Checking
              </div>
              <p className="text-xs text-gray-300 leading-relaxed">
                Verification evaluates 5 typed invariant classes: Subnet Isolation, Least Privilege, No Transit Routing, Compliance Segmentation, and Bounded Reachability. Violations produce concrete, reproducible counterexample paths.
              </p>
            </div>

            <div className="p-4 rounded-lg bg-surface border border-gray-800 space-y-2">
              <div className="text-xs font-semibold text-purple-400 font-mono">
                [Guaranteed Capability] Counterfactual What-If Mutations
              </div>
              <p className="text-xs text-gray-300 leading-relaxed">
                Simulated mutations (ADD_FIREWALL_RULE, REMOVE_LINK, MODIFY_ROUTE) apply isolated transactional delta layers against baseline models, computing path diffs and invariant status shifts without altering the underlying network twin.
              </p>
            </div>

            <div className="p-4 rounded-lg bg-surface border border-gray-800 space-y-2">
              <div className="text-xs font-semibold text-amber-400 font-mono">
                [Documented Boundary] Non-Goals & Scope Limits
              </div>
              <p className="text-xs text-gray-300 leading-relaxed">
                The laboratory does not perform real-time wire-speed traffic generation or arbitrary active network penetration. Hardware-specific microarchitectural timing differences and physical cable physics are outside the digital twin model scope.
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
