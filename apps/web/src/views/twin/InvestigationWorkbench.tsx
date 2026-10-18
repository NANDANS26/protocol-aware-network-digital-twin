import React, { useState, useEffect, useCallback } from 'react';
import { apiClient } from '../../api/client';
import type {
  InvestigationCase,
  InvestigationType,
  EvidenceClass,
  CandidateStatus,
  EvidenceSufficiency,
  CreateInvestigationRequest,
  RunCounterfactualRequest,
} from '../../types/investigations';
import {
  Search,
  Plus,
  Play,
  RotateCw,
  AlertCircle,
  CheckCircle2,
  AlertTriangle,
  HelpCircle,
  Download,
  Trash2,
  Shield,
  Layers,
  FileText,
  Activity,
  GitBranch,
} from 'lucide-react';

export const InvestigationWorkbench: React.FC = () => {
  const [cases, setCases] = useState<InvestigationCase[]>([]);
  const [selectedCaseId, setSelectedCaseId] = useState<string>('');
  const [currentCase, setCurrentCase] = useState<InvestigationCase | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [executing, setExecuting] = useState<boolean>(false);
  const [counterfactualLoading, setCounterfactualLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  // Modal State for New Investigation
  const [showNewModal, setShowNewModal] = useState<boolean>(false);
  const [newTitle, setNewTitle] = useState<string>('');
  const [newType, setNewType] = useState<InvestigationType>('CONNECTIVITY_FAILURE');
  const [newSrcIp, setNewSrcIp] = useState<string>('');
  const [newDstIp, setNewDstIp] = useState<string>('');
  const [newProto, setNewProto] = useState<string>('TCP');
  const [newDstPort, setNewDstPort] = useState<string>('80');
  const [newHostname, setNewHostname] = useState<string>('');
  const [newModelId, setNewModelId] = useState<string>('');

  // Counterfactual Modal State
  const [showCfModal, setShowCfModal] = useState<boolean>(false);
  const [cfScenarioName, setCfScenarioName] = useState<string>('Hypothetical Remediation Scenario');
  const [cfActionType, setCfActionType] = useState<string>('SET_INTERFACE_STATE');
  const [cfNodeId, setCfNodeId] = useState<string>('router-1');
  const [cfIfaceId, setCfIfaceId] = useState<string>('eth1');
  const [cfState, setCfState] = useState<string>('UP');

  // Load cases list
  const loadCases = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const list = await apiClient.listInvestigations();
      setCases(list);
      const first = list[0];
      if (first && !selectedCaseId) {
        setSelectedCaseId(first.investigation_id);
        setCurrentCase(first);
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to load investigation cases.');
    } finally {
      setLoading(false);
    }
  }, [selectedCaseId]);

  useEffect(() => {
    loadCases();
  }, [loadCases]);

  // Load single case details when selectedCaseId changes
  const loadCaseDetails = useCallback(async (invId: string) => {
    if (!invId) {
      setCurrentCase(null);
      return;
    }
    try {
      const c = await apiClient.getInvestigation(invId);
      setCurrentCase(c);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to load investigation details.');
    }
  }, []);

  useEffect(() => {
    if (selectedCaseId) {
      loadCaseDetails(selectedCaseId);
    }
  }, [selectedCaseId, loadCaseDetails]);

  // Handle case execution
  const handleExecute = async () => {
    if (!selectedCaseId) return;
    try {
      setExecuting(true);
      setError(null);
      const updated = await apiClient.executeInvestigation(selectedCaseId);
      setCurrentCase(updated);
      setCases((prev) => prev.map((c) => (c.investigation_id === updated.investigation_id ? updated : c)));
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to execute investigation.');
    } finally {
      setExecuting(false);
    }
  };

  // Handle create investigation
  const handleCreateCase = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTitle.trim()) return;

    try {
      setLoading(true);
      setError(null);
      const req: CreateInvestigationRequest = {
        title: newTitle.trim(),
        investigation_type: newType,
        scope: {
          source_ip: newSrcIp.trim() || undefined,
          destination_ip: newDstIp.trim() || undefined,
          transport_protocol: newProto.trim() || undefined,
          destination_port: newDstPort.trim() ? parseInt(newDstPort, 10) : undefined,
          hostname: newHostname.trim() || undefined,
          model_id: newModelId.trim() || undefined,
          capture_ids: [],
          snapshot_ids: [],
        },
      };

      const created = await apiClient.createInvestigation(req);
      setCases((prev) => [created, ...prev]);
      setSelectedCaseId(created.investigation_id);
      setCurrentCase(created);
      setShowNewModal(false);
      setNewTitle('');
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to create investigation case.');
    } finally {
      setLoading(false);
    }
  };

  // Handle counterfactual execution
  const handleRunCounterfactual = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedCaseId) return;

    try {
      setCounterfactualLoading(true);
      setError(null);
      const req: RunCounterfactualRequest = {
        scenario_name: cfScenarioName,
        action_type: cfActionType,
        action_parameters: {
          node_id: cfNodeId,
          interface_id: cfIfaceId,
          state: cfState,
        },
      };
      const updated = await apiClient.runInvestigationCounterfactual(selectedCaseId, req);
      setCurrentCase(updated);
      setCases((prev) => prev.map((c) => (c.investigation_id === updated.investigation_id ? updated : c)));
      setShowCfModal(false);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to run counterfactual remediation.');
    } finally {
      setCounterfactualLoading(false);
    }
  };

  // Handle delete
  const handleDeleteCase = async (invId: string) => {
    if (!confirm('Are you sure you want to delete this incident investigation case?')) return;
    try {
      setLoading(true);
      await apiClient.deleteInvestigation(invId);
      const remaining = cases.filter((c) => c.investigation_id !== invId);
      setCases(remaining);
      if (selectedCaseId === invId) {
        const nextCase = remaining[0];
        setSelectedCaseId(nextCase ? nextCase.investigation_id : '');
        setCurrentCase(nextCase || null);
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to delete investigation case.');
    } finally {
      setLoading(false);
    }
  };

  // Handle JSON export
  const handleExport = async (invId: string) => {
    try {
      const data = await apiClient.exportInvestigation(invId);
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `investigation-${invId}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to export investigation case.');
    }
  };

  // Helper badge rendering
  const renderSufficiencyBadge = (s: EvidenceSufficiency) => {
    switch (s) {
      case 'SUFFICIENT':
        return (
          <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-emerald-950 text-emerald-400 border border-emerald-800 flex items-center gap-1">
            <CheckCircle2 className="w-3 h-3" /> SUFFICIENT
          </span>
        );
      case 'PARTIAL':
        return (
          <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-amber-950 text-amber-400 border border-amber-800 flex items-center gap-1">
            <AlertTriangle className="w-3 h-3" /> PARTIAL
          </span>
        );
      case 'INSUFFICIENT':
      default:
        return (
          <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-rose-950 text-rose-400 border border-rose-800 flex items-center gap-1">
            <AlertCircle className="w-3 h-3" /> INSUFFICIENT
          </span>
        );
    }
  };

  const renderCandidateStatusBadge = (status: CandidateStatus) => {
    switch (status) {
      case 'CONFIRMED_WITHIN_MODEL_SCOPE':
        return (
          <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-emerald-950 text-emerald-300 border border-emerald-700 flex items-center gap-1">
            <CheckCircle2 className="w-3 h-3" /> CONFIRMED WITHIN MODEL SCOPE
          </span>
        );
      case 'SUPPORTED_HYPOTHESIS':
        return (
          <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-blue-950 text-blue-300 border border-blue-700 flex items-center gap-1">
            <Activity className="w-3 h-3" /> SUPPORTED HYPOTHESIS
          </span>
        );
      case 'INDETERMINATE':
        return (
          <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-amber-950 text-amber-300 border border-amber-700 flex items-center gap-1">
            <AlertTriangle className="w-3 h-3" /> INDETERMINATE
          </span>
        );
      case 'INSUFFICIENT_EVIDENCE':
      default:
        return (
          <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-gray-800 text-gray-300 border border-gray-600 flex items-center gap-1">
            <HelpCircle className="w-3 h-3" /> INSUFFICIENT EVIDENCE
          </span>
        );
    }
  };

  const renderEvidenceClassBadge = (ec: EvidenceClass) => {
    switch (ec) {
      case 'OBSERVED':
        return <span className="px-1.5 py-0.2 rounded text-[10px] font-semibold bg-emerald-950 text-emerald-300 border border-emerald-700">OBSERVED</span>;
      case 'INFERRED':
        return <span className="px-1.5 py-0.2 rounded text-[10px] font-semibold bg-sky-950 text-sky-300 border border-sky-700">INFERRED</span>;
      case 'SIMULATED':
        return <span className="px-1.5 py-0.2 rounded text-[10px] font-semibold bg-purple-950 text-purple-300 border border-purple-700">SIMULATED</span>;
      case 'PREDICTED':
      default:
        return <span className="px-1.5 py-0.2 rounded text-[10px] font-semibold bg-amber-950 text-amber-300 border border-amber-700">PREDICTED</span>;
    }
  };

  return (
    <div className="space-y-6">
      {/* HEADER BANNER */}
      <div className="bg-gradient-to-r from-gray-900 via-indigo-950/40 to-gray-900 border border-indigo-900/40 rounded-lg p-5">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <span className="px-2 py-0.5 text-[10px] font-bold rounded-full bg-indigo-950 text-indigo-400 border border-indigo-800">
                Phase 10 Verified
              </span>
              <h2 className="text-lg font-bold text-white tracking-wide">
                Evidence-Backed Network Incident Investigation & Root-Cause Analysis
              </h2>
            </div>
            <p className="text-xs text-gray-400 mt-1 max-w-3xl">
              Deterministic, explainable investigation engine strictly grounded in verified evidence. Epistemological classes
              (OBSERVED, INFERRED, SIMULATED, PREDICTED) guarantee that unobserved conditions are never fabricated as confirmed facts.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => setShowNewModal(true)}
              className="px-3 py-1.5 rounded bg-indigo-600 hover:bg-indigo-500 text-white font-medium text-xs flex items-center gap-1.5 shadow-sm transition"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>New Incident Case</span>
            </button>
            <button
              onClick={loadCases}
              disabled={loading}
              className="px-3 py-1.5 rounded bg-gray-800 hover:bg-gray-700 text-gray-300 text-xs flex items-center gap-1.5 border border-gray-700 transition"
              title="Refresh Cases"
            >
              <RotateCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            </button>
          </div>
        </div>
      </div>

      {error && (
        <div className="p-3 bg-rose-950/40 border border-rose-800/60 rounded-md text-rose-300 text-xs flex items-center gap-2">
          <AlertCircle className="w-4 h-4 shrink-0 text-rose-400" />
          <span>{error}</span>
        </div>
      )}

      {/* WORKSPACE GRID */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* SIDEBAR: INCIDENT CASES LIST */}
        <div className="lg:col-span-1 bg-surface border border-gray-800 rounded-lg p-4 space-y-3">
          <div className="flex items-center justify-between border-b border-gray-800 pb-2">
            <span className="text-xs font-bold uppercase tracking-wider text-gray-400">
              Investigation Cases ({cases.length})
            </span>
          </div>

          <div className="space-y-2 max-h-[650px] overflow-y-auto pr-1">
            {cases.length === 0 ? (
              <div className="text-center py-8 text-gray-500 text-xs italic">
                No active investigation cases. Create one to begin evidence-backed root cause analysis.
              </div>
            ) : (
              cases.map((c) => (
                <div
                  key={c.investigation_id}
                  onClick={() => setSelectedCaseId(c.investigation_id)}
                  className={`p-3 rounded-md border text-left cursor-pointer transition ${
                    selectedCaseId === c.investigation_id
                      ? 'bg-indigo-950/40 border-indigo-500 text-white shadow'
                      : 'bg-gray-900/50 border-gray-800 text-gray-300 hover:border-gray-700 hover:bg-gray-900'
                  }`}
                >
                  <div className="flex items-center justify-between text-[11px] mb-1">
                    <span className="font-mono text-gray-400">{c.investigation_id}</span>
                    {renderSufficiencyBadge(c.sufficiency)}
                  </div>
                  <div className="font-semibold text-xs text-gray-100 truncate">{c.title}</div>
                  <div className="text-[10px] text-gray-400 mt-1 flex items-center justify-between">
                    <span>{c.investigation_type}</span>
                    <span className="font-mono">{new Date(c.created_at_iso).toLocaleDateString()}</span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* MAIN PANEL: CASE DETAILS & WORKBENCH */}
        <div className="lg:col-span-3 space-y-6">
          {currentCase ? (
            <>
              {/* CASE HEADER & ACTIONS */}
              <div className="bg-surface border border-gray-800 rounded-lg p-5 space-y-4">
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-gray-800 pb-4">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs text-indigo-400">{currentCase.investigation_id}</span>
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-gray-800 text-gray-300 border border-gray-700">
                        {currentCase.status}
                      </span>
                      {renderSufficiencyBadge(currentCase.sufficiency)}
                    </div>
                    <h3 className="text-base font-bold text-white mt-1">{currentCase.title}</h3>
                    <div className="text-xs text-gray-400 mt-0.5 flex flex-wrap gap-x-4 gap-y-1">
                      <span>Type: <strong className="text-gray-200">{currentCase.investigation_type}</strong></span>
                      <span>Target: <strong className="text-gray-200">{currentCase.scope.source_ip || '*'} &rarr; {currentCase.scope.destination_ip || '*'}</strong></span>
                      {currentCase.scope.destination_port && (
                        <span>Port: <strong className="text-gray-200">{currentCase.scope.destination_port} ({currentCase.scope.transport_protocol || 'TCP'})</strong></span>
                      )}
                      {currentCase.scope.hostname && (
                        <span>Host: <strong className="text-gray-200">{currentCase.scope.hostname}</strong></span>
                      )}
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      onClick={handleExecute}
                      disabled={executing}
                      className="px-3 py-1.5 rounded bg-emerald-600 hover:bg-emerald-500 text-white font-medium text-xs flex items-center gap-1.5 shadow transition disabled:opacity-50"
                    >
                      <Play className={`w-3.5 h-3.5 ${executing ? 'animate-spin' : ''}`} />
                      <span>{executing ? 'Executing...' : 'Run Investigation'}</span>
                    </button>
                    <button
                      onClick={() => setShowCfModal(true)}
                      className="px-3 py-1.5 rounded bg-purple-600 hover:bg-purple-500 text-white font-medium text-xs flex items-center gap-1.5 shadow transition"
                    >
                      <GitBranch className="w-3.5 h-3.5" />
                      <span>Counterfactual</span>
                    </button>
                    <button
                      onClick={() => handleExport(currentCase.investigation_id)}
                      className="p-1.5 rounded bg-gray-800 hover:bg-gray-700 text-gray-300 border border-gray-700"
                      title="Export Case JSON"
                    >
                      <Download className="w-4 h-4" />
                    </button>
                    <button
                      onClick={() => handleDeleteCase(currentCase.investigation_id)}
                      className="p-1.5 rounded bg-rose-950/40 hover:bg-rose-900/60 text-rose-300 border border-rose-800"
                      title="Delete Case"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                </div>

                {/* PRIMARY ROOT CAUSE CALLOUT */}
                {currentCase.candidate_explanations.length > 0 && (
                  <div className="p-4 bg-gray-900 border border-gray-700 rounded-lg">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-xs font-bold uppercase tracking-wider text-gray-400 flex items-center gap-1.5">
                        <Shield className="w-3.5 h-3.5 text-indigo-400" />
                        Ranked Root-Cause Explanations ({currentCase.candidate_explanations.length})
                      </span>
                    </div>

                    <div className="space-y-3">
                      {currentCase.candidate_explanations.map((cand, idx) => (
                        <div
                          key={cand.candidate_id}
                          className={`p-3 rounded-md border text-xs space-y-2 ${
                            idx === 0
                              ? 'bg-indigo-950/20 border-indigo-700/60'
                              : 'bg-gray-950/40 border-gray-800'
                          }`}
                        >
                          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1">
                            <div className="flex items-center gap-2">
                              <span className="font-mono text-gray-400">#{cand.rank}</span>
                              <span className="font-semibold text-white">{cand.title}</span>
                            </div>
                            <div className="flex items-center gap-2">
                              <span className="font-mono text-[10px] text-gray-400">Score: {(cand.score * 100).toFixed(0)}%</span>
                              {renderCandidateStatusBadge(cand.status)}
                            </div>
                          </div>

                          <p className="text-gray-300 text-[11px] leading-relaxed">{cand.rationale}</p>

                          {/* Evidence breakdown */}
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-[10px] pt-1">
                            <div>
                              <span className="text-emerald-400 font-semibold">Supporting Evidence:</span>
                              <ul className="list-disc list-inside text-gray-400 mt-0.5">
                                {cand.supporting_evidence_ids.length > 0 ? (
                                  cand.supporting_evidence_ids.map((id) => <li key={id} className="font-mono">{id}</li>)
                                ) : (
                                  <li className="italic text-gray-500">None</li>
                                )}
                              </ul>
                            </div>
                            <div>
                              <span className="text-amber-400 font-semibold">Missing Evidence / Uncertainty:</span>
                              <ul className="list-disc list-inside text-gray-400 mt-0.5">
                                {cand.missing_evidence.length > 0 ? (
                                  cand.missing_evidence.map((item, i) => <li key={i}>{item}</li>)
                                ) : (
                                  <li className="italic text-gray-500">None identified</li>
                                )}
                              </ul>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* EVIDENCE GRAPH VISUALIZER */}
              <div className="bg-surface border border-gray-800 rounded-lg p-5 space-y-4">
                <div className="flex items-center justify-between border-b border-gray-800 pb-3">
                  <div className="flex items-center gap-2">
                    <Layers className="w-4 h-4 text-indigo-400" />
                    <h4 className="text-xs font-bold uppercase tracking-wider text-gray-300">
                      Evidence Graph ({currentCase.evidence_graph.node_count} nodes, {currentCase.evidence_graph.edge_count} edges)
                    </h4>
                  </div>
                  <div className="flex items-center gap-1.5 text-[10px]">
                    <span className="text-gray-400 mr-1">Classes:</span>
                    {renderEvidenceClassBadge('OBSERVED')}
                    {renderEvidenceClassBadge('INFERRED')}
                    {renderEvidenceClassBadge('SIMULATED')}
                    {renderEvidenceClassBadge('PREDICTED')}
                  </div>
                </div>

                {currentCase.evidence_graph.nodes.length === 0 ? (
                  <div className="text-center py-6 text-gray-500 text-xs italic">
                    Evidence graph is empty. Execute the investigation to collect and correlate network evidence.
                  </div>
                ) : (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    {currentCase.evidence_graph.nodes.map((node) => (
                      <div
                        key={node.evidence_id}
                        className="p-3 rounded bg-gray-900 border border-gray-800 text-xs space-y-1.5 hover:border-gray-700 transition"
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-mono text-[10px] text-gray-400">{node.evidence_id}</span>
                          {renderEvidenceClassBadge(node.evidence_class)}
                        </div>
                        <div className="font-semibold text-gray-200">{node.label}</div>
                        <div className="text-[11px] text-gray-400 leading-snug">{node.description}</div>
                        <div className="pt-1 flex flex-wrap gap-2 text-[10px] font-mono text-gray-500 border-t border-gray-800/60 mt-1">
                          <span>Type: {node.node_type}</span>
                          <span>Source: {node.source_id}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* ISOLATED COUNTERFACTUAL REMEDIATION COMPARISONS */}
              {currentCase.counterfactual_comparisons.length > 0 && (
                <div className="bg-surface border border-gray-800 rounded-lg p-5 space-y-4">
                  <div className="flex items-center gap-2 border-b border-gray-800 pb-3">
                    <GitBranch className="w-4 h-4 text-purple-400" />
                    <h4 className="text-xs font-bold uppercase tracking-wider text-gray-300">
                      Isolated Counterfactual Scenarios & Remediation Validation ({currentCase.counterfactual_comparisons.length})
                    </h4>
                  </div>

                  <div className="space-y-3">
                    {currentCase.counterfactual_comparisons.map((cf) => (
                      <div
                        key={cf.scenario_id}
                        className="p-4 rounded-lg bg-gray-900 border border-purple-900/40 text-xs space-y-3"
                      >
                        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                          <span className="font-bold text-white text-sm">{cf.scenario_name}</span>
                          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-purple-950 text-purple-300 border border-purple-700">
                            {cf.action_type}
                          </span>
                        </div>

                        {/* Side by side comparison */}
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 bg-gray-950 p-3 rounded border border-gray-800">
                          <div>
                            <span className="text-[10px] uppercase font-bold text-gray-500">Baseline Observed Outcome</span>
                            <div className="mt-1 flex items-center gap-2">
                              <span className="font-semibold text-rose-400">{cf.baseline_status}</span>
                              <span className="font-mono text-[10px] text-gray-400">({cf.baseline_reason})</span>
                            </div>
                          </div>

                          <div>
                            <span className="text-[10px] uppercase font-bold text-gray-500">Counterfactual Outcome</span>
                            <div className="mt-1 flex items-center gap-2">
                              <span className="font-semibold text-emerald-400">{cf.counterfactual_status}</span>
                              <span className="font-mono text-[10px] text-gray-400">({cf.counterfactual_reason})</span>
                            </div>
                          </div>
                        </div>

                        <div className="flex items-center justify-between text-[11px] pt-1">
                          <span className="text-gray-300">Difference: <strong>{cf.outcome_difference}</strong></span>
                          {cf.is_counterfactual_verified && (
                            <span className="text-emerald-400 font-semibold flex items-center gap-1">
                              <CheckCircle2 className="w-3.5 h-3.5" /> Verified in Forwarding Simulator
                            </span>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* BOUNDED LIMITATIONS & REPRODUCTION STEPS */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {/* Limitations */}
                <div className="bg-surface border border-gray-800 rounded-lg p-5 space-y-3">
                  <div className="flex items-center gap-2 border-b border-gray-800 pb-2">
                    <AlertTriangle className="w-4 h-4 text-amber-400" />
                    <h4 className="text-xs font-bold uppercase tracking-wider text-gray-300">
                      Explicit Epistemological Limitations
                    </h4>
                  </div>
                  <ul className="space-y-1.5 text-xs text-gray-300">
                    {currentCase.known_limitations.map((lim, idx) => (
                      <li key={idx} className="flex items-start gap-2">
                        <span className="text-amber-500 font-mono text-[10px] mt-0.5">&bull;</span>
                        <span className="text-gray-400 text-[11px]">{lim}</span>
                      </li>
                    ))}
                  </ul>
                </div>

                {/* Reproduction steps */}
                <div className="bg-surface border border-gray-800 rounded-lg p-5 space-y-3">
                  <div className="flex items-center gap-2 border-b border-gray-800 pb-2">
                    <FileText className="w-4 h-4 text-cyan-400" />
                    <h4 className="text-xs font-bold uppercase tracking-wider text-gray-300">
                      Deterministic Reproduction Instructions
                    </h4>
                  </div>
                  <ol className="space-y-1.5 text-xs text-gray-300">
                    {currentCase.reproduction_steps.map((step, idx) => (
                      <li key={idx} className="flex items-start gap-2">
                        <span className="font-mono text-cyan-400 text-[10px] mt-0.5">{idx + 1}.</span>
                        <span className="text-gray-400 text-[11px] font-mono">{step}</span>
                      </li>
                    ))}
                  </ol>
                </div>
              </div>
            </>
          ) : (
            <div className="bg-surface border border-gray-800 rounded-lg p-12 text-center text-gray-400 space-y-3">
              <Search className="w-8 h-8 text-gray-600 mx-auto" />
              <div className="text-sm font-semibold text-gray-300">No Investigation Selected</div>
              <p className="text-xs text-gray-500 max-w-sm mx-auto">
                Select an investigation case from the left sidebar or create a new incident case to begin evidence analysis.
              </p>
            </div>
          )}
        </div>
      </div>

      {/* MODAL: CREATE INVESTIGATION CASE */}
      {showNewModal && (
        <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
          <form
            onSubmit={handleCreateCase}
            className="bg-surface border border-gray-700 rounded-lg shadow-xl max-w-lg w-full p-5 space-y-4"
          >
            <div>
              <h3 className="text-sm font-bold text-white">Create New Incident Investigation</h3>
              <p className="text-xs text-gray-400 mt-0.5">
                Define the incident scope and typed investigative workflow.
              </p>
            </div>

            <div className="space-y-3 text-xs">
              <div>
                <label className="block font-medium text-gray-300 mb-1">Case Title</label>
                <input
                  type="text"
                  required
                  placeholder="e.g., Outage: Core Gateway to WAN Dropping SSH"
                  value={newTitle}
                  onChange={(e) => setNewTitle(e.target.value)}
                  className="w-full bg-gray-900 border border-gray-700 rounded px-3 py-1.5 text-gray-100 text-xs focus:border-indigo-500 outline-none"
                />
              </div>

              <div>
                <label className="block font-medium text-gray-300 mb-1">Investigation Workflow Type</label>
                <select
                  value={newType}
                  onChange={(e) => setNewType(e.target.value as InvestigationType)}
                  className="w-full bg-gray-900 border border-gray-700 rounded px-3 py-1.5 text-gray-100 text-xs focus:border-indigo-500 outline-none"
                >
                  <option value="CONNECTIVITY_FAILURE">A. Connectivity Failure (LPM, Down Interface, ACL)</option>
                  <option value="UNEXPECTED_POLICY_DECISION">B. Unexpected Policy Decision (ACL Permit/Deny)</option>
                  <option value="DNS_RESOLUTION_FAILURE">C. DNS / Service-Resolution Failure</option>
                  <option value="UNEXPECTED_TRAFFIC_RELATIONSHIP">D. Unexpected Traffic Relationship</option>
                  <option value="CHANGE_RELATED_BEHAVIOR">E. Change-Related Differential Behavior</option>
                </select>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block font-medium text-gray-300 mb-1">Source IP</label>
                  <input
                    type="text"
                    placeholder="e.g., 192.168.10.50"
                    value={newSrcIp}
                    onChange={(e) => setNewSrcIp(e.target.value)}
                    className="w-full bg-gray-900 border border-gray-700 rounded px-3 py-1.5 text-gray-100 text-xs focus:border-indigo-500 outline-none"
                  />
                </div>

                <div>
                  <label className="block font-medium text-gray-300 mb-1">Destination IP</label>
                  <input
                    type="text"
                    placeholder="e.g., 10.200.0.99"
                    value={newDstIp}
                    onChange={(e) => setNewDstIp(e.target.value)}
                    className="w-full bg-gray-900 border border-gray-700 rounded px-3 py-1.5 text-gray-100 text-xs focus:border-indigo-500 outline-none"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block font-medium text-gray-300 mb-1">Transport Protocol</label>
                  <select
                    value={newProto}
                    onChange={(e) => setNewProto(e.target.value)}
                    className="w-full bg-gray-900 border border-gray-700 rounded px-3 py-1.5 text-gray-100 text-xs focus:border-indigo-500 outline-none"
                  >
                    <option value="TCP">TCP</option>
                    <option value="UDP">UDP</option>
                    <option value="ICMP">ICMP</option>
                  </select>
                </div>

                <div>
                  <label className="block font-medium text-gray-300 mb-1">Destination Port</label>
                  <input
                    type="number"
                    placeholder="80"
                    value={newDstPort}
                    onChange={(e) => setNewDstPort(e.target.value)}
                    className="w-full bg-gray-900 border border-gray-700 rounded px-3 py-1.5 text-gray-100 text-xs focus:border-indigo-500 outline-none"
                  />
                </div>
              </div>

              <div>
                <label className="block font-medium text-gray-300 mb-1">Hostname (for DNS workflows)</label>
                <input
                  type="text"
                  placeholder="e.g., auth.internal.corp"
                  value={newHostname}
                  onChange={(e) => setNewHostname(e.target.value)}
                  className="w-full bg-gray-900 border border-gray-700 rounded px-3 py-1.5 text-gray-100 text-xs focus:border-indigo-500 outline-none"
                />
              </div>

              <div>
                <label className="block font-medium text-gray-300 mb-1">Model ID (optional)</label>
                <input
                  type="text"
                  placeholder="Leave blank to use active digital twin model"
                  value={newModelId}
                  onChange={(e) => setNewModelId(e.target.value)}
                  className="w-full bg-gray-900 border border-gray-700 rounded px-3 py-1.5 text-gray-100 text-xs focus:border-indigo-500 outline-none font-mono"
                />
              </div>
            </div>

            <div className="flex justify-end gap-2 pt-2 border-t border-gray-800">
              <button
                type="button"
                onClick={() => setShowNewModal(false)}
                className="px-3 py-1.5 rounded bg-gray-800 hover:bg-gray-700 text-gray-300 text-xs"
              >
                Cancel
              </button>
              <button
                type="submit"
                className="px-3 py-1.5 rounded bg-indigo-600 hover:bg-indigo-500 text-white font-medium text-xs shadow"
              >
                Create Investigation
              </button>
            </div>
          </form>
        </div>
      )}

      {/* MODAL: RUN COUNTERFACTUAL REMEDIATION */}
      {showCfModal && (
        <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
          <form
            onSubmit={handleRunCounterfactual}
            className="bg-surface border border-gray-700 rounded-lg shadow-xl max-w-md w-full p-5 space-y-4"
          >
            <div>
              <h3 className="text-sm font-bold text-white">Isolated Counterfactual Simulation</h3>
              <p className="text-xs text-gray-400 mt-0.5">
                Simulate a hypothetical remediation in complete isolation from production digital twin state.
              </p>
            </div>

            <div className="space-y-3 text-xs">
              <div>
                <label className="block font-medium text-gray-300 mb-1">Scenario Name</label>
                <input
                  type="text"
                  required
                  value={cfScenarioName}
                  onChange={(e) => setCfScenarioName(e.target.value)}
                  className="w-full bg-gray-900 border border-gray-700 rounded px-3 py-1.5 text-gray-100 text-xs focus:border-purple-500 outline-none"
                />
              </div>

              <div>
                <label className="block font-medium text-gray-300 mb-1">Remedial Action Type</label>
                <select
                  value={cfActionType}
                  onChange={(e) => setCfActionType(e.target.value)}
                  className="w-full bg-gray-900 border border-gray-700 rounded px-3 py-1.5 text-gray-100 text-xs focus:border-purple-500 outline-none"
                >
                  <option value="SET_INTERFACE_STATE">SET_INTERFACE_STATE (Bring interface UP)</option>
                  <option value="ADD_FIREWALL_RULE">ADD_FIREWALL_RULE (Permit traffic)</option>
                  <option value="ADD_ROUTE">ADD_ROUTE (Add missing route)</option>
                </select>
              </div>

              <div>
                <label className="block font-medium text-gray-300 mb-1">Target Node ID</label>
                <input
                  type="text"
                  value={cfNodeId}
                  onChange={(e) => setCfNodeId(e.target.value)}
                  className="w-full bg-gray-900 border border-gray-700 rounded px-3 py-1.5 text-gray-100 text-xs focus:border-purple-500 outline-none font-mono"
                />
              </div>

              <div>
                <label className="block font-medium text-gray-300 mb-1">Interface ID</label>
                <input
                  type="text"
                  value={cfIfaceId}
                  onChange={(e) => setCfIfaceId(e.target.value)}
                  className="w-full bg-gray-900 border border-gray-700 rounded px-3 py-1.5 text-gray-100 text-xs focus:border-purple-500 outline-none font-mono"
                />
              </div>

              <div>
                <label className="block font-medium text-gray-300 mb-1">Target State</label>
                <select
                  value={cfState}
                  onChange={(e) => setCfState(e.target.value)}
                  className="w-full bg-gray-900 border border-gray-700 rounded px-3 py-1.5 text-gray-100 text-xs focus:border-purple-500 outline-none"
                >
                  <option value="UP">UP</option>
                  <option value="DOWN">DOWN</option>
                </select>
              </div>
            </div>

            <div className="flex justify-end gap-2 pt-2 border-t border-gray-800">
              <button
                type="button"
                onClick={() => setShowCfModal(false)}
                className="px-3 py-1.5 rounded bg-gray-800 hover:bg-gray-700 text-gray-300 text-xs"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={counterfactualLoading}
                className="px-3 py-1.5 rounded bg-purple-600 hover:bg-purple-500 text-white font-medium text-xs shadow flex items-center gap-1.5 disabled:opacity-50"
              >
                <Play className={`w-3.5 h-3.5 ${counterfactualLoading ? 'animate-spin' : ''}`} />
                <span>{counterfactualLoading ? 'Simulating...' : 'Run Counterfactual'}</span>
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
};
