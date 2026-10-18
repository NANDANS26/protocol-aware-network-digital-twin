import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { apiClient } from '../api/client';
import type {
  Asset,
  NetworkSegment,
  NetworkService,
  CommunicationRelationship,
  EvidenceRecord,
  TopologyGraph,
  TopologyNode,
  TopologyEdge,
  TopologySnapshot,
  SnapshotComparisonDiff,
  ConfigImportResult,
  CaptureMetadata,
  IdentityStatus,
  EvidenceClass,
} from '../types/intelligence';
import type {
  NetworkModel,
  ReachabilityQuery,
  ReachabilityResult,
  SecurityInvariant,
  VerificationResult,
  SimulationScenario,
  CounterfactualResult,
} from '../types/simulation';
import { ReachabilityWorkbench } from './twin/ReachabilityWorkbench';
import { SecurityVerificationView } from './twin/SecurityVerificationView';
import { CounterfactualScenarioView } from './twin/CounterfactualScenarioView';
import { ModelInspectorView } from './twin/ModelInspectorView';
import { SecurityTestingWorkbench } from './twin/SecurityTestingWorkbench';
import { PredictiveWorkbench } from './twin/PredictiveWorkbench';
import { BenchmarkWorkbench } from './twin/BenchmarkWorkbench';
import { AdversarialHardeningWorkbench } from './twin/AdversarialHardeningWorkbench';
import { RealCaptureWorkbench } from './twin/RealCaptureWorkbench';
import { InvestigationWorkbench } from './twin/InvestigationWorkbench';
import { TopologyGraphView } from './twin/topology/TopologyGraphView';
import { TopologyModal } from './twin/topology/TopologyModal';
import {
  Server,
  Network,
  ShieldAlert,
  Layers,
  History,
  FileCode,
  FileCheck2,
  Search,
  RefreshCw,
  Plus,
  GitCompare,
  CheckCircle,
  CheckCircle2,
  AlertTriangle,
  ArrowRight,
  Database,
  Info,
  ShieldCheck,
  Cpu,
  Route,
  Activity,
  Bug,
  TrendingUp,
  Maximize2,
} from 'lucide-react';

export type TwinTab =
  | 'assets'
  | 'topology'
  | 'reachability'
  | 'verification'
  | 'counterfactual'
  | 'models'
  | 'fuzzing'
  | 'predictive'
  | 'benchmarks'
  | 'hardening'
  | 'captures'
  | 'investigations'
  | 'evidence'
  | 'comparison'
  | 'imports';

export const NetworkTwinView: React.FC = () => {
  const [activeTab, setActiveTab] = useState<TwinTab>('assets');
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Data states
  const [assets, setAssets] = useState<Asset[]>([]);
  const [segments, setSegments] = useState<NetworkSegment[]>([]);
  const [services, setServices] = useState<NetworkService[]>([]);
  const [relationships, setRelationships] = useState<CommunicationRelationship[]>([]);
  const [evidenceList, setEvidenceList] = useState<EvidenceRecord[]>([]);
  const [topology, setTopology] = useState<TopologyGraph | null>(null);
  const [snapshots, setSnapshots] = useState<TopologySnapshot[]>([]);
  const [captures, setCaptures] = useState<CaptureMetadata[]>([]);
  const [importHistory, setImportHistory] = useState<ConfigImportResult[]>([]);

  // Simulation and Verification states
  const [models, setModels] = useState<NetworkModel[]>([]);
  const [selectedModelId, setSelectedModelId] = useState<string>('');
  const [invariants, setInvariants] = useState<SecurityInvariant[]>([]);
  const [verificationResults, setVerificationResults] = useState<VerificationResult[]>([]);
  const [scenarios, setScenarios] = useState<SimulationScenario[]>([]);
  const [selectedScenarioId, setSelectedScenarioId] = useState<string>('');
  const [counterfactualResult, setCounterfactualResult] = useState<CounterfactualResult | null>(null);
  const [actionLoading, setActionLoading] = useState<boolean>(false);

  // Selection & filter states
  const [selectedAsset, setSelectedAsset] = useState<Asset | null>(null);
  const [selectedNode, setSelectedNode] = useState<TopologyNode | null>(null);
  const [selectedEdge, setSelectedEdge] = useState<TopologyEdge | null>(null);
  const [selectedEvidence, setSelectedEvidence] = useState<EvidenceRecord | null>(null);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [evidenceTypeFilter, setEvidenceTypeFilter] = useState<string>('ALL');
  const [evidenceClassFilter, setEvidenceClassFilter] = useState<string>('ALL');

  // Snapshot comparison state
  const [baseSnapshotId, setBaseSnapshotId] = useState<string>('');
  const [targetSnapshotId, setTargetSnapshotId] = useState<string>('');
  const [comparisonDiff, setComparisonDiff] = useState<SnapshotComparisonDiff | null>(null);
  const [comparing, setComparing] = useState<boolean>(false);

  // Full-screen interactive topology modal state
  const [isTopologyModalOpen, setIsTopologyModalOpen] = useState<boolean>(false);

  // Snapshot creation modal
  const [showSnapshotModal, setShowSnapshotModal] = useState<boolean>(false);
  const [newSnapshotName, setNewSnapshotName] = useState<string>('');

  // Configuration import state
  const [importSourceName, setImportSourceName] = useState<string>('core-router-routes');
  const [importFormat, setImportFormat] = useState<'json' | 'csv'>('json');
  const [importContent, setImportContent] = useState<string>(
    JSON.stringify(
      [
        {
          destination: '10.0.1.0/24',
          gateway: '10.0.0.1',
          interface: 'eth0',
          metric: 10,
        },
        {
          destination: '192.168.1.0/24',
          gateway: '192.168.1.1',
          interface: 'eth1',
          metric: 20,
        },
      ],
      null,
      2
    )
  );
  const [importing, setImporting] = useState<boolean>(false);
  const [importSuccessMessage, setImportSuccessMessage] = useState<string | null>(null);

  // Fetch all primary model and simulation data
  const loadTwinData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [
        assetsData,
        segmentsData,
        servicesData,
        relData,
        evData,
        topoData,
        snapData,
        capData,
        impData,
        modelsData,
        invariantsData,
        scenariosData,
      ] = await Promise.all([
        apiClient.listAssets(),
        apiClient.listSegments(),
        apiClient.listServices(),
        apiClient.listRelationships({ limit: 200 }),
        apiClient.listEvidence({ limit: 200 }),
        apiClient.getTopology(),
        apiClient.listSnapshots(),
        apiClient.listCaptures(),
        apiClient.listImports(),
        apiClient.listModels ? apiClient.listModels().catch(() => []) : Promise.resolve([]),
        apiClient.listInvariants ? apiClient.listInvariants().catch(() => []) : Promise.resolve([]),
        apiClient.listScenarios ? apiClient.listScenarios().catch(() => []) : Promise.resolve([]),
      ]);

      setAssets(assetsData);
      setSegments(segmentsData);
      setServices(servicesData);
      setRelationships(relData);
      setEvidenceList(evData);
      setTopology(topoData);
      setSnapshots(snapData);
      setCaptures(capData);
      setImportHistory(impData);

      setModels(modelsData);
      if (modelsData.length > 0 && !selectedModelId && modelsData[0]) {
        setSelectedModelId(modelsData[0].model_id);
      }

      setInvariants(invariantsData);
      setScenarios(scenariosData);
      if (scenariosData.length > 0 && !selectedScenarioId && scenariosData[0]) {
        setSelectedScenarioId(scenariosData[0].scenario_id);
      }

      if (snapData.length >= 2 && !baseSnapshotId && !targetSnapshotId) {
        setBaseSnapshotId(snapData[0]?.snapshot_id || '');
        setTargetSnapshotId(snapData[1]?.snapshot_id || '');
      } else if (snapData.length === 1 && !baseSnapshotId) {
        setBaseSnapshotId(snapData[0]?.snapshot_id || '');
      }
    } catch (err: unknown) {
      setError((err as Error).message || 'Failed to load network twin data.');
    } finally {
      setLoading(false);
    }
  }, [baseSnapshotId, targetSnapshotId, selectedModelId, selectedScenarioId]);

  // Action Handlers
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

  const handleCreateScenario = async (scen: SimulationScenario): Promise<void> => {
    setActionLoading(true);
    try {
      const saved = await apiClient.createScenario(scen);
      setScenarios((prev) => [saved, ...prev]);
      setSelectedScenarioId(saved.scenario_id);
    } catch (err: unknown) {
      setError((err as Error).message || 'Failed to create scenario');
    } finally {
      setActionLoading(false);
    }
  };

  const handleBuildModel = async (snapshotId: string, name?: string): Promise<void> => {
    setActionLoading(true);
    try {
      const model = await apiClient.buildNetworkModel({ snapshot_id: snapshotId, name });
      setModels((prev) => [model, ...prev]);
      setSelectedModelId(model.model_id);
    } catch (err: unknown) {
      setError((err as Error).message || 'Failed to build network model');
    } finally {
      setActionLoading(false);
    }
  };

  useEffect(() => {
    loadTwinData();
  }, [loadTwinData]);

  // Handle Snapshot Creation
  const handleCreateSnapshot = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newSnapshotName.trim()) return;
    try {
      await apiClient.createSnapshot({ name: newSnapshotName.trim() });
      setShowSnapshotModal(false);
      setNewSnapshotName('');
      await loadTwinData();
    } catch (err: unknown) {
      setError((err as Error).message || 'Failed to create snapshot.');
    }
  };

  // Handle Snapshot Comparison
  const handleCompareSnapshots = async () => {
    if (!baseSnapshotId || !targetSnapshotId) return;
    setComparing(true);
    setError(null);
    try {
      const diff = await apiClient.compareSnapshots(baseSnapshotId, targetSnapshotId);
      setComparisonDiff(diff);
    } catch (err: unknown) {
      setError((err as Error).message || 'Failed to compare snapshots.');
    } finally {
      setComparing(false);
    }
  };

  // Handle Config Import
  const handleImportConfig = async (e: React.FormEvent) => {
    e.preventDefault();
    setImporting(true);
    setError(null);
    setImportSuccessMessage(null);
    try {
      const res = await apiClient.importConfiguration({
        source_name: importSourceName,
        format: importFormat,
        content: importContent,
      });
      setImportSuccessMessage(
        `Imported ${res.items_imported} items successfully from '${res.source_name}' (${res.source_type}).`
      );
      await loadTwinData();
    } catch (err: unknown) {
      setError((err as Error).message || 'Failed to import configuration.');
    } finally {
      setImporting(false);
    }
  };

  // Filtered Assets
  const filteredAssets = useMemo(() => {
    return assets.filter((asset) => {
      const matchesSearch =
        searchQuery === '' ||
        asset.asset_id.toLowerCase().includes(searchQuery.toLowerCase()) ||
        asset.ip_addresses.some((ip) => ip.includes(searchQuery)) ||
        asset.mac_addresses.some((mac) => mac.toLowerCase().includes(searchQuery.toLowerCase())) ||
        asset.hostnames.some((h) => h.toLowerCase().includes(searchQuery.toLowerCase()));

      const matchesStatus = statusFilter === 'ALL' || asset.identity_status === statusFilter;
      return matchesSearch && matchesStatus;
    });
  }, [assets, searchQuery, statusFilter]);

  // Filtered Evidence
  const filteredEvidence = useMemo(() => {
    return evidenceList.filter((ev) => {
      const matchesType = evidenceTypeFilter === 'ALL' || ev.source_type === evidenceTypeFilter;
      const matchesSearch =
        searchQuery === '' ||
        ev.evidence_id.toLowerCase().includes(searchQuery.toLowerCase()) ||
        ev.source_artifact_id.toLowerCase().includes(searchQuery.toLowerCase()) ||
        (ev.flow_key && ev.flow_key.toLowerCase().includes(searchQuery.toLowerCase()));
      return matchesType && matchesSearch;
    });
  }, [evidenceList, evidenceTypeFilter, searchQuery]);

  // Helper badge renderers
  const renderIdentityBadge = (status: IdentityStatus) => {
    switch (status) {
      case 'CONFIRMED':
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-emerald-950/70 text-emerald-400 border border-emerald-800/60">
            <CheckCircle className="w-3 h-3 mr-1" /> Confirmed
          </span>
        );
      case 'PROBABLE':
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-cyan-950/70 text-cyan-400 border border-cyan-800/60">
            Probable
          </span>
        );
      case 'AMBIGUOUS':
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-amber-950/70 text-amber-400 border border-amber-800/60">
            Ambiguous
          </span>
        );
      case 'CONFLICTING':
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-rose-950/70 text-rose-400 border border-rose-800/60">
            <AlertTriangle className="w-3 h-3 mr-1" /> Conflicting
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-gray-800 text-gray-400 border border-gray-700">
            Unresolved
          </span>
        );
    }
  };

  const renderEvidenceClassBadge = (evClass?: EvidenceClass | string) => {
    switch (evClass) {
      case 'DIRECTLY_OBSERVED':
      case 'DIRECT_OBSERVATION':
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium bg-emerald-950/60 text-emerald-300 border border-emerald-800/50">
            Directly Observed
          </span>
        );
      case 'CONFIGURED':
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium bg-blue-950/60 text-blue-300 border border-blue-800/50">
            Configured
          </span>
        );
      case 'INFERRED':
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium bg-purple-950/60 text-purple-300 border border-purple-800/50">
            Inferred
          </span>
        );
      case 'PREDICTED':
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium bg-cyan-950/60 text-cyan-300 border border-cyan-800/50">
            Predicted
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium bg-gray-800 text-gray-400 border border-gray-700">
            {evClass || 'Unknown'}
          </span>
        );
    }
  };

  return (
    <div className="space-y-6">
      {/* Header bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-gray-800 pb-5">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2 bg-indigo-950/80 rounded-lg border border-indigo-700/50 text-indigo-400">
              <Network className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
                Network Digital Twin
                <span className="text-xs px-2 py-0.5 rounded bg-emerald-950/80 text-emerald-400 border border-emerald-800/60 font-mono font-medium">
                  Twin Operational
                </span>
              </h1>
              <p className="text-xs text-gray-400 mt-0.5">
                Executable network digital twin, deterministic security verification, predictive models & reproducible benchmarks
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowSnapshotModal(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-medium shadow-sm transition"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Create Snapshot</span>
          </button>
          <button
            onClick={loadTwinData}
            disabled={loading}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-gray-800 hover:bg-gray-700 text-gray-200 text-xs font-medium border border-gray-700 transition disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Metrics Strip */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        <div className="bg-surface/50 border border-gray-800/80 p-3 rounded-lg">
          <div className="text-[11px] font-medium text-gray-400 uppercase tracking-wider">Assets</div>
          <div className="text-xl font-bold font-mono text-white mt-1">{assets.length}</div>
          <div className="text-[10px] text-emerald-400 mt-0.5">Identity resolved</div>
        </div>
        <div className="bg-surface/50 border border-gray-800/80 p-3 rounded-lg">
          <div className="text-[11px] font-medium text-gray-400 uppercase tracking-wider">Subnets</div>
          <div className="text-xl font-bold font-mono text-cyan-400 mt-1">{segments.length}</div>
          <div className="text-[10px] text-gray-400 mt-0.5">Inferred & configured</div>
        </div>
        <div className="bg-surface/50 border border-gray-800/80 p-3 rounded-lg">
          <div className="text-[11px] font-medium text-gray-400 uppercase tracking-wider">Services</div>
          <div className="text-xl font-bold font-mono text-amber-400 mt-1">{services.length}</div>
          <div className="text-[10px] text-gray-400 mt-0.5">Discovered ports</div>
        </div>
        <div className="bg-surface/50 border border-gray-800/80 p-3 rounded-lg">
          <div className="text-[11px] font-medium text-gray-400 uppercase tracking-wider">Relationships</div>
          <div className="text-xl font-bold font-mono text-purple-400 mt-1">{relationships.length}</div>
          <div className="text-[10px] text-gray-400 mt-0.5">Observed flows</div>
        </div>
        <div className="bg-surface/50 border border-gray-800/80 p-3 rounded-lg">
          <div className="text-[11px] font-medium text-gray-400 uppercase tracking-wider">Evidence Ledger</div>
          <div className="text-xl font-bold font-mono text-indigo-400 mt-1">{evidenceList.length}</div>
          <div className="text-[10px] text-indigo-300 mt-0.5">Auditable records</div>
        </div>
        <div className="bg-surface/50 border border-gray-800/80 p-3 rounded-lg">
          <div className="text-[11px] font-medium text-gray-400 uppercase tracking-wider">Snapshots</div>
          <div className="text-xl font-bold font-mono text-blue-400 mt-1">{snapshots.length}</div>
          <div className="text-[10px] text-blue-300 mt-0.5">Versioned states</div>
        </div>
      </div>

      {/* Error alert */}
      {error && (
        <div className="p-3 bg-rose-950/40 border border-rose-800/60 rounded-lg text-rose-300 text-xs flex items-center justify-between">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 shrink-0 text-rose-400" />
            <span>{error}</span>
          </div>
          <button onClick={() => setError(null)} className="text-rose-400 hover:text-rose-200">
            Dismiss
          </button>
        </div>
      )}

      {/* Navigation Sub-Tabs */}
      <div className="flex border-b border-gray-800 space-x-1">
        <button
          onClick={() => setActiveTab('assets')}
          className={`flex items-center gap-2 px-4 py-2 text-xs font-semibold border-b-2 transition ${
            activeTab === 'assets'
              ? 'border-indigo-500 text-white bg-indigo-950/20'
              : 'border-transparent text-gray-400 hover:text-gray-200 hover:border-gray-700'
          }`}
        >
          <Server className="w-3.5 h-3.5" />
          <span>Asset Explorer</span>
          <span className="text-[10px] px-1.5 py-0.2 rounded-full bg-gray-800 text-gray-300">
            {assets.length}
          </span>
        </button>

        <button
          onClick={() => setActiveTab('topology')}
          className={`flex items-center gap-2 px-4 py-2 text-xs font-semibold border-b-2 transition ${
            activeTab === 'topology'
              ? 'border-indigo-500 text-white bg-indigo-950/20'
              : 'border-transparent text-gray-400 hover:text-gray-200 hover:border-gray-700'
          }`}
        >
          <Layers className="w-3.5 h-3.5" />
          <span>Topology Graph</span>
          {topology && (
            <span className="text-[10px] px-1.5 py-0.2 rounded-full bg-gray-800 text-gray-300">
              {topology.node_count} nodes
            </span>
          )}
        </button>

        <button
          onClick={() => setActiveTab('evidence')}
          className={`flex items-center gap-2 px-4 py-2 text-xs font-semibold border-b-2 transition ${
            activeTab === 'evidence'
              ? 'border-indigo-500 text-white bg-indigo-950/20'
              : 'border-transparent text-gray-400 hover:text-gray-200 hover:border-gray-700'
          }`}
        >
          <ShieldAlert className="w-3.5 h-3.5" />
          <span>Evidence Inspector</span>
          <span className="text-[10px] px-1.5 py-0.2 rounded-full bg-gray-800 text-gray-300">
            {evidenceList.length}
          </span>
        </button>

        <button
          onClick={() => setActiveTab('comparison')}
          className={`flex items-center gap-2 px-4 py-2 text-xs font-semibold border-b-2 transition ${
            activeTab === 'comparison'
              ? 'border-indigo-500 text-white bg-indigo-950/20'
              : 'border-transparent text-gray-400 hover:text-gray-200 hover:border-gray-700'
          }`}
        >
          <GitCompare className="w-3.5 h-3.5" />
          <span>Snapshot Comparison</span>
        </button>

        <button
          onClick={() => setActiveTab('reachability')}
          className={`flex items-center gap-2 px-4 py-2 text-xs font-semibold border-b-2 transition ${
            activeTab === 'reachability'
              ? 'border-indigo-500 text-white bg-indigo-950/20'
              : 'border-transparent text-gray-400 hover:text-gray-200 hover:border-gray-700'
          }`}
        >
          <Route className="w-3.5 h-3.5 text-cyan-400" />
          <span>Reachability</span>
        </button>

        <button
          onClick={() => setActiveTab('verification')}
          className={`flex items-center gap-2 px-4 py-2 text-xs font-semibold border-b-2 transition ${
            activeTab === 'verification'
              ? 'border-indigo-500 text-white bg-indigo-950/20'
              : 'border-transparent text-gray-400 hover:text-gray-200 hover:border-gray-700'
          }`}
        >
          <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
          <span>Security Invariants</span>
          <span className="text-[10px] px-1.5 py-0.2 rounded-full bg-gray-800 text-gray-300">
            {invariants.length}
          </span>
        </button>

        <button
          onClick={() => setActiveTab('counterfactual')}
          className={`flex items-center gap-2 px-4 py-2 text-xs font-semibold border-b-2 transition ${
            activeTab === 'counterfactual'
              ? 'border-indigo-500 text-white bg-indigo-950/20'
              : 'border-transparent text-gray-400 hover:text-gray-200 hover:border-gray-700'
          }`}
        >
          <Activity className="w-3.5 h-3.5 text-purple-400" />
          <span>What-If Scenarios</span>
          <span className="text-[10px] px-1.5 py-0.2 rounded-full bg-gray-800 text-gray-300">
            {scenarios.length}
          </span>
        </button>

        <button
          onClick={() => setActiveTab('models')}
          className={`flex items-center gap-2 px-4 py-2 text-xs font-semibold border-b-2 transition ${
            activeTab === 'models'
              ? 'border-indigo-500 text-white bg-indigo-950/20'
              : 'border-transparent text-gray-400 hover:text-gray-200 hover:border-gray-700'
          }`}
        >
          <Cpu className="w-3.5 h-3.5 text-amber-400" />
          <span>Model Inspector</span>
          <span className="text-[10px] px-1.5 py-0.2 rounded-full bg-gray-800 text-gray-300">
            {models.length}
          </span>
        </button>

        <button
          onClick={() => setActiveTab('fuzzing')}
          className={`flex items-center gap-2 px-4 py-2 text-xs font-semibold border-b-2 transition ${
            activeTab === 'fuzzing'
              ? 'border-indigo-500 text-white bg-indigo-950/20'
              : 'border-transparent text-gray-400 hover:text-gray-200 hover:border-gray-700'
          }`}
        >
          <Bug className="w-3.5 h-3.5 text-rose-400" />
          <span>Security Testing & Fuzzing</span>
        </button>

        <button
          onClick={() => setActiveTab('predictive')}
          className={`flex items-center gap-2 px-4 py-2 text-xs font-semibold border-b-2 transition ${
            activeTab === 'predictive'
              ? 'border-indigo-500 text-white bg-indigo-950/20'
              : 'border-transparent text-gray-400 hover:text-gray-200 hover:border-gray-700'
          }`}
        >
          <TrendingUp className="w-3.5 h-3.5 text-blue-400" />
          <span>Predictive World Model</span>
        </button>

        <button
          onClick={() => setActiveTab('benchmarks')}
          className={`flex items-center gap-2 px-4 py-2 text-xs font-semibold border-b-2 transition ${
            activeTab === 'benchmarks'
              ? 'border-indigo-500 text-white bg-indigo-950/20'
              : 'border-transparent text-gray-400 hover:text-gray-200 hover:border-gray-700'
          }`}
        >
          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
          <span>Validation & Benchmarks</span>
        </button>

        <button
          onClick={() => setActiveTab('hardening')}
          className={`flex items-center gap-2 px-4 py-2 text-xs font-semibold border-b-2 transition ${
            activeTab === 'hardening'
              ? 'border-indigo-500 text-white bg-indigo-950/20'
              : 'border-transparent text-gray-400 hover:text-gray-200 hover:border-gray-700'
          }`}
        >
          <ShieldAlert className="w-3.5 h-3.5 text-amber-400" />
          <span>Adversarial Hardening</span>
        </button>

        <button
          onClick={() => setActiveTab('captures')}
          className={`flex items-center gap-2 px-4 py-2 text-xs font-semibold border-b-2 transition ${
            activeTab === 'captures'
              ? 'border-indigo-500 text-white bg-indigo-950/20'
              : 'border-transparent text-gray-400 hover:text-gray-200 hover:border-gray-700'
          }`}
        >
          <FileCheck2 className="w-3.5 h-3.5 text-cyan-400" />
          <span>Real Captures & Differential</span>
        </button>

        <button
          onClick={() => setActiveTab('investigations')}
          className={`flex items-center gap-2 px-4 py-2 text-xs font-semibold border-b-2 transition ${
            activeTab === 'investigations'
              ? 'border-indigo-500 text-white bg-indigo-950/20'
              : 'border-transparent text-gray-400 hover:text-gray-200 hover:border-gray-700'
          }`}
        >
          <Search className="w-3.5 h-3.5 text-indigo-400" />
          <span>Incident Investigations</span>
        </button>

        <button
          onClick={() => setActiveTab('imports')}
          className={`flex items-center gap-2 px-4 py-2 text-xs font-semibold border-b-2 transition ${
            activeTab === 'imports'
              ? 'border-indigo-500 text-white bg-indigo-950/20'
              : 'border-transparent text-gray-400 hover:text-gray-200 hover:border-gray-700'
          }`}
        >
          <FileCode className="w-3.5 h-3.5" />
          <span>Import & Ingestion</span>
        </button>
      </div>

      {/* TAB CONTENT: ASSET EXPLORER */}
      {activeTab === 'assets' && (
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="relative flex-1 max-w-md">
              <Search className="absolute left-3 top-2.5 w-4 h-4 text-gray-500" />
              <input
                type="text"
                placeholder="Search IP, MAC, hostname or asset ID..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full bg-surface/80 border border-gray-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-gray-200 placeholder-gray-500 focus:outline-none focus:border-indigo-500 transition"
              />
            </div>

            <div className="flex items-center gap-2">
              <span className="text-xs text-gray-400">Identity:</span>
              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                className="bg-surface/80 border border-gray-800 rounded-lg px-2.5 py-1.5 text-xs text-gray-300 focus:outline-none focus:border-indigo-500"
              >
                <option value="ALL">All Statuses</option>
                <option value="CONFIRMED">Confirmed</option>
                <option value="PROBABLE">Probable</option>
                <option value="AMBIGUOUS">Ambiguous</option>
                <option value="CONFLICTING">Conflicting</option>
                <option value="UNRESOLVED">Unresolved</option>
              </select>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Asset Table */}
            <div className="lg:col-span-2 bg-surface/40 border border-gray-800/80 rounded-lg overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="bg-surface/90 border-b border-gray-800 text-gray-400 font-medium">
                    <tr>
                      <th className="py-2.5 px-3">IP Addresses</th>
                      <th className="py-2.5 px-3">MAC Addresses</th>
                      <th className="py-2.5 px-3">Identity Status</th>
                      <th className="py-2.5 px-3">Confidence</th>
                      <th className="py-2.5 px-3 text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-800/60">
                    {filteredAssets.length === 0 ? (
                      <tr>
                        <td colSpan={5} className="py-8 text-center text-gray-500">
                          {loading ? 'Loading assets...' : 'No network assets match the current filter criteria.'}
                        </td>
                      </tr>
                    ) : (
                      filteredAssets.map((asset) => (
                        <tr
                          key={asset.asset_id}
                          onClick={() => setSelectedAsset(asset)}
                          className={`hover:bg-indigo-950/20 cursor-pointer transition ${
                            selectedAsset?.asset_id === asset.asset_id ? 'bg-indigo-950/30' : ''
                          }`}
                        >
                          <td className="py-2.5 px-3 font-mono">
                            {asset.ip_addresses.length > 0 ? (
                              <div className="flex flex-wrap gap-1">
                                {asset.ip_addresses.map((ip) => (
                                  <span
                                    key={ip}
                                    className="px-1.5 py-0.5 rounded bg-gray-800/80 text-gray-200 text-[11px]"
                                  >
                                    {ip}
                                  </span>
                                ))}
                              </div>
                            ) : (
                              <span className="text-gray-500 italic">None</span>
                            )}
                            {asset.hostnames.length > 0 && (
                              <div className="text-[10px] text-indigo-400 mt-0.5">
                                {asset.hostnames.join(', ')}
                              </div>
                            )}
                          </td>
                          <td className="py-2.5 px-3 font-mono text-gray-400">
                            {asset.mac_addresses.length > 0 ? (
                              asset.mac_addresses.join(', ')
                            ) : (
                              <span className="text-gray-600">Unresolved</span>
                            )}
                          </td>
                          <td className="py-2.5 px-3">{renderIdentityBadge(asset.identity_status)}</td>
                          <td className="py-2.5 px-3 font-mono">
                            <div className="flex items-center gap-2">
                              <span>{(asset.confidence * 100).toFixed(0)}%</span>
                              <div className="w-12 bg-gray-800 rounded-full h-1.5 overflow-hidden">
                                <div
                                  className={`h-full ${
                                    asset.confidence >= 0.8
                                      ? 'bg-emerald-500'
                                      : asset.confidence >= 0.5
                                      ? 'bg-cyan-500'
                                      : 'bg-amber-500'
                                  }`}
                                  style={{ width: `${asset.confidence * 100}%` }}
                                />
                              </div>
                            </div>
                          </td>
                          <td className="py-2.5 px-3 text-right">
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                setSelectedAsset(asset);
                              }}
                              className="text-xs text-indigo-400 hover:text-indigo-300 font-medium"
                            >
                              Inspect
                            </button>
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Asset Detail Drawer */}
            <div className="bg-surface/50 border border-gray-800/80 rounded-lg p-4 space-y-4">
              {selectedAsset ? (
                <div>
                  <div className="flex items-start justify-between border-b border-gray-800 pb-3">
                    <div>
                      <div className="text-[10px] uppercase font-mono text-gray-400 tracking-wider">
                        Asset Inspector
                      </div>
                      <h3 className="text-sm font-bold text-white font-mono mt-0.5 break-all">
                        {selectedAsset.asset_id}
                      </h3>
                    </div>
                    {renderIdentityBadge(selectedAsset.identity_status)}
                  </div>

                  <div className="mt-4 space-y-3 text-xs">
                    <div>
                      <span className="text-gray-400 font-medium">Device Class:</span>{' '}
                      <span className="text-gray-200 font-mono capitalize">{selectedAsset.device_class}</span>
                    </div>

                    <div>
                      <span className="text-gray-400 font-medium">Confidence Score:</span>{' '}
                      <span className="text-emerald-400 font-mono font-bold">
                        {(selectedAsset.confidence * 100).toFixed(1)}%
                      </span>
                    </div>

                    {(selectedAsset.conflict_reasons || selectedAsset.conflicts || []).length > 0 && (
                      <div className="p-2.5 bg-rose-950/30 border border-rose-900/50 rounded text-rose-300">
                        <div className="font-semibold flex items-center gap-1 text-[11px]">
                          <AlertTriangle className="w-3.5 h-3.5" /> Conflict Reasons:
                        </div>
                        <ul className="list-disc list-inside mt-1 text-[11px] space-y-0.5">
                          {(selectedAsset.conflict_reasons || selectedAsset.conflicts || []).map((r, i) => (
                            <li key={i}>{r}</li>
                          ))}
                        </ul>
                      </div>
                    )}

                    <div>
                      <div className="text-gray-400 font-medium mb-1">Observed Services:</div>
                      {services.filter((s) => s.asset_id === selectedAsset.asset_id).length === 0 ? (
                        <div className="text-gray-500 italic text-[11px]">No services hosted on this asset.</div>
                      ) : (
                        <div className="space-y-1">
                          {services
                            .filter((s) => s.asset_id === selectedAsset.asset_id)
                            .map((srv) => (
                              <div
                                key={srv.service_id}
                                className="p-1.5 bg-gray-900/70 border border-gray-800 rounded font-mono text-[11px] flex justify-between"
                              >
                                <span className="text-amber-400">
                                  {srv.application_protocol} ({srv.port}/{srv.transport_protocol})
                                </span>
                                {srv.banner_or_alpn && (
                                  <span className="text-gray-400 text-[10px] truncate max-w-[120px]">
                                    {srv.banner_or_alpn}
                                  </span>
                                )}
                              </div>
                            ))}
                        </div>
                      )}
                    </div>

                    <div>
                      <div className="text-gray-400 font-medium mb-1">Communication Peers:</div>
                      {relationships.filter(
                        (r) =>
                          r.source_asset_id === selectedAsset.asset_id ||
                          r.destination_asset_id === selectedAsset.asset_id
                      ).length === 0 ? (
                        <div className="text-gray-500 italic text-[11px]">No observed flows for this asset.</div>
                      ) : (
                        <div className="space-y-1 max-h-48 overflow-y-auto">
                          {relationships
                            .filter(
                              (r) =>
                                r.source_asset_id === selectedAsset.asset_id ||
                                r.destination_asset_id === selectedAsset.asset_id
                            )
                            .slice(0, 10)
                            .map((rel) => {
                              const isSource = rel.source_asset_id === selectedAsset.asset_id;
                              const peerIp = isSource ? rel.destination_ip : rel.source_ip;
                              return (
                                <div
                                  key={rel.relationship_id}
                                  className="p-1.5 bg-gray-900/60 border border-gray-800 rounded font-mono text-[11px] flex items-center justify-between"
                                >
                                  <div className="flex items-center gap-1.5">
                                    <span className="text-gray-400">{isSource ? '->' : '<-'}</span>
                                    <span className="text-gray-200">{peerIp}</span>
                                    <span className="text-gray-500 text-[10px]">({rel.transport_protocol})</span>
                                  </div>
                                  <span className="text-gray-400 text-[10px]">{rel.packet_count} pkts</span>
                                </div>
                              );
                            })}
                        </div>
                      )}
                    </div>

                    {(selectedAsset.evidence_ids || []).length > 0 && (
                      <div>
                        <div className="text-gray-400 font-medium mb-1">
                          Supporting Evidence ({(selectedAsset.evidence_ids || []).length}):
                        </div>
                        <div className="flex flex-wrap gap-1">
                          {(selectedAsset.evidence_ids || []).slice(0, 6).map((evId: string) => (
                            <button
                              key={evId}
                              onClick={() => {
                                const ev = evidenceList.find((e) => e.evidence_id === evId);
                                if (ev) {
                                  setSelectedEvidence(ev);
                                  setActiveTab('evidence');
                                }
                              }}
                              className="px-1.5 py-0.5 rounded bg-indigo-950/60 text-indigo-300 border border-indigo-800/40 text-[10px] font-mono hover:bg-indigo-900/60"
                            >
                              {evId.slice(0, 8)}...
                            </button>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              ) : (
                <div className="py-12 text-center text-gray-500 text-xs">
                  <Info className="w-8 h-8 mx-auto text-gray-600 mb-2" />
                  Select an asset from the table to inspect identity resolution, services, relationships, and evidence links.
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* TAB CONTENT: TOPOLOGY GRAPH */}
      {activeTab === 'topology' && (
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-3.5 rounded-xl bg-gradient-to-r from-indigo-950/40 via-surface/60 to-purple-950/30 border border-indigo-900/40">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-lg bg-indigo-600/20 border border-indigo-500/30 flex items-center justify-center text-indigo-400">
                <Layers className="w-5 h-5" />
              </div>
              <div>
                <h3 className="text-sm font-semibold text-white">Full-Screen Interactive Topology Workspace</h3>
                <p className="text-xs text-gray-400">
                  Expand the topology model into an immersive modal workspace with dedicated zoom, pan, search, collision-free cluster layout, and collapsible node inspection.
                </p>
              </div>
            </div>
            <button
              type="button"
              onClick={() => setIsTopologyModalOpen(true)}
              className="flex items-center gap-2 px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold shadow-md shadow-indigo-900/30 transition shrink-0"
            >
              <Maximize2 className="w-4 h-4" />
              <span>Open Interactive Topology</span>
            </button>
          </div>

          <TopologyGraphView
            topology={topology}
            selectedNode={selectedNode}
            selectedEdge={selectedEdge}
            onSelectNode={setSelectedNode}
            onSelectEdge={setSelectedEdge}
            evidenceClassFilter={evidenceClassFilter}
            onChangeEvidenceFilter={setEvidenceClassFilter}
            renderEvidenceClassBadge={renderEvidenceClassBadge}
            onOpenModal={() => setIsTopologyModalOpen(true)}
          />
        </div>
      )}

      {/* TAB CONTENT: EVIDENCE INSPECTOR */}
      {activeTab === 'evidence' && (
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="relative flex-1 max-w-md">
              <Search className="absolute left-3 top-2.5 w-4 h-4 text-gray-500" />
              <input
                type="text"
                placeholder="Search evidence ID, artifact ID or flow key..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full bg-surface/80 border border-gray-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-gray-200 placeholder-gray-500 focus:outline-none focus:border-indigo-500 transition"
              />
            </div>

            <div className="flex items-center gap-2">
              <span className="text-xs text-gray-400">Source:</span>
              <select
                value={evidenceTypeFilter}
                onChange={(e) => setEvidenceTypeFilter(e.target.value)}
                className="bg-surface/80 border border-gray-800 rounded-lg px-2.5 py-1.5 text-xs text-gray-300 focus:outline-none focus:border-indigo-500"
              >
                <option value="ALL">All Source Types</option>
                <option value="PCAP_OBSERVATION">PCAP Observation</option>
                <option value="DNS_RESOLUTION">DNS Resolution</option>
                <option value="ARP_RESOLUTION">ARP Resolution</option>
                <option value="ROUTING_CONFIG">Routing Configuration</option>
                <option value="INVENTORY_IMPORT">Inventory Import</option>
              </select>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Evidence Ledger Table */}
            <div className="lg:col-span-2 bg-surface/40 border border-gray-800/80 rounded-lg overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="bg-surface/90 border-b border-gray-800 text-gray-400 font-medium">
                    <tr>
                      <th className="py-2.5 px-3">Evidence ID</th>
                      <th className="py-2.5 px-3">Source Type</th>
                      <th className="py-2.5 px-3">Artifact ID / Ref</th>
                      <th className="py-2.5 px-3">Confidence</th>
                      <th className="py-2.5 px-3 text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-800/60">
                    {filteredEvidence.length === 0 ? (
                      <tr>
                        <td colSpan={5} className="py-8 text-center text-gray-500">
                          No auditable evidence records found.
                        </td>
                      </tr>
                    ) : (
                      filteredEvidence.map((ev) => (
                        <tr
                          key={ev.evidence_id}
                          onClick={() => setSelectedEvidence(ev)}
                          className={`hover:bg-indigo-950/20 cursor-pointer transition ${
                            selectedEvidence?.evidence_id === ev.evidence_id ? 'bg-indigo-950/30' : ''
                          }`}
                        >
                          <td className="py-2.5 px-3 font-mono text-indigo-400 font-medium">
                            {ev.evidence_id.slice(0, 10)}...
                          </td>
                          <td className="py-2.5 px-3">
                            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-medium bg-gray-800 text-gray-300">
                              {ev.source_type}
                            </span>
                          </td>
                          <td className="py-2.5 px-3 font-mono text-gray-400 truncate max-w-[150px]">
                            {ev.source_artifact_id}
                          </td>
                          <td className="py-2.5 px-3 font-mono text-emerald-400">
                            {(ev.confidence * 100).toFixed(0)}%
                          </td>
                          <td className="py-2.5 px-3 text-right">
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                setSelectedEvidence(ev);
                              }}
                              className="text-xs text-indigo-400 hover:text-indigo-300 font-medium"
                            >
                              Inspect
                            </button>
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Evidence Detail Drawer */}
            <div className="bg-surface/50 border border-gray-800/80 rounded-lg p-4 space-y-4">
              {selectedEvidence ? (
                <div>
                  <div className="border-b border-gray-800 pb-3">
                    <div className="text-[10px] uppercase font-mono text-gray-400">Auditable Evidence Record</div>
                    <h4 className="text-xs font-bold text-indigo-300 font-mono mt-0.5 break-all">
                      {selectedEvidence.evidence_id}
                    </h4>
                  </div>

                  <div className="mt-3 space-y-3 text-xs">
                    <div>
                      <span className="text-gray-400 font-medium">Source Type:</span>{' '}
                      <span className="font-mono text-cyan-400 font-semibold">{selectedEvidence.source_type}</span>
                    </div>

                    <div>
                      <span className="text-gray-400 font-medium">Artifact Reference:</span>{' '}
                      <span className="font-mono text-gray-300 break-all">{selectedEvidence.source_artifact_id}</span>
                    </div>

                    {selectedEvidence.flow_key && (
                      <div>
                        <span className="text-gray-400 font-medium">Flow Key:</span>{' '}
                        <span className="font-mono text-purple-300 break-all">{selectedEvidence.flow_key}</span>
                      </div>
                    )}

                    {selectedEvidence.packet_number_or_offset !== undefined && (
                      <div>
                        <span className="text-gray-400 font-medium">Packet / Frame Offset:</span>{' '}
                        <span className="font-mono text-amber-300">{selectedEvidence.packet_number_or_offset}</span>
                      </div>
                    )}

                    {selectedEvidence.timestamp_iso && (
                      <div>
                        <span className="text-gray-400 font-medium">Timestamp:</span>{' '}
                        <span className="font-mono text-gray-400">{selectedEvidence.timestamp_iso}</span>
                      </div>
                    )}

                    <div>
                      <span className="text-gray-400 font-medium">Confidence Score:</span>{' '}
                      <span className="font-mono text-emerald-400 font-bold">
                        {(selectedEvidence.confidence * 100).toFixed(1)}%
                      </span>
                    </div>

                    {selectedEvidence.notes && (
                      <div className="p-2 bg-gray-900 border border-gray-800 rounded text-gray-300 text-[11px]">
                        {selectedEvidence.notes}
                      </div>
                    )}

                    <div>
                      <div className="text-gray-400 font-medium mb-1">Extracted Attributes:</div>
                      <pre className="p-2 bg-slate-950 border border-gray-800 rounded font-mono text-[10px] text-gray-300 overflow-x-auto max-h-48">
                        {JSON.stringify(selectedEvidence.extracted_attributes, null, 2)}
                      </pre>
                    </div>
                  </div>
                </div>
              ) : (
                <div className="py-12 text-center text-gray-500 text-xs">
                  <ShieldAlert className="w-8 h-8 mx-auto text-gray-600 mb-2" />
                  Select an evidence record from the ledger to inspect provenance metadata, timestamps, and extracted attributes.
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* TAB CONTENT: SNAPSHOT COMPARISON */}
      {activeTab === 'comparison' && (
        <div className="space-y-6">
          <div className="bg-surface/40 border border-gray-800 rounded-lg p-4">
            <h3 className="text-sm font-semibold text-white mb-1">Differential Topology Comparison</h3>
            <p className="text-xs text-gray-400 mb-4">
              Select two immutable snapshots to compute structural diffs with evidence-backed explanations.
            </p>

            <div className="flex flex-col sm:flex-row items-center gap-4">
              <div className="flex-1 w-full">
                <label className="block text-[11px] font-medium text-gray-400 mb-1">Base Snapshot (A)</label>
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
                <label className="block text-[11px] font-medium text-gray-400 mb-1">Target Snapshot (B)</label>
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
                onClick={handleCompareSnapshots}
                disabled={!baseSnapshotId || !targetSnapshotId || comparing}
                className="mt-5 px-4 py-2 rounded bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold shadow-sm transition disabled:opacity-50 flex items-center gap-2"
              >
                <GitCompare className="w-4 h-4" />
                <span>{comparing ? 'Comparing...' : 'Run Diff'}</span>
              </button>
            </div>
          </div>

          {comparisonDiff && (
            <div className="space-y-4">
              {/* Diff summary badges */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <div className="p-3 bg-surface/40 border border-gray-800 rounded-lg">
                  <span className="text-[10px] text-gray-400 font-medium uppercase">Added Nodes</span>
                  <div className="text-xl font-bold font-mono text-emerald-400 mt-0.5">
                    +{comparisonDiff.added_nodes.length}
                  </div>
                </div>
                <div className="p-3 bg-surface/40 border border-gray-800 rounded-lg">
                  <span className="text-[10px] text-gray-400 font-medium uppercase">Removed Nodes</span>
                  <div className="text-xl font-bold font-mono text-rose-400 mt-0.5">
                    -{comparisonDiff.removed_nodes.length}
                  </div>
                </div>
                <div className="p-3 bg-surface/40 border border-gray-800 rounded-lg">
                  <span className="text-[10px] text-gray-400 font-medium uppercase">Added Edges</span>
                  <div className="text-xl font-bold font-mono text-emerald-400 mt-0.5">
                    +{comparisonDiff.added_edges.length}
                  </div>
                </div>
                <div className="p-3 bg-surface/40 border border-gray-800 rounded-lg">
                  <span className="text-[10px] text-gray-400 font-medium uppercase">Removed Edges</span>
                  <div className="text-xl font-bold font-mono text-rose-400 mt-0.5">
                    -{comparisonDiff.removed_edges.length}
                  </div>
                </div>
              </div>

              {/* Explanations */}
              <div className="bg-surface/50 border border-gray-800 rounded-lg p-4">
                <h4 className="text-xs font-semibold text-white uppercase tracking-wider mb-2 flex items-center gap-1.5">
                  <Info className="w-3.5 h-3.5 text-indigo-400" />
                  Evidence-Grounded Explanations
                </h4>
                <div className="space-y-1.5">
                  {comparisonDiff.evidence_explanations.map((exp, idx) => (
                    <div
                      key={idx}
                      className="p-2 bg-gray-900/60 border border-gray-800 rounded text-xs text-gray-300 font-mono"
                    >
                      {exp}
                    </div>
                  ))}
                </div>
              </div>

              {/* Structural Diffs */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                {/* Added Nodes */}
                <div className="bg-surface/40 border border-gray-800 rounded-lg p-3">
                  <div className="font-semibold text-emerald-400 mb-2">
                    Added Nodes ({comparisonDiff.added_nodes.length})
                  </div>
                  {comparisonDiff.added_nodes.length === 0 ? (
                    <div className="text-gray-500 italic">No new nodes added in target snapshot.</div>
                  ) : (
                    <div className="space-y-1 font-mono max-h-48 overflow-y-auto">
                      {comparisonDiff.added_nodes.map((n) => (
                        <div key={n.id} className="p-1.5 bg-emerald-950/20 border border-emerald-900/40 rounded flex justify-between">
                          <span className="text-emerald-300 font-semibold">{n.label}</span>
                          <span className="text-gray-400">{n.node_type}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* Removed Nodes */}
                <div className="bg-surface/40 border border-gray-800 rounded-lg p-3">
                  <div className="font-semibold text-rose-400 mb-2">
                    Removed Nodes ({comparisonDiff.removed_nodes.length})
                  </div>
                  {comparisonDiff.removed_nodes.length === 0 ? (
                    <div className="text-gray-500 italic">No nodes removed in target snapshot.</div>
                  ) : (
                    <div className="space-y-1 font-mono max-h-48 overflow-y-auto">
                      {comparisonDiff.removed_nodes.map((n) => (
                        <div key={n.id} className="p-1.5 bg-rose-950/20 border border-rose-900/40 rounded flex justify-between">
                          <span className="text-rose-300 font-semibold">{n.label}</span>
                          <span className="text-gray-400">{n.node_type}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* TAB CONTENT: IMPORTS & INGESTION */}
      {activeTab === 'imports' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Import form */}
            <form onSubmit={handleImportConfig} className="bg-surface/40 border border-gray-800 rounded-lg p-4 space-y-4">
              <div>
                <h3 className="text-sm font-semibold text-white">Import Network Configuration</h3>
                <p className="text-xs text-gray-400 mt-0.5">
                  Directly ingest authorized routing tables, neighbor/ARP tables, or CMDB device inventories.
                </p>
              </div>

              {importSuccessMessage && (
                <div className="p-3 bg-emerald-950/40 border border-emerald-800/60 rounded text-emerald-300 text-xs flex items-center gap-2">
                  <CheckCircle className="w-4 h-4 shrink-0" />
                  <span>{importSuccessMessage}</span>
                </div>
              )}

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-[11px] font-medium text-gray-400 mb-1">Source Name</label>
                  <input
                    type="text"
                    value={importSourceName}
                    onChange={(e) => setImportSourceName(e.target.value)}
                    className="w-full bg-surface/80 border border-gray-800 rounded px-2.5 py-1.5 text-xs text-gray-200 focus:outline-none focus:border-indigo-500 font-mono"
                    required
                  />
                </div>

                <div>
                  <label className="block text-[11px] font-medium text-gray-400 mb-1">Format</label>
                  <select
                    value={importFormat}
                    onChange={(e) => setImportFormat(e.target.value as 'json' | 'csv')}
                    className="w-full bg-surface/80 border border-gray-800 rounded px-2.5 py-1.5 text-xs text-gray-200 focus:outline-none focus:border-indigo-500"
                  >
                    <option value="json">JSON</option>
                    <option value="csv">CSV</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-[11px] font-medium text-gray-400 mb-1">Configuration Content</label>
                <textarea
                  rows={8}
                  value={importContent}
                  onChange={(e) => setImportContent(e.target.value)}
                  className="w-full bg-slate-950 border border-gray-800 rounded p-2.5 font-mono text-xs text-gray-200 focus:outline-none focus:border-indigo-500"
                  placeholder="Paste JSON or CSV configuration..."
                  required
                />
              </div>

              <button
                type="submit"
                disabled={importing}
                className="w-full py-2 rounded bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold shadow-sm transition disabled:opacity-50 flex items-center justify-center gap-1.5"
              >
                <Database className="w-4 h-4" />
                <span>{importing ? 'Importing...' : 'Submit & Ingest Configuration'}</span>
              </button>
            </form>

            {/* Ingestion & Capture History */}
            <div className="space-y-4">
              <div className="bg-surface/40 border border-gray-800 rounded-lg p-4">
                <h3 className="text-sm font-semibold text-white mb-2 flex items-center gap-2">
                  <History className="w-4 h-4 text-indigo-400" />
                  Configuration Import History
                </h3>
                {importHistory.length === 0 ? (
                  <div className="text-gray-500 text-xs italic py-4">No configuration imports recorded.</div>
                ) : (
                  <div className="divide-y divide-gray-800/80 text-xs max-h-56 overflow-y-auto">
                    {importHistory.map((imp) => (
                      <div key={imp.import_id} className="py-2 flex items-center justify-between font-mono">
                        <div>
                          <div className="text-gray-200 font-semibold">{imp.source_name}</div>
                          <div className="text-[10px] text-gray-400">
                            {imp.source_type} &bull; {imp.imported_at_iso.slice(0, 19)}
                          </div>
                        </div>
                        <div className="text-right">
                          <span className="text-emerald-400 font-semibold">+{imp.items_imported} items</span>
                          <div className="text-[10px] text-gray-500">{imp.status}</div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              <div className="bg-surface/40 border border-gray-800 rounded-lg p-4">
                <h3 className="text-sm font-semibold text-white mb-2 flex items-center gap-2">
                  <Database className="w-4 h-4 text-cyan-400" />
                  Registered PCAP / PCAPNG Captures
                </h3>
                {captures.length === 0 ? (
                  <div className="text-gray-500 text-xs italic py-4">No packet captures cataloged.</div>
                ) : (
                  <div className="divide-y divide-gray-800/80 text-xs max-h-56 overflow-y-auto">
                    {captures.map((cap) => (
                      <div key={cap.capture_id} className="py-2 flex items-center justify-between font-mono">
                        <div>
                          <div className="text-gray-200 font-semibold">{cap.file_name}</div>
                          <div className="text-[10px] text-gray-500">
                            SHA: {cap.sha256_hash.slice(0, 12)}...
                          </div>
                        </div>
                        <div className="text-right">
                          <span className="text-indigo-400 font-semibold">{cap.packet_count} packets</span>
                          <div className="text-[10px] text-gray-400">{cap.format}</div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB CONTENT: REACHABILITY WORKBENCH */}
      {activeTab === 'reachability' && (
        <ReachabilityWorkbench
          models={models}
          selectedModelId={selectedModelId}
          onSelectModel={setSelectedModelId}
          onEvaluate={handleEvaluateReachability}
          loading={actionLoading}
        />
      )}

      {/* TAB CONTENT: SECURITY INVARIANTS & VERIFICATION */}
      {activeTab === 'verification' && (
        <SecurityVerificationView
          models={models}
          selectedModelId={selectedModelId}
          onSelectModel={setSelectedModelId}
          invariants={invariants}
          verificationResults={verificationResults}
          onRunVerification={handleRunVerification}
          onCreateInvariant={handleCreateInvariant}
          loading={actionLoading}
        />
      )}

      {/* TAB CONTENT: WHAT-IF SCENARIOS & COUNTERFACTUAL SIMULATION */}
      {activeTab === 'counterfactual' && (
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
          loading={actionLoading}
        />
      )}

      {/* TAB CONTENT: MODEL INSPECTOR */}
      {activeTab === 'models' && (
        <ModelInspectorView
          models={models}
          selectedModelId={selectedModelId}
          onSelectModel={setSelectedModelId}
          snapshots={snapshots}
          onBuildModel={handleBuildModel}
          loading={loading || actionLoading}
        />
      )}

      {/* TAB CONTENT: PROTOCOL SECURITY TESTING & FUZZING */}
      {activeTab === 'fuzzing' && (
        <SecurityTestingWorkbench />
      )}

      {/* TAB CONTENT: PREDICTIVE WORLD MODEL & BEHAVIOR FORECASTING */}
      {activeTab === 'predictive' && (
        <PredictiveWorkbench />
      )}

      {/* TAB CONTENT: VALIDATION & BENCHMARKS */}
      {activeTab === 'benchmarks' && (
        <BenchmarkWorkbench />
      )}

      {/* TAB CONTENT: ADVERSARIAL VERIFICATION & HARDENING */}
      {activeTab === 'hardening' && (
        <AdversarialHardeningWorkbench />
      )}

      {/* TAB CONTENT: REAL CAPTURE VALIDATION & DIFFERENTIAL TESTING */}
      {activeTab === 'captures' && (
        <RealCaptureWorkbench />
      )}

      {/* TAB CONTENT: INCIDENT INVESTIGATIONS */}
      {activeTab === 'investigations' && (
        <InvestigationWorkbench />
      )}

      {/* Full-Screen Interactive Topology Workspace Modal */}
      <TopologyModal
        isOpen={isTopologyModalOpen}
        onClose={() => setIsTopologyModalOpen(false)}
        topology={topology}
        selectedNode={selectedNode}
        selectedEdge={selectedEdge}
        onSelectNode={setSelectedNode}
        onSelectEdge={setSelectedEdge}
        evidenceClassFilter={evidenceClassFilter}
        onChangeEvidenceFilter={setEvidenceClassFilter}
        renderEvidenceClassBadge={renderEvidenceClassBadge}
      />

      {/* Snapshot Creation Modal */}
      {showSnapshotModal && (
        <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
          <form
            onSubmit={handleCreateSnapshot}
            className="bg-surface border border-gray-700 rounded-lg shadow-xl max-w-md w-full p-5 space-y-4"
          >
            <div>
              <h3 className="text-sm font-bold text-white">Create Topology Snapshot</h3>
              <p className="text-xs text-gray-400 mt-0.5">
                Take an immutable, SHA-256 fingerprinted snapshot of the current network digital twin.
              </p>
            </div>

            <div>
              <label className="block text-xs font-medium text-gray-300 mb-1">Snapshot Name</label>
              <input
                type="text"
                placeholder="e.g., prod-pre-maintenance-baseline"
                value={newSnapshotName}
                onChange={(e) => setNewSnapshotName(e.target.value)}
                className="w-full bg-slate-950 border border-gray-700 rounded px-3 py-1.5 text-xs text-gray-200 focus:outline-none focus:border-indigo-500 font-mono"
                required
              />
            </div>

            <div className="flex justify-end gap-2 pt-2">
              <button
                type="button"
                onClick={() => setShowSnapshotModal(false)}
                className="px-3 py-1.5 rounded bg-gray-800 hover:bg-gray-700 text-gray-300 text-xs font-medium"
              >
                Cancel
              </button>
              <button
                type="submit"
                className="px-3 py-1.5 rounded bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-medium shadow"
              >
                Save Snapshot
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
};
