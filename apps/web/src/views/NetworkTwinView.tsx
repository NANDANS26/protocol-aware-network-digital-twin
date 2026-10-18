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
  ZoomIn,
  ZoomOut,
  RotateCcw,
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

  // Canvas zoom & pan interaction states
  const [zoomLevel, setZoomLevel] = useState<number>(1);
  const [panOffset, setPanOffset] = useState<{ x: number; y: number }>({ x: 0, y: 0 });
  const [isPanning, setIsPanning] = useState<boolean>(false);
  const [panStart, setPanStart] = useState<{ x: number; y: number }>({ x: 0, y: 0 });

  // Snapshot comparison state
  const [baseSnapshotId, setBaseSnapshotId] = useState<string>('');
  const [targetSnapshotId, setTargetSnapshotId] = useState<string>('');
  const [comparisonDiff, setComparisonDiff] = useState<SnapshotComparisonDiff | null>(null);
  const [comparing, setComparing] = useState<boolean>(false);

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

  // Topology clustered layout computation
  const nodePositions = useMemo(() => {
    const positions = new Map<string, { x: number; y: number }>();
    if (!topology || !topology.nodes || topology.nodes.length === 0) return positions;

    const nodes = topology.nodes;
    const edges = topology.edges || [];

    const subnetNodes = nodes.filter((n) => n.node_type === 'SUBNET');
    const routerNodes = nodes.filter((n) => n.node_type === 'ROUTER');
    const assetNodes = nodes.filter(
      (n) => n.node_type === 'ASSET' || n.node_type === 'INTERFACE' || n.node_type === 'DNS_RESOLVER'
    );
    const serviceNodes = nodes.filter((n) => n.node_type === 'SERVICE');

    // 1. Position Subnets as anchor hubs
    const subnetCenters = new Map<string, { x: number; y: number }>();
    if (subnetNodes.length === 1) {
      const sId = subnetNodes[0]!.node_id || subnetNodes[0]!.id || '';
      subnetCenters.set(sId, { x: 0, y: 0 });
      positions.set(sId, { x: 0, y: 0 });
    } else if (subnetNodes.length > 1) {
      const sRadius = Math.min(200, 80 + subnetNodes.length * 35);
      subnetNodes.forEach((s, idx) => {
        const sId = s.node_id || s.id || '';
        const angle = (idx / subnetNodes.length) * 2 * Math.PI - Math.PI / 2;
        const pos = {
          x: Math.round(Math.cos(angle) * sRadius),
          y: Math.round(Math.sin(angle) * sRadius),
        };
        subnetCenters.set(sId, pos);
        positions.set(sId, pos);
      });
    }

    // 2. Position Routers between subnets or along axis
    if (routerNodes.length > 0) {
      routerNodes.forEach((r, idx) => {
        const rId = r.node_id || r.id || '';
        const connectedSubnetEdges = edges.filter(
          (e) =>
            (e.source_node_id === rId || e.target_node_id === rId) &&
            (subnetCenters.has(e.source_node_id) || subnetCenters.has(e.target_node_id))
        );
        if (connectedSubnetEdges.length >= 2) {
          let ax = 0;
          let ay = 0;
          let count = 0;
          connectedSubnetEdges.forEach((e) => {
            const sId = subnetCenters.has(e.source_node_id) ? e.source_node_id : e.target_node_id;
            const sc = subnetCenters.get(sId);
            if (sc) {
              ax += sc.x;
              ay += sc.y;
              count++;
            }
          });
          positions.set(rId, {
            x: count > 0 ? Math.round(ax / count) : 0,
            y: count > 0 ? Math.round(ay / count) : 0,
          });
        } else if (connectedSubnetEdges.length === 1) {
          const sId = subnetCenters.has(connectedSubnetEdges[0]!.source_node_id)
            ? connectedSubnetEdges[0]!.source_node_id
            : connectedSubnetEdges[0]!.target_node_id;
          const sc = subnetCenters.get(sId) || { x: 0, y: 0 };
          positions.set(rId, { x: sc.x, y: sc.y - 75 });
        } else {
          const angle = (idx / routerNodes.length) * 2 * Math.PI;
          positions.set(rId, {
            x: Math.round(Math.cos(angle) * 75),
            y: Math.round(Math.sin(angle) * 75),
          });
        }
      });
    }

    // 3. Group and position Assets clustered around their respective subnets
    const subnetAssetMap = new Map<string, TopologyNode[]>();
    const unattachedAssets: TopologyNode[] = [];

    assetNodes.forEach((a) => {
      const aId = a.node_id || a.id || '';
      const attachment = edges.find(
        (e) =>
          (e.edge_type === 'SUBNET_ATTACHMENT' ||
            subnetCenters.has(e.source_node_id) ||
            subnetCenters.has(e.target_node_id)) &&
          (e.source_node_id === aId || e.target_node_id === aId)
      );
      const subId = attachment
        ? subnetCenters.has(attachment.source_node_id)
          ? attachment.source_node_id
          : attachment.target_node_id
        : null;

      if (subId && subnetCenters.has(subId)) {
        if (!subnetAssetMap.has(subId)) subnetAssetMap.set(subId, []);
        subnetAssetMap.get(subId)!.push(a);
      } else {
        unattachedAssets.push(a);
      }
    });

    subnetAssetMap.forEach((attached, subId) => {
      const sc = subnetCenters.get(subId) || { x: 0, y: 0 };
      const orbitRadius = Math.min(130, 65 + attached.length * 10);
      attached.forEach((a, aIdx) => {
        const aId = a.node_id || a.id || '';
        const angle = (aIdx / attached.length) * 2 * Math.PI;
        positions.set(aId, {
          x: Math.round(sc.x + Math.cos(angle) * orbitRadius),
          y: Math.round(sc.y + Math.sin(angle) * orbitRadius),
        });
      });
    });

    if (unattachedAssets.length > 0) {
      const outerRadius = 220;
      unattachedAssets.forEach((a, uIdx) => {
        const aId = a.node_id || a.id || '';
        const angle = (uIdx / unattachedAssets.length) * 2 * Math.PI;
        positions.set(aId, {
          x: Math.round(Math.cos(angle) * outerRadius),
          y: Math.round(Math.sin(angle) * outerRadius),
        });
      });
    }

    // 4. Position Services as satellites to host nodes
    serviceNodes.forEach((srv, sIdx) => {
      const sId = srv.node_id || srv.id || '';
      const hostEdge = edges.find(
        (e) =>
          (e.source_node_id === sId || e.target_node_id === sId) &&
          (positions.has(e.source_node_id) || positions.has(e.target_node_id))
      );
      const hostNodeId = srv.asset_id
        ? `node-${srv.asset_id}`
        : hostEdge
        ? positions.has(hostEdge.source_node_id) && hostEdge.source_node_id !== sId
          ? hostEdge.source_node_id
          : hostEdge.target_node_id
        : null;

      const hostPos = hostNodeId && positions.has(hostNodeId) ? positions.get(hostNodeId)! : { x: 0, y: 0 };
      const offsetAngle = sIdx * 1.5;
      positions.set(sId, {
        x: Math.round(hostPos.x + Math.cos(offsetAngle) * 32),
        y: Math.round(hostPos.y + Math.sin(offsetAngle) * 32),
      });
    });

    // 5. Fallback for any unplaced nodes
    nodes.forEach((n, idx) => {
      const nId = n.node_id || n.id || '';
      if (!positions.has(nId)) {
        const angle = (idx / nodes.length) * 2 * Math.PI;
        positions.set(nId, {
          x: Math.round(Math.cos(angle) * 180),
          y: Math.round(Math.sin(angle) * 180),
        });
      }
    });

    return positions;
  }, [topology]);

  // Topology Canvas Interaction Handlers
  const handleZoomIn = () => setZoomLevel((z) => Math.min(3.0, Number((z + 0.2).toFixed(1))));
  const handleZoomOut = () => setZoomLevel((z) => Math.max(0.4, Number((z - 0.2).toFixed(1))));
  const handleResetZoom = () => {
    setZoomLevel(1);
    setPanOffset({ x: 0, y: 0 });
  };

  const handleMouseDown = (e: React.MouseEvent<SVGSVGElement>) => {
    const targetTag = (e.target as HTMLElement).tagName?.toLowerCase();
    if (targetTag === 'svg' || (e.target as HTMLElement).getAttribute('data-bg') === 'true') {
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
    setZoomLevel((z) => Math.min(3.0, Math.max(0.4, Number((z + delta).toFixed(1)))));
  };

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
          <div className="flex flex-wrap items-center justify-between gap-3 bg-surface/40 p-3 rounded-lg border border-gray-800">
            <div className="flex items-center gap-3">
              <div className="flex items-center gap-2">
                <span className="text-xs text-gray-400">Filter Evidence:</span>
                <select
                  value={evidenceClassFilter}
                  onChange={(e) => setEvidenceClassFilter(e.target.value)}
                  className="bg-surface/80 border border-gray-800 rounded px-2.5 py-1 text-xs text-gray-300 focus:outline-none focus:border-indigo-500 font-mono"
                >
                  <option value="ALL">All Relationships</option>
                  <option value="DIRECTLY_OBSERVED">Directly Observed Only</option>
                  <option value="DIRECT_OBSERVATION">Direct Observation Only</option>
                  <option value="CONFIGURED">Configured Only</option>
                  <option value="INFERRED">Inferred Only</option>
                </select>
              </div>

              {/* Canvas Zoom & Pan Controls */}
              <div className="flex items-center gap-1 bg-surface border border-gray-800 rounded px-1.5 py-0.5">
                <button
                  type="button"
                  onClick={handleZoomIn}
                  title="Zoom In"
                  className="p-1 hover:bg-gray-800 rounded text-gray-300 hover:text-white transition"
                >
                  <ZoomIn className="w-3.5 h-3.5" />
                </button>
                <button
                  type="button"
                  onClick={handleZoomOut}
                  title="Zoom Out"
                  className="p-1 hover:bg-gray-800 rounded text-gray-300 hover:text-white transition"
                >
                  <ZoomOut className="w-3.5 h-3.5" />
                </button>
                <button
                  type="button"
                  onClick={handleResetZoom}
                  title="Reset View / Fit to View"
                  className="px-2 py-0.5 hover:bg-gray-800 rounded text-[11px] font-mono text-gray-300 hover:text-white transition flex items-center gap-1"
                >
                  <RotateCcw className="w-3 h-3" />
                  <span>{(zoomLevel * 100).toFixed(0)}%</span>
                </button>
              </div>
            </div>

            <div className="flex items-center gap-4 text-xs font-mono">
              <span className="flex items-center gap-1.5 text-blue-400">
                <span className="w-2.5 h-2.5 rounded bg-blue-500 inline-block" /> Subnet Hub
              </span>
              <span className="flex items-center gap-1.5 text-emerald-400">
                <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 inline-block" /> Asset Node
              </span>
              <span className="flex items-center gap-1.5 text-amber-400">
                <span className="w-2.5 h-2.5 rotate-45 bg-amber-500 inline-block" /> Service
              </span>
              <span className="flex items-center gap-1.5 text-purple-400">
                <span className="w-2.5 h-2.5 rounded bg-purple-500 inline-block" /> Router
              </span>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
            {/* SVG Graph Canvas */}
            <div
              className={`lg:col-span-3 bg-slate-950 border border-gray-800/80 rounded-lg p-2 relative min-h-[540px] flex items-center justify-center overflow-hidden ${
                isPanning ? 'cursor-grabbing' : 'cursor-grab'
              }`}
            >
              {/* Canvas interaction hint overlay */}
              <div className="absolute top-3 left-3 z-10 text-[10px] font-mono text-gray-500 bg-gray-950/80 border border-gray-800/70 px-2 py-1 rounded pointer-events-none select-none">
                Scroll: Zoom | Drag: Pan | Click: Inspect
              </div>

              {topology && (topology.nodes || []).length > 0 ? (
                <svg
                  className="w-full h-[540px] select-none"
                  viewBox="-340 -280 680 560"
                  onMouseDown={handleMouseDown}
                  onMouseMove={handleMouseMove}
                  onMouseUp={handleMouseUp}
                  onMouseLeave={handleMouseUp}
                  onWheel={handleWheel}
                >
                  <defs>
                    <marker
                      id="arrow"
                      viewBox="0 0 10 10"
                      refX="20"
                      refY="5"
                      markerWidth="6"
                      markerHeight="6"
                      orient="auto-start-reverse"
                    >
                      <path d="M 0 0 L 10 5 L 0 10 z" fill="#64748b" />
                    </marker>
                    <marker
                      id="arrow-selected"
                      viewBox="0 0 10 10"
                      refX="20"
                      refY="5"
                      markerWidth="6"
                      markerHeight="6"
                      orient="auto-start-reverse"
                    >
                      <path d="M 0 0 L 10 5 L 0 10 z" fill="#60a5fa" />
                    </marker>
                    {/* Grid Pattern for canvas background */}
                    <pattern id="twin-grid" width="40" height="40" patternUnits="userSpaceOnUse">
                      <path d="M 40 0 L 0 0 0 40" fill="none" stroke="#1e293b" strokeWidth="0.5" opacity="0.4" />
                    </pattern>
                  </defs>

                  {/* Infinite canvas grid */}
                  <rect
                    data-bg="true"
                    x="-1000"
                    y="-1000"
                    width="2000"
                    height="2000"
                    fill="url(#twin-grid)"
                  />

                  {/* Pan & Zoom Group */}
                  <g transform={`translate(${panOffset.x}, ${panOffset.y}) scale(${zoomLevel})`}>
                    {/* Edges */}
                    {(topology.edges || [])
                      .filter(
                        (e) => evidenceClassFilter === 'ALL' || e.evidence_class === evidenceClassFilter
                      )
                      .map((edge, edgeIdx) => {
                        const edgeKey = edge.edge_id || edge.id || `edge-${edgeIdx}`;
                        const sPos = nodePositions.get(edge.source_node_id);
                        const tPos = nodePositions.get(edge.target_node_id);
                        if (!sPos || !tPos) return null;

                        const isSelected = (selectedEdge?.edge_id || selectedEdge?.id) === (edge.edge_id || edge.id);
                        const isStrokeDashed = edge.evidence_class === 'INFERRED';
                        const strokeColor = isSelected
                          ? '#60a5fa'
                          : edge.edge_type === 'OBSERVED_COMMUNICATION'
                          ? '#06b6d4'
                          : edge.edge_type === 'SUBNET_ATTACHMENT'
                          ? '#6366f1'
                          : '#f59e0b';

                        return (
                          <g
                            key={edgeKey}
                            onClick={(ev) => {
                              ev.stopPropagation();
                              setSelectedEdge(edge);
                              setSelectedNode(null);
                            }}
                            className="cursor-pointer group"
                          >
                            <title>
                              {`Edge: ${edge.source_node_id} -> ${edge.target_node_id}\nType: ${edge.edge_type}\nProtocol: ${edge.primary_protocol || edge.protocol || 'IP'}\nPackets: ${edge.packet_count}`}
                            </title>
                            {/* Hover hit area */}
                            <line
                              x1={sPos.x}
                              y1={sPos.y}
                              x2={tPos.x}
                              y2={tPos.y}
                              stroke="transparent"
                              strokeWidth={14}
                            />
                            {/* Visible edge */}
                            <line
                              x1={sPos.x}
                              y1={sPos.y}
                              x2={tPos.x}
                              y2={tPos.y}
                              stroke={strokeColor}
                              strokeWidth={isSelected ? 3 : Math.min(3, Math.max(1, Math.log10(edge.packet_count + 1)))}
                              strokeDasharray={isStrokeDashed ? '4,4' : undefined}
                              opacity={isSelected ? 1 : 0.7}
                              markerEnd={isSelected ? 'url(#arrow-selected)' : 'url(#arrow)'}
                              className="group-hover:stroke-indigo-300 transition"
                            />
                          </g>
                        );
                      })}

                    {/* Nodes */}
                    {(topology.nodes || []).map((node, nodeIdx) => {
                      const nodeId = node.node_id || node.id || `node-${nodeIdx}`;
                      const pos = nodePositions.get(nodeId) || { x: 0, y: 0 };
                      const isSelected = (selectedNode?.node_id || selectedNode?.id) === nodeId;

                      return (
                        <g
                          key={nodeId}
                          transform={`translate(${pos.x}, ${pos.y})`}
                          onClick={(ev) => {
                            ev.stopPropagation();
                            setSelectedNode(node);
                            setSelectedEdge(null);
                          }}
                          className="cursor-pointer group"
                        >
                          <title>
                            {`Node: ${node.label}\nType: ${node.node_type}\nID: ${nodeId}`}
                          </title>

                          {node.node_type === 'SUBNET' ? (
                            <rect
                              x="-32"
                              y="-16"
                              width="64"
                              height="32"
                              rx="8"
                              fill="#1e3a8a"
                              stroke={isSelected ? '#93c5fd' : '#3b82f6'}
                              strokeWidth={isSelected ? '2.5' : '1.5'}
                              className="group-hover:stroke-blue-300 transition"
                            />
                          ) : node.node_type === 'ROUTER' ? (
                            <polygon
                              points="0,-20 20,0 0,20 -20,0"
                              fill="#581c87"
                              stroke={isSelected ? '#d8b4fe' : '#a855f7'}
                              strokeWidth={isSelected ? '2.5' : '1.5'}
                              className="group-hover:stroke-purple-300 transition"
                            />
                          ) : node.node_type === 'SERVICE' ? (
                            <polygon
                              points="0,-14 14,0 0,14 -14,0"
                              fill="#78350f"
                              stroke={isSelected ? '#fde047' : '#f59e0b'}
                              strokeWidth={isSelected ? '2.5' : '1.5'}
                              className="group-hover:stroke-amber-300 transition"
                            />
                          ) : (
                            <circle
                              r="16"
                              fill="#064e3b"
                              stroke={isSelected ? '#6ee7b7' : '#10b981'}
                              strokeWidth={isSelected ? '2.5' : '1.5'}
                              className="group-hover:stroke-emerald-300 transition"
                            />
                          )}

                          {/* Node label */}
                          <text
                            y={node.node_type === 'SUBNET' ? 4 : 26}
                            textAnchor="middle"
                            fill="#e2e8f0"
                            fontSize={node.node_type === 'SUBNET' ? '10' : '9'}
                            fontFamily="monospace"
                            className="font-medium group-hover:fill-indigo-300 transition pointer-events-none"
                          >
                            {node.label.length > 20 ? node.label.slice(0, 18) + '...' : node.label}
                          </text>
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
            <div className="bg-surface/50 border border-gray-800/80 rounded-lg p-4 space-y-4">
              {selectedNode ? (
                <div>
                  <div className="flex items-start justify-between border-b border-gray-800 pb-3">
                    <div>
                      <div className="text-[10px] uppercase font-mono text-gray-400">Topology Node</div>
                      <h4 className="text-sm font-bold text-white font-mono mt-0.5 break-all">{selectedNode.label}</h4>
                    </div>
                    {renderEvidenceClassBadge(selectedNode.evidence_class)}
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
                      <div className="text-gray-400 font-medium mb-1">Adjacent Edges:</div>
                      {(topology?.edges || []).filter(
                        (e) => e.source_node_id === (selectedNode.node_id || selectedNode.id) ||
                               e.target_node_id === (selectedNode.node_id || selectedNode.id)
                      ).length === 0 ? (
                        <div className="text-gray-500 italic text-[11px]">No adjacent graph edges.</div>
                      ) : (
                        <div className="space-y-1 max-h-40 overflow-y-auto">
                          {(topology?.edges || [])
                            .filter(
                              (e) => e.source_node_id === (selectedNode.node_id || selectedNode.id) ||
                                     e.target_node_id === (selectedNode.node_id || selectedNode.id)
                            )
                            .map((e, idx) => (
                              <div
                                key={e.edge_id || e.id || idx}
                                onClick={() => {
                                  setSelectedEdge(e);
                                  setSelectedNode(null);
                                }}
                                className="p-1.5 bg-gray-900 border border-gray-800 hover:border-gray-700 rounded font-mono text-[10px] flex items-center justify-between cursor-pointer transition"
                              >
                                <span className="text-gray-300">{e.edge_type}</span>
                                {renderEvidenceClassBadge(e.evidence_class)}
                              </div>
                            ))}
                        </div>
                      )}
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
                    {renderEvidenceClassBadge(selectedEdge.evidence_class)}
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
                  </div>
                </div>
              ) : (
                <div className="py-12 text-center text-gray-500 text-xs">
                  <Layers className="w-8 h-8 mx-auto text-gray-600 mb-2" />
                  Select any node or edge from the topology canvas to inspect detailed attributes, flow metrics, and evidence provenance.
                </div>
              )}
            </div>
          </div>
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
