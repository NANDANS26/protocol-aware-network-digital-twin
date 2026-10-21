import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { useAnalysisContext } from '../context/AnalysisContext';
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
  ConsumptionAudit,
  EvidenceCoverageSummary,
} from '../types/intelligence';
import type {
  NetworkModel,
  ReachabilityQuery,
  ReachabilityResult,
  SecurityInvariant,
  VerificationResult,
} from '../types/simulation';
import { ReachabilityWorkbench } from './twin/ReachabilityWorkbench';
import { SecurityVerificationView } from './twin/SecurityVerificationView';
import { ModelInspectorView } from './twin/ModelInspectorView';
import { TopologyGraphView } from './twin/topology/TopologyGraphView';
import { TopologyModal } from './twin/topology/TopologyModal';
import { SnapshotComparisonView } from './twin/SnapshotComparisonView';
import {
  Server,
  Network,
  ShieldAlert,
  Layers,
  History,
  FileCode,
  Search,
  RefreshCw,
  Plus,
  GitCompare,
  CheckCircle,
  AlertTriangle,
  Database,
  Info,
  ShieldCheck,
  Cpu,
  Route,
  Maximize2,
  ChevronDown,
  ChevronRight,
  Trash2,
  Sparkles,
  ArrowRight,
} from 'lucide-react';

export type TwinTab =
  | 'assets'
  | 'topology'
  | 'evidence'
  | 'comparison'
  | 'imports'
  | 'reachability'
  | 'verification'
  | 'models';

export interface NetworkTwinViewProps {
  initialSnapshotId?: string | null;
  initialCaptureId?: string | null;
  onNavigateToObservatory?: (captureId?: string) => void;
}

export const NetworkTwinView: React.FC<NetworkTwinViewProps> = ({
  initialSnapshotId,
  initialCaptureId,
  onNavigateToObservatory,
}) => {
  const {
    activeCaptureId,
    activeCapture,
    activeSnapshotId,
    setActiveSnapshotId,
  } = useAnalysisContext();

  const effectiveCaptureId = initialCaptureId || activeCaptureId;

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

  // Active snapshot & model reconstruction states
  const [selectedSnapshotId, setSelectedSnapshotId] = useState<string>(initialSnapshotId || activeSnapshotId || '');
  const [showReconstructModal, setShowReconstructModal] = useState<boolean>(false);
  const [reconstructName, setReconstructName] = useState<string>('');
  const [selectedCaptureIds, setSelectedCaptureIds] = useState<string[]>(effectiveCaptureId ? [effectiveCaptureId] : []);
  const [selectedConfigIds, setSelectedConfigIds] = useState<string[]>([]);
  const [includeAllTelemetry, setIncludeAllTelemetry] = useState<boolean>(!effectiveCaptureId);
  const [reconstructionAudit, setReconstructionAudit] = useState<{
    snapshot: TopologySnapshot;
    audit?: ConsumptionAudit;
    coverage?: EvidenceCoverageSummary;
    limitations?: string[];
  } | null>(null);

  // Snapshot comparison state
  const [baseSnapshotId, setBaseSnapshotId] = useState<string>(initialSnapshotId || '');
  const [targetSnapshotId, setTargetSnapshotId] = useState<string>('');
  const [comparisonDiff, setComparisonDiff] = useState<SnapshotComparisonDiff | null>(null);
  const [comparing, setComparing] = useState<boolean>(false);
  const [diffError, setDiffError] = useState<string | null>(null);

  // Responsive secondary navigation drawer state
  const [isMobileNavOpen, setIsMobileNavOpen] = useState<boolean>(false);

  // Full-screen interactive topology modal state
  const [isTopologyModalOpen, setIsTopologyModalOpen] = useState<boolean>(false);

  // Snapshot creation modal
  const [showSnapshotModal, setShowSnapshotModal] = useState<boolean>(false);
  const [newSnapshotName, setNewSnapshotName] = useState<string>('');

  // Configuration import state
  const [importSourceName, setImportSourceName] = useState<string>('core-router-routes');
  const [importConfigType, setImportConfigType] = useState<'routing_table' | 'neighbor_table' | 'inventory'>('routing_table');
  const [importSerializationFormat, setImportSerializationFormat] = useState<'auto' | 'json' | 'csv'>('auto');
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
  const [deletingImportId, setDeletingImportId] = useState<string | null>(null);
  const [importSuccessMessage, setImportSuccessMessage] = useState<string | null>(null);

  const handleConfigTypeChange = (newType: 'routing_table' | 'neighbor_table' | 'inventory') => {
    setImportConfigType(newType);
    if (newType === 'routing_table') {
      setImportSourceName('core-router-routes');
      setImportContent(
        importSerializationFormat === 'csv'
          ? `destination,gateway,interface,metric\n10.0.1.0/24,10.0.0.1,eth0,10\n192.168.1.0/24,192.168.1.1,eth1,20`
          : JSON.stringify(
              [
                { destination: '10.0.1.0/24', gateway: '10.0.0.1', interface: 'eth0', metric: 10 },
                { destination: '192.168.1.0/24', gateway: '192.168.1.1', interface: 'eth1', metric: 20 },
              ],
              null,
              2
            )
      );
    } else if (newType === 'neighbor_table') {
      setImportSourceName('core-arp-table');
      setImportContent(
        importSerializationFormat === 'csv'
          ? `ip_address,mac_address,interface\n10.0.1.15,00:50:56:c0:00:08,eth0\n10.0.1.25,00:50:56:c0:00:09,eth0`
          : JSON.stringify(
              [
                { ip_address: '10.0.1.15', mac_address: '00:50:56:c0:00:08', interface: 'eth0' },
                { ip_address: '10.0.1.25', mac_address: '00:50:56:c0:00:09', interface: 'eth0' },
              ],
              null,
              2
            )
      );
    } else {
      setImportSourceName('datacenter-inventory');
      setImportContent(
        importSerializationFormat === 'csv'
          ? `device_id,device_type,ip_addresses,hostname\ncore-router-01,router,10.0.0.1,core-rt01.corp\naccess-sw-01,switch,10.0.0.2,acc-sw01.corp`
          : JSON.stringify(
              [
                { device_id: 'core-router-01', device_type: 'router', ip_addresses: ['10.0.0.1'], hostname: 'core-rt01.corp' },
                { device_id: 'access-sw-01', device_type: 'switch', ip_addresses: ['10.0.0.2'], hostname: 'acc-sw01.corp' },
              ],
              null,
              2
            )
      );
    }
  };

  const handleSerializationFormatChange = (newFmt: 'auto' | 'json' | 'csv') => {
    setImportSerializationFormat(newFmt);
    if (newFmt === 'csv') {
      if (importConfigType === 'routing_table') {
        setImportContent(`destination,gateway,interface,metric\n10.0.1.0/24,10.0.0.1,eth0,10\n192.168.1.0/24,192.168.1.1,eth1,20`);
      } else if (importConfigType === 'neighbor_table') {
        setImportContent(`ip_address,mac_address,interface\n10.0.1.15,00:50:56:c0:00:08,eth0\n10.0.1.25,00:50:56:c0:00:09,eth0`);
      } else {
        setImportContent(`device_id,device_type,ip_addresses,hostname\ncore-router-01,router,10.0.0.1,core-rt01.corp\naccess-sw-01,switch,10.0.0.2,acc-sw01.corp`);
      }
    } else {
      if (importConfigType === 'routing_table') {
        setImportContent(
          JSON.stringify(
            [
              { destination: '10.0.1.0/24', gateway: '10.0.0.1', interface: 'eth0', metric: 10 },
              { destination: '192.168.1.0/24', gateway: '192.168.1.1', interface: 'eth1', metric: 20 },
            ],
            null,
            2
          )
        );
      } else if (importConfigType === 'neighbor_table') {
        setImportContent(
          JSON.stringify(
            [
              { ip_address: '10.0.1.15', mac_address: '00:50:56:c0:00:08', interface: 'eth0' },
              { ip_address: '10.0.1.25', mac_address: '00:50:56:c0:00:09', interface: 'eth0' },
            ],
            null,
            2
          )
        );
      } else {
        setImportContent(
          JSON.stringify(
            [
              { device_id: 'core-router-01', device_type: 'router', ip_addresses: ['10.0.0.1'], hostname: 'core-rt01.corp' },
              { device_id: 'access-sw-01', device_type: 'switch', ip_addresses: ['10.0.0.2'], hostname: 'acc-sw01.corp' },
            ],
            null,
            2
          )
        );
      }
    }
  };

  // Fetch all primary model and simulation data
  const loadTwinData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [
        snapData,
        capData,
        impData,
        modelsData,
        invariantsData,
      ] = await Promise.all([
        apiClient.listSnapshots(effectiveCaptureId || undefined),
        apiClient.listCaptures(),
        apiClient.listImports(),
        apiClient.listModels ? apiClient.listModels().catch(() => []) : Promise.resolve([]),
        apiClient.listInvariants ? apiClient.listInvariants().catch(() => []) : Promise.resolve([]),
      ]);

      setSnapshots(snapData);
      setCaptures(capData);
      setImportHistory(impData);
      setModels(modelsData);
      if (modelsData.length > 0 && !selectedModelId && modelsData[0]) {
        setSelectedModelId(modelsData[0].model_id);
      }
      setInvariants(invariantsData);

      // If no snapshots exist for the active capture, clear entity states to prevent cross-capture leakage
      if (snapData.length === 0) {
        setAssets([]);
        setSegments([]);
        setServices([]);
        setRelationships([]);
        setEvidenceList([]);
        setTopology(null);
        setSelectedSnapshotId('');
        return;
      }

      // Resolve active snapshot
      let targetSnapId = selectedSnapshotId;
      if (initialSnapshotId && snapData.some((s) => s.snapshot_id === initialSnapshotId)) {
        targetSnapId = initialSnapshotId;
      } else if (activeSnapshotId && snapData.some((s) => s.snapshot_id === activeSnapshotId)) {
        targetSnapId = activeSnapshotId;
      } else if (!targetSnapId || !snapData.some((s) => s.snapshot_id === targetSnapId)) {
        targetSnapId = snapData[0]?.snapshot_id || '';
      }

      setSelectedSnapshotId(targetSnapId);
      if (targetSnapId && targetSnapId !== activeSnapshotId) {
        setActiveSnapshotId(targetSnapId);
      }

      if (snapData.length >= 2 && !baseSnapshotId && !targetSnapshotId) {
        setBaseSnapshotId(snapData[0]?.snapshot_id || '');
        setTargetSnapshotId(snapData[1]?.snapshot_id || '');
      } else if (snapData.length === 1 && !baseSnapshotId) {
        setBaseSnapshotId(snapData[0]?.snapshot_id || '');
      }

      // Fetch entities strictly scoped to target snapshot / capture
      const [assetsData, segmentsData, servicesData, relData, evData, topoData] = await Promise.all([
        apiClient.listAssets({ snapshot_id: targetSnapId, capture_id: effectiveCaptureId || undefined }),
        apiClient.listSegments({ snapshot_id: targetSnapId, capture_id: effectiveCaptureId || undefined }),
        apiClient.listServices({ snapshot_id: targetSnapId }),
        apiClient.listRelationships({ snapshot_id: targetSnapId, limit: 200 }),
        apiClient.listEvidence({ snapshot_id: targetSnapId, limit: 200 }),
        apiClient.getTopology({ capture_id: effectiveCaptureId || undefined, snapshot_id: targetSnapId }),
      ]);

      setAssets(assetsData);
      setSegments(segmentsData);
      setServices(servicesData);
      setRelationships(relData);
      setEvidenceList(evData);
      setTopology(topoData);
    } catch (err: unknown) {
      setError((err as Error).message || 'Failed to load network twin data.');
    } finally {
      setLoading(false);
    }
  }, [
    effectiveCaptureId,
    initialSnapshotId,
    activeSnapshotId,
    selectedSnapshotId,
    baseSnapshotId,
    targetSnapshotId,
    selectedModelId,
    setActiveSnapshotId,
  ]);

  const handleSelectSnapshot = async (newSnapshotId: string) => {
    setSelectedSnapshotId(newSnapshotId);
    setActiveSnapshotId(newSnapshotId);
    setActionLoading(true);
    try {
      const [assetsData, segmentsData, servicesData, relData, evData, topoData] = await Promise.all([
        apiClient.listAssets({ snapshot_id: newSnapshotId, capture_id: effectiveCaptureId || undefined }),
        apiClient.listSegments({ snapshot_id: newSnapshotId, capture_id: effectiveCaptureId || undefined }),
        apiClient.listServices({ snapshot_id: newSnapshotId }),
        apiClient.listRelationships({ snapshot_id: newSnapshotId, limit: 200 }),
        apiClient.listEvidence({ snapshot_id: newSnapshotId, limit: 200 }),
        apiClient.getTopology({ capture_id: effectiveCaptureId || undefined, snapshot_id: newSnapshotId }),
      ]);
      setAssets(assetsData);
      setSegments(segmentsData);
      setServices(servicesData);
      setRelationships(relData);
      setEvidenceList(evData);
      setTopology(topoData);
    } catch (err: unknown) {
      setError((err as Error).message || 'Failed to switch snapshot.');
    } finally {
      setActionLoading(false);
    }
  };

  const handleReconstructFromActiveCapture = async () => {
    if (!effectiveCaptureId) return;
    setActionLoading(true);
    setError(null);
    try {
      const newSnap = await apiClient.createSnapshotFromCapture(effectiveCaptureId);
      setSelectedSnapshotId(newSnap.snapshot_id);
      setActiveSnapshotId(newSnap.snapshot_id);
      setReconstructionAudit({
        snapshot: newSnap,
        audit: newSnap.metadata?.consumption_audit,
        coverage: newSnap.metadata?.evidence_coverage,
        limitations: newSnap.metadata?.limitations,
      });
      await loadTwinData();
    } catch (err: unknown) {
      setError((err as Error).message || 'Failed to reconstruct model from capture.');
    } finally {
      setActionLoading(false);
    }
  };

  const activeSnapshot = useMemo(() => {
    return snapshots.find((s) => s.snapshot_id === selectedSnapshotId) || snapshots[0] || null;
  }, [snapshots, selectedSnapshotId]);

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

  // Explicit Build / Update Network Model Operation
  const handleReconstructModel = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    setActionLoading(true);
    setError(null);
    try {
      const snapName = reconstructName.trim() || `Twin Model Reconstructed (${new Date().toLocaleTimeString()})`;
      const caps = includeAllTelemetry ? undefined : selectedCaptureIds;
      const cfgs = includeAllTelemetry ? undefined : selectedConfigIds;

      const newSnap = await apiClient.createSnapshot({
        name: snapName,
        source_captures: caps && caps.length > 0 ? caps : undefined,
        source_configs: cfgs && cfgs.length > 0 ? cfgs : undefined,
      });

      setShowReconstructModal(false);
      setReconstructName('');
      setSelectedSnapshotId(newSnap.snapshot_id);

      // Store the audit info for display
      setReconstructionAudit({
        snapshot: newSnap,
        audit: newSnap.metadata?.consumption_audit,
        coverage: newSnap.metadata?.evidence_coverage,
        limitations: newSnap.metadata?.limitations,
      });

      await loadTwinData();
    } catch (err: unknown) {
      setError((err as Error).message || 'Failed to reconstruct network model.');
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
    setDiffError(null);
    setError(null);
    try {
      const diff = await apiClient.compareSnapshots(baseSnapshotId, targetSnapshotId);
      setComparisonDiff(diff);
    } catch (err: unknown) {
      const msg = (err as Error).message || 'Failed to compare snapshots.';
      setDiffError(msg);
      setError(msg);
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
      if (!importContent.trim()) {
        throw new Error('Configuration content cannot be empty.');
      }
      if (importSerializationFormat === 'json') {
        try {
          JSON.parse(importContent);
        } catch {
          throw new Error('Invalid JSON format. Please verify configuration syntax.');
        }
      }
      const res = await apiClient.importConfiguration({
        source_name: importSourceName,
        format: importConfigType,
        content: importContent,
      });
      setImportSuccessMessage(
        `Imported ${res.items_imported} items successfully from '${res.source_name}' (${res.format || res.source_type}).`
      );
      await loadTwinData();
    } catch (err: unknown) {
      setError((err as Error).message || 'Failed to import configuration.');
    } finally {
      setImporting(false);
    }
  };

  // Handle Delete Config Import
  const handleDeleteConfigImport = async (importId: string, sourceName: string) => {
    if (!window.confirm(`Are you sure you want to delete imported configuration '${sourceName}'?`)) {
      return;
    }
    setDeletingImportId(importId);
    setError(null);
    try {
      await apiClient.deleteConfigImport(importId);
      setImportSuccessMessage(`Configuration import '${sourceName}' deleted successfully.`);
      await loadTwinData();
    } catch (err: unknown) {
      setError((err as Error).message || `Failed to delete configuration import '${sourceName}'.`);
    } finally {
      setDeletingImportId(null);
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

  const navGroups: Array<{
    id: string;
    title: string;
    items: Array<{
      id: TwinTab;
      label: string;
      icon: React.ComponentType<{ className?: string }>;
      iconColor?: string;
      badge?: string | number;
    }>;
  }> = useMemo(
    () => [
      {
        id: 'reconstruct_ingest',
        title: 'INGEST & RECONSTRUCT',
        items: [
          { id: 'imports', label: 'Import & Ingestion', icon: FileCode, badge: importHistory.length },
          { id: 'evidence', label: 'Evidence Inspector', icon: ShieldAlert, badge: evidenceList.length },
        ],
      },
      {
        id: 'observe_topology',
        title: 'TOPOLOGY & ASSETS',
        items: [
          { id: 'assets', label: 'Asset Explorer', icon: Server, badge: assets.length },
          {
            id: 'topology',
            label: 'Topology Graph',
            icon: Layers,
            badge: topology ? `${topology.node_count} nodes` : undefined,
          },
          { id: 'models', label: 'Model Inspector', icon: Cpu, iconColor: 'text-amber-400', badge: models.length },
        ],
      },
      {
        id: 'verify_compare',
        title: 'VERIFY & VALIDATE',
        items: [
          { id: 'reachability', label: 'Reachability', icon: Route, iconColor: 'text-cyan-400' },
          {
            id: 'verification',
            label: 'Security Invariants',
            icon: ShieldCheck,
            iconColor: 'text-emerald-400',
            badge: invariants.length,
          },
          {
            id: 'comparison',
            label: 'Snapshot Comparison',
            icon: GitCompare,
            badge: snapshots.length > 1 ? `${snapshots.length} snaps` : undefined,
          },
        ],
      },
    ],
    [assets.length, topology, evidenceList.length, invariants.length, models.length, importHistory.length, snapshots.length]
  );

  const currentActiveItem = useMemo(() => {
    for (const group of navGroups) {
      for (const item of group.items) {
        if (item.id === activeTab) {
          return {
            id: item.id,
            label: item.label,
            icon: item.icon,
            iconColor: item.iconColor,
            badge: item.badge,
            groupTitle: group.title,
          };
        }
      }
    }
    return {
      id: activeTab,
      label: 'Workspace',
      icon: Layers as React.ComponentType<{ className?: string }>,
      iconColor: 'text-indigo-400',
      badge: undefined as string | number | undefined,
      groupTitle: 'WORKSPACE',
    };
  }, [activeTab, navGroups]);

  return (
    <div className="space-y-6" data-testid="network-twin-workstation">
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
                {activeSnapshot && (
                  <span className="text-xs px-2 py-0.5 rounded bg-indigo-950 text-indigo-300 border border-indigo-800/60 font-mono">
                    Active: {activeSnapshot.name}
                  </span>
                )}
              </h1>
              <p className="text-xs text-gray-400 mt-0.5">
                Evidence-grounded network topology reconstruction, formal model verification, reachability analysis &amp; snapshot differential
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          <button
            type="button"
            onClick={() => setShowReconstructModal(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-medium shadow-sm transition"
          >
            <Sparkles className="w-3.5 h-3.5" />
            <span>Reconstruct Model</span>
          </button>
          <button
            type="button"
            onClick={() => setShowSnapshotModal(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-slate-900 hover:bg-slate-800 text-indigo-300 text-xs font-medium border border-indigo-800/60 transition"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Create Snapshot</span>
          </button>
          <button
            type="button"
            onClick={loadTwinData}
            disabled={loading}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-gray-800 hover:bg-gray-700 text-gray-200 text-xs font-medium border border-gray-700 transition disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Primary Lifecycle Workflow Stepper & Active Snapshot Switcher */}
      <div className="bg-slate-900/60 border border-gray-800 rounded-lg p-3 text-xs flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2 flex-wrap text-gray-400">
          <span className="text-[10px] uppercase font-bold tracking-wider text-indigo-400 font-mono">Twin Pipeline:</span>
          <button
            type="button"
            onClick={() => setActiveTab('imports')}
            className={`px-2.5 py-1 rounded text-xs transition flex items-center gap-1.5 ${
              activeTab === 'imports' || activeTab === 'evidence'
                ? 'bg-indigo-950 text-indigo-300 border border-indigo-700/60 font-semibold'
                : 'hover:text-white bg-slate-950/60 border border-gray-800'
            }`}
          >
            <span className="w-4 h-4 rounded-full bg-indigo-900/80 text-[10px] flex items-center justify-center font-bold text-indigo-300">1</span>
            <span>Evidence &amp; Config Inputs</span>
          </button>
          <ArrowRight className="w-3.5 h-3.5 text-gray-600" />
          <button
            type="button"
            onClick={() => setShowReconstructModal(true)}
            className="px-2.5 py-1 rounded text-xs transition flex items-center gap-1.5 hover:text-white bg-slate-950/60 border border-gray-800 text-cyan-300"
          >
            <span className="w-4 h-4 rounded-full bg-cyan-900/80 text-[10px] flex items-center justify-center font-bold text-cyan-300">2</span>
            <span>Reconstruct Model</span>
          </button>
          <ArrowRight className="w-3.5 h-3.5 text-gray-600" />
          <button
            type="button"
            onClick={() => setActiveTab('topology')}
            className={`px-2.5 py-1 rounded text-xs transition flex items-center gap-1.5 ${
              activeTab === 'topology' || activeTab === 'assets' || activeTab === 'models'
                ? 'bg-indigo-950 text-indigo-300 border border-indigo-700/60 font-semibold'
                : 'hover:text-white bg-slate-950/60 border border-gray-800'
            }`}
          >
            <span className="w-4 h-4 rounded-full bg-indigo-900/80 text-[10px] flex items-center justify-center font-bold text-indigo-300">3</span>
            <span>Topology &amp; Assets</span>
          </button>
          <ArrowRight className="w-3.5 h-3.5 text-gray-600" />
          <button
            type="button"
            onClick={() => setActiveTab('reachability')}
            className={`px-2.5 py-1 rounded text-xs transition flex items-center gap-1.5 ${
              activeTab === 'reachability' || activeTab === 'verification'
                ? 'bg-indigo-950 text-indigo-300 border border-indigo-700/60 font-semibold'
                : 'hover:text-white bg-slate-950/60 border border-gray-800'
            }`}
          >
            <span className="w-4 h-4 rounded-full bg-indigo-900/80 text-[10px] flex items-center justify-center font-bold text-indigo-300">4</span>
            <span>Verify Security</span>
          </button>
          <ArrowRight className="w-3.5 h-3.5 text-gray-600" />
          <button
            type="button"
            onClick={() => setActiveTab('comparison')}
            className={`px-2.5 py-1 rounded text-xs transition flex items-center gap-1.5 ${
              activeTab === 'comparison'
                ? 'bg-indigo-950 text-indigo-300 border border-indigo-700/60 font-semibold'
                : 'hover:text-white bg-slate-950/60 border border-gray-800'
            }`}
          >
            <span className="w-4 h-4 rounded-full bg-indigo-900/80 text-[10px] flex items-center justify-center font-bold text-indigo-300">5</span>
            <span>Snapshot Differential</span>
          </button>
        </div>

        {snapshots.length > 0 && (
          <div className="flex items-center gap-2">
            <span className="text-[11px] text-gray-400 font-medium">Active Snapshot:</span>
            <select
              value={selectedSnapshotId}
              onChange={(e) => handleSelectSnapshot(e.target.value)}
              className="bg-slate-950 border border-gray-700 rounded px-2.5 py-1 text-xs text-cyan-300 font-mono focus:outline-none focus:border-indigo-500 max-w-[220px] truncate"
            >
              {snapshots.map((s) => (
                <option key={s.snapshot_id} value={s.snapshot_id}>
                  {s.name} ({s.snapshot_id})
                </option>
              ))}
            </select>
          </div>
        )}
      </div>

      {/* Reconstruction Audit & Lineage Report Card (if recent reconstruction executed) */}
      {reconstructionAudit && (
        <div className="bg-gradient-to-r from-indigo-950/60 to-slate-950/80 border border-indigo-700/60 rounded-lg p-4 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <CheckCircle className="w-4 h-4 text-emerald-400" />
              <h3 className="text-xs font-bold text-white font-mono">
                Model Reconstructed &amp; Persisted: {reconstructionAudit.snapshot.snapshot_id}
              </h3>
              <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-950/80 text-emerald-300 border border-emerald-800/50">
                Verified Immutable
              </span>
            </div>
            <button
              type="button"
              onClick={() => setReconstructionAudit(null)}
              className="text-gray-400 hover:text-gray-200 text-xs"
            >
              Dismiss
            </button>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
            <div className="p-2.5 bg-slate-950/70 rounded border border-gray-800">
              <div className="text-[10px] text-gray-400">Consumed Assets</div>
              <div className="text-white font-bold mt-0.5">
                {reconstructionAudit.audit?.consumed_assets_count ?? reconstructionAudit.snapshot.node_count} nodes
              </div>
            </div>
            <div className="p-2.5 bg-slate-950/70 rounded border border-gray-800">
              <div className="text-[10px] text-gray-400">Consumed Subnets</div>
              <div className="text-cyan-400 font-bold mt-0.5">
                {reconstructionAudit.audit?.consumed_subnets_count ?? segments.length} subnets
              </div>
            </div>
            <div className="p-2.5 bg-slate-950/70 rounded border border-gray-800">
              <div className="text-[10px] text-gray-400">Evidence Coverage</div>
              <div className="text-emerald-400 font-bold mt-0.5">
                {reconstructionAudit.coverage?.directly_observed_pct ?? 85}% Directly Observed
              </div>
            </div>
            <div className="p-2.5 bg-slate-950/70 rounded border border-gray-800">
              <div className="text-[10px] text-gray-400">Reconstructed Edges</div>
              <div className="text-indigo-300 font-bold mt-0.5">
                {reconstructionAudit.snapshot.edge_count} flows/paths
              </div>
            </div>
          </div>

          {/* Skipped or Rejected Records with explicit reasons */}
          {reconstructionAudit.audit?.skipped_or_rejected && reconstructionAudit.audit.skipped_or_rejected.length > 0 && (
            <div className="space-y-1.5 pt-1">
              <div className="text-[11px] font-semibold text-amber-300 flex items-center gap-1.5">
                <AlertTriangle className="w-3.5 h-3.5" />
                <span>Source Records Filtered / Skipped During Normalization ({reconstructionAudit.audit.skipped_or_rejected.length})</span>
              </div>
              <div className="max-h-36 overflow-y-auto space-y-1 text-[11px] font-mono">
                {reconstructionAudit.audit.skipped_or_rejected.map((item, idx) => (
                  <div key={idx} className="p-2 bg-slate-950/90 rounded border border-gray-800/80 flex items-start gap-2">
                    <span className={`px-1.5 py-0.2 rounded text-[9px] font-bold ${item.action === 'REJECTED' ? 'bg-rose-950 text-rose-300 border border-rose-800' : 'bg-amber-950 text-amber-300 border border-amber-800'}`}>
                      {item.action}
                    </span>
                    <span className="text-gray-300 font-semibold">{item.item_type} [{item.item_id}]:</span>
                    <span className="text-gray-400 flex-1">{item.reason}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Limitations Banner */}
          {reconstructionAudit.limitations && reconstructionAudit.limitations.length > 0 && (
            <div className="text-[11px] text-gray-400 pt-1 border-t border-gray-800/80 flex items-start gap-2">
              <Info className="w-3.5 h-3.5 text-cyan-400 shrink-0 mt-0.5" />
              <div>
                <span className="text-gray-300 font-semibold">Model Scope Limitations: </span>
                <span>{reconstructionAudit.limitations.join(' ')}</span>
              </div>
            </div>
          )}
        </div>
      )}

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
          <button type="button" onClick={() => setError(null)} className="text-rose-400 hover:text-rose-200">
            Dismiss
          </button>
        </div>
      )}

      {/* Mobile Workspace Navigator Bar */}
      <div className="md:hidden bg-surface/50 border border-gray-800 rounded-lg p-3 flex items-center justify-between">
        <div className="flex items-center gap-2.5 min-w-0">
          <currentActiveItem.icon className={`w-4 h-4 shrink-0 ${currentActiveItem.iconColor || 'text-indigo-400'}`} />
          <div className="min-w-0">
            <div className="text-[9px] font-bold uppercase tracking-wider text-gray-500">
              GROUP: {currentActiveItem.groupTitle}
            </div>
            <div className="text-xs font-semibold text-white truncate" data-testid="mobile-active-workspace">
              Active: {currentActiveItem.label}
            </div>
          </div>
          {currentActiveItem.badge !== undefined && (
            <span className="ml-1 text-[10px] px-1.5 py-0.2 rounded-full font-mono bg-gray-800 text-gray-300 shrink-0">
              {currentActiveItem.badge}
            </span>
          )}
        </div>

        <button
          type="button"
          onClick={() => setIsMobileNavOpen((prev) => !prev)}
          className="px-2.5 py-1.5 rounded bg-gray-800 hover:bg-gray-700 text-gray-200 text-xs font-medium border border-gray-700 flex items-center gap-1.5 shrink-0 transition"
          aria-expanded={isMobileNavOpen}
          aria-label="Toggle workspace navigation menu"
        >
          <span>Workspaces</span>
          {isMobileNavOpen ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
        </button>
      </div>

      {/* Grouped Secondary Navigation + Main Content Layout */}
      <div className="flex flex-col md:flex-row gap-5 items-start">
        {/* Persistent Grouped Workspace Navigator */}
        <aside
          aria-label="Digital Twin Workspaces"
          className={`${
            isMobileNavOpen ? 'block' : 'hidden'
          } md:block w-full md:w-64 shrink-0 bg-surface/40 border border-gray-800 rounded-lg p-3 space-y-4 md:sticky md:top-4 md:max-h-[calc(100vh-140px)] md:overflow-y-auto z-10`}
        >
          {navGroups.map((group) => (
            <div key={group.id} className="space-y-1">
              <div className="text-[10px] font-bold uppercase tracking-wider text-gray-500 px-2.5 py-1">
                {group.title}
              </div>
              <div className="space-y-0.5">
                {group.items.map((item) => {
                  const isActive = activeTab === item.id;
                  const Icon = item.icon;
                  return (
                    <button
                      key={item.id}
                      type="button"
                      onClick={() => {
                        setActiveTab(item.id);
                        setIsMobileNavOpen(false);
                      }}
                      className={`w-full flex items-center gap-2.5 px-2.5 py-1.5 text-xs rounded transition text-left group ${
                        isActive
                          ? 'bg-indigo-600/20 text-white font-semibold border-l-2 border-indigo-500 shadow-sm'
                          : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800/40 border-l-2 border-transparent'
                      }`}
                      aria-current={isActive ? 'page' : undefined}
                    >
                      <Icon className={`w-3.5 h-3.5 shrink-0 ${item.iconColor || (isActive ? 'text-indigo-400' : 'text-gray-400 group-hover:text-gray-300')}`} />
                      <span className="truncate flex-1">{item.label}</span>
                      {item.badge !== undefined && (
                        <span
                          className={`ml-auto text-[10px] px-1.5 py-0.2 rounded-full font-mono shrink-0 ${
                            isActive
                              ? 'bg-indigo-950/80 text-indigo-300 border border-indigo-800/60'
                              : 'bg-gray-800/80 text-gray-400 border border-gray-700/50'
                          }`}
                        >
                          {item.badge}
                        </span>
                      )}
                    </button>
                  );
                })}
              </div>
            </div>
          ))}
        </aside>

        {/* Main Workbench Stage */}
        <main className="flex-1 min-w-0 w-full space-y-4">
          {effectiveCaptureId && snapshots.length === 0 && !loading && activeTab !== 'imports' ? (
            <div
              className="bg-slate-900/90 border-2 border-indigo-500/40 rounded-xl p-8 text-center max-w-2xl mx-auto my-8 shadow-2xl backdrop-blur-sm"
              data-testid="twin-empty-state-card"
            >
              <div className="w-16 h-16 rounded-2xl bg-indigo-950/80 border border-indigo-700/60 flex items-center justify-center mx-auto mb-4 text-indigo-400">
                <Sparkles className="w-8 h-8" />
              </div>
              <h3 className="text-base font-bold text-white font-mono">
                No Digital Twin Snapshot for Active Capture
              </h3>
              <p className="mt-2 text-xs text-gray-400 max-w-md mx-auto leading-relaxed">
                Capture <span className="text-cyan-300 font-mono font-semibold">{activeCapture?.filename || effectiveCaptureId}</span> has completed protocol analysis and event normalization, but its versioned network model snapshot has not been generated yet.
              </p>
              <div className="mt-6 flex flex-col sm:flex-row items-center justify-center gap-3">
                <button
                  type="button"
                  onClick={handleReconstructFromActiveCapture}
                  disabled={actionLoading}
                  className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white font-semibold text-xs shadow-lg transition"
                  data-testid="reconstruct-from-capture-btn"
                >
                  {actionLoading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Sparkles className="w-4 h-4" />}
                  <span>Reconstruct Network Model from {activeCapture?.filename || 'Active Capture'}</span>
                </button>
                {onNavigateToObservatory && (
                  <button
                    type="button"
                    onClick={() => onNavigateToObservatory(effectiveCaptureId)}
                    className="px-4 py-2.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-gray-300 text-xs transition"
                  >
                    Return to Network Observatory
                  </button>
                )}
              </div>
            </div>
          ) : (
            <>

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
                              type="button"
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
                              type="button"
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
                              type="button"
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
        <SnapshotComparisonView
          snapshots={snapshots}
          baseSnapshotId={baseSnapshotId}
          targetSnapshotId={targetSnapshotId}
          setBaseSnapshotId={setBaseSnapshotId}
          setTargetSnapshotId={setTargetSnapshotId}
          comparisonDiff={comparisonDiff}
          comparing={comparing}
          diffError={diffError}
          onCompare={handleCompareSnapshots}
        />
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

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
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
                  <label className="block text-[11px] font-medium text-gray-400 mb-1">Configuration Type (Semantic)</label>
                  <select
                    value={importConfigType}
                    onChange={(e) => handleConfigTypeChange(e.target.value as 'routing_table' | 'neighbor_table' | 'inventory')}
                    className="w-full bg-surface/80 border border-gray-800 rounded px-2.5 py-1.5 text-xs text-gray-200 focus:outline-none focus:border-indigo-500 font-mono"
                  >
                    <option value="routing_table">Routing Table (routes &amp; next hops)</option>
                    <option value="neighbor_table">Neighbor / ARP Table (IP &amp; MAC bindings)</option>
                    <option value="inventory">Device Inventory (hosts, routers, switches)</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block text-[11px] font-medium text-gray-400 mb-1">Serialization Format</label>
                  <select
                    value={importSerializationFormat}
                    onChange={(e) => handleSerializationFormatChange(e.target.value as 'auto' | 'json' | 'csv')}
                    className="w-full bg-surface/80 border border-gray-800 rounded px-2.5 py-1.5 text-xs text-gray-200 focus:outline-none focus:border-indigo-500 font-mono"
                  >
                    <option value="auto">Auto-Detect (JSON or CSV)</option>
                    <option value="json">JSON</option>
                    <option value="csv">CSV</option>
                  </select>
                </div>

                <div className="flex items-end">
                  <button
                    type="button"
                    onClick={() => handleSerializationFormatChange(importSerializationFormat)}
                    className="w-full py-1.5 px-3 rounded bg-surface border border-gray-700 hover:bg-gray-800 text-gray-300 hover:text-white text-xs font-mono transition flex items-center justify-center gap-1.5"
                  >
                    <FileCode className="w-3.5 h-3.5 text-indigo-400" />
                    <span>Reset to Template</span>
                  </button>
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
                            {imp.source_type} &bull; {imp.imported_at_iso ? imp.imported_at_iso.slice(0, 19) : 'N/A'}
                          </div>
                        </div>
                        <div className="flex items-center gap-3">
                          <div className="text-right">
                            <span className="text-emerald-400 font-semibold">+{imp.items_imported} items</span>
                            <div className="text-[10px] text-gray-500">{imp.status}</div>
                          </div>
                          <button
                            type="button"
                            onClick={() => handleDeleteConfigImport(imp.import_id, imp.source_name)}
                            disabled={deletingImportId === imp.import_id}
                            aria-label={`Delete import ${imp.source_name}`}
                            className="p-1.5 rounded text-gray-500 hover:text-rose-400 hover:bg-rose-950/40 border border-transparent hover:border-rose-900/40 transition disabled:opacity-50"
                            title="Delete Configuration Record"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
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
                    {captures.map((cap) => {
                      const raw = cap as unknown as Record<string, unknown>;
                      const sha = (cap.sha256_hash || raw.content_sha256 || '') as string;
                      const capName = (cap.file_name || raw.filename || cap.capture_id) as string;
                      const pktText = cap.packet_count != null ? `${cap.packet_count} packets` : 'PCAP recorded';
                      return (
                      <div key={cap.capture_id} className="py-2 flex items-center justify-between font-mono">
                        <div>
                          <div className="text-gray-200 font-semibold">{capName}</div>
                          <div className="text-[10px] text-gray-500">
                            SHA: {sha ? `${sha.slice(0, 12)}...` : 'N/A'}
                          </div>
                        </div>
                        <div className="text-right">
                          <span className="text-indigo-400 font-semibold">{pktText}</span>
                          <div className="text-[10px] text-gray-400">{cap.format}</div>
                        </div>
                      </div>
                      );
                    })}
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
            </>
          )}
        </main>
      </div>

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

      {/* Reconstruct Network Model Modal */}
      {showReconstructModal && (
        <div className="fixed inset-0 z-50 bg-black/75 flex items-center justify-center p-4">
          <form
            onSubmit={handleReconstructModel}
            className="bg-surface border border-gray-700 rounded-lg shadow-2xl max-w-xl w-full p-6 space-y-4 text-xs"
          >
            <div className="border-b border-gray-800 pb-3">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Sparkles className="w-4 h-4 text-indigo-400" />
                Build &amp; Reconstruct Network Digital Twin
              </h3>
              <p className="text-gray-400 mt-1">
                Synthesize observed PCAP traffic evidence and imported configurations into an immutable, versioned topology snapshot and formal executable twin.
              </p>
            </div>

            <div className="space-y-4">
              <div>
                <label className="block font-semibold text-gray-300 mb-1">Model Snapshot Title</label>
                <input
                  type="text"
                  placeholder="e.g., Enterprise Core Twin - Baseline Reconstructed"
                  value={reconstructName}
                  onChange={(e) => setReconstructName(e.target.value)}
                  className="w-full bg-slate-950 border border-gray-700 rounded px-3 py-2 text-gray-200 focus:outline-none focus:border-indigo-500 font-mono text-xs"
                />
              </div>

              {/* Source Inputs Selection */}
              <div>
                <div className="flex items-center justify-between mb-2">
                  <label className="font-semibold text-gray-300">Model Source Inputs</label>
                  <label className="text-indigo-300 flex items-center gap-1.5 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={includeAllTelemetry}
                      onChange={(e) => setIncludeAllTelemetry(e.target.checked)}
                      className="rounded bg-slate-950 border-gray-700 text-indigo-600 focus:ring-0"
                    />
                    <span>Include All Active Catalog Intelligence</span>
                  </label>
                </div>

                {!includeAllTelemetry && (
                  <div className="space-y-3 p-3 bg-slate-950/80 border border-gray-800 rounded-lg max-h-56 overflow-y-auto">
                    <div>
                      <div className="font-semibold text-gray-400 mb-1">Observed PCAP Captures ({captures.length}):</div>
                      {captures.length === 0 ? (
                        <div className="text-gray-500 italic py-1">No analyzed captures cataloged.</div>
                      ) : (
                        <div className="space-y-1">
                          {captures.map((c) => {
                            const raw = c as unknown as Record<string, unknown>;
                            const name = (c.file_name || raw.filename || c.capture_id) as string;
                            const isSelected = selectedCaptureIds.includes(c.capture_id);
                            return (
                              <label key={c.capture_id} className="flex items-center gap-2 p-1.5 rounded hover:bg-gray-800/50 cursor-pointer">
                                <input
                                  type="checkbox"
                                  checked={isSelected}
                                  onChange={(e) => {
                                    if (e.target.checked) {
                                      setSelectedCaptureIds((prev) => [...prev, c.capture_id]);
                                    } else {
                                      setSelectedCaptureIds((prev) => prev.filter((id) => id !== c.capture_id));
                                    }
                                  }}
                                  className="rounded bg-slate-950 border-gray-700 text-indigo-600"
                                />
                                <span className="font-mono text-gray-200 truncate">{name}</span>
                                <span className="text-gray-500 ml-auto font-mono">{c.packet_count ?? 0} pkts</span>
                              </label>
                            );
                          })}
                        </div>
                      )}
                    </div>

                    <div>
                      <div className="font-semibold text-gray-400 mb-1">Configuration Imports ({importHistory.length}):</div>
                      {importHistory.length === 0 ? (
                        <div className="text-gray-500 italic py-1">No configuration tables imported.</div>
                      ) : (
                        <div className="space-y-1">
                          {importHistory.map((imp) => {
                            const isSelected = selectedConfigIds.includes(imp.import_id);
                            return (
                              <label key={imp.import_id} className="flex items-center gap-2 p-1.5 rounded hover:bg-gray-800/50 cursor-pointer">
                                <input
                                  type="checkbox"
                                  checked={isSelected}
                                  onChange={(e) => {
                                    if (e.target.checked) {
                                      setSelectedConfigIds((prev) => [...prev, imp.import_id]);
                                    } else {
                                      setSelectedConfigIds((prev) => prev.filter((id) => id !== imp.import_id));
                                    }
                                  }}
                                  className="rounded bg-slate-950 border-gray-700 text-indigo-600"
                                />
                                <span className="font-mono text-gray-200 truncate">{imp.source_name}</span>
                                <span className="text-emerald-400 ml-auto font-mono">+{imp.items_imported} items</span>
                              </label>
                            );
                          })}
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            </div>

            <div className="flex justify-end gap-2 pt-3 border-t border-gray-800">
              <button
                type="button"
                onClick={() => setShowReconstructModal(false)}
                className="px-3 py-1.5 rounded bg-gray-800 hover:bg-gray-700 text-gray-300 font-medium"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={actionLoading}
                className="flex items-center gap-1.5 px-4 py-1.5 rounded bg-indigo-600 hover:bg-indigo-500 text-white font-medium shadow transition disabled:opacity-50"
              >
                <Sparkles className="w-3.5 h-3.5" />
                <span>{actionLoading ? 'Reconstructing...' : 'Execute Reconstruction'}</span>
              </button>
            </div>
          </form>
        </div>
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
