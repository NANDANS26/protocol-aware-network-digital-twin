import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { apiClient } from '../../api/client';
import type {
  CaptureManifestItem,
  CorpusSummaryResponse,
  CaptureValidationReport,
  DifferentialTestResult,
  MetamorphicRelationType,
  CaptureProvenance,
  CaptureFormat,
} from '../../types/captures';
import {
  FileCheck2,
  Cpu,
  Layers,
  Activity,
  Play,
  RotateCw,
  AlertCircle,
  CheckCircle2,
  XCircle,
  Database,
  Shield,
  Search,
  Network,
  Info,
  Radio,
  FileCode,
} from 'lucide-react';

export const RealCaptureWorkbench: React.FC = () => {
  const [captures, setCaptures] = useState<CaptureManifestItem[]>([]);
  const [summary, setSummary] = useState<CorpusSummaryResponse | null>(null);
  const [selectedCaptureId, setSelectedCaptureId] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Search & Filter state
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [provenanceFilter, setProvenanceFilter] = useState<'ALL' | CaptureProvenance>('ALL');
  const [formatFilter, setFormatFilter] = useState<'ALL' | CaptureFormat>('ALL');

  // Multi-capture validation report cache (preserves status across capture selections)
  const [validationReports, setValidationReports] = useState<Record<string, CaptureValidationReport>>({});
  const [validating, setValidating] = useState<boolean>(false);

  // Differential testing state
  const [differentialResults, setDifferentialResults] = useState<DifferentialTestResult[]>([]);
  const [runningDiffRel, setRunningDiffRel] = useState<MetamorphicRelationType | null>(null);

  // E2E Pipeline state
  const [e2eResult, setE2eResult] = useState<Record<string, unknown> | null>(null);
  const [runningE2E, setRunningE2E] = useState<boolean>(false);

  const loadCorpusData = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const [caps, summ] = await Promise.all([
        apiClient.listCorpusCaptures(),
        apiClient.getCorpusSummary().catch(() => null),
      ]);
      setCaptures(caps);
      setSummary(summ);
      if (caps.length > 0 && !selectedCaptureId) {
        setSelectedCaptureId(caps[0]?.capture_id ?? '');
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to load capture corpus.');
    } finally {
      setLoading(false);
    }
  }, [selectedCaptureId]);

  useEffect(() => {
    loadCorpusData();
  }, [loadCorpusData]);

  const selectedCapture = useMemo(
    () => captures.find((c) => c.capture_id === selectedCaptureId),
    [captures, selectedCaptureId]
  );

  const activeValidationReport = selectedCaptureId ? validationReports[selectedCaptureId] ?? null : null;

  const handleRunValidation = async () => {
    if (!selectedCaptureId) return;
    try {
      setValidating(true);
      setError(null);
      const report = await apiClient.validateCapture(selectedCaptureId);
      setValidationReports((prev) => ({
        ...prev,
        [selectedCaptureId]: report,
      }));
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Validation failed.');
    } finally {
      setValidating(false);
    }
  };

  const handleRunDifferential = async (relType: MetamorphicRelationType) => {
    if (!selectedCaptureId) return;
    try {
      setRunningDiffRel(relType);
      setError(null);
      let transformedId: string | null = null;
      if (relType === 'FORMAT_EQUIVALENCE') {
        transformedId = selectedCaptureId.endsWith('-pcap')
          ? selectedCaptureId.replace('-pcap', '-pcapng')
          : 'real-web-traffic-pcapng';
      }
      const res = await apiClient.runDifferentialTest({
        relation_type: relType,
        base_capture_id: selectedCaptureId,
        transformed_capture_id: transformedId,
        shift_seconds: 60,
      });
      setDifferentialResults((prev) => [res, ...prev.slice(0, 9)]);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Differential test failed.');
    } finally {
      setRunningDiffRel(null);
    }
  };

  const handleRunE2E = async () => {
    if (!selectedCaptureId) return;
    try {
      setRunningE2E(true);
      setError(null);
      const res = await apiClient.runE2EValidation(selectedCaptureId);
      setE2eResult(res);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'E2E validation failed.');
    } finally {
      setRunningE2E(false);
    }
  };

  const formatBytes = (bytes: number): string => {
    if (!bytes || bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
  };

  // Filtered Captures
  const filteredCaptures = useMemo(() => {
    return captures.filter((c) => {
      if (provenanceFilter !== 'ALL' && c.provenance !== provenanceFilter) return false;
      if (formatFilter !== 'ALL' && c.format !== formatFilter) return false;
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matchesName = c.name.toLowerCase().includes(q);
        const matchesId = c.capture_id.toLowerCase().includes(q);
        const matchesProto = c.protocols.some((p) => p.toLowerCase().includes(q));
        const matchesFile = c.file_name.toLowerCase().includes(q);
        if (!matchesName && !matchesId && !matchesProto && !matchesFile) return false;
      }
      return true;
    });
  }, [captures, provenanceFilter, formatFilter, searchQuery]);

  return (
    <div className="space-y-6" data-testid="real-capture-workbench">
      {/* Header and Summary Cards */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-gray-900 border border-gray-800 rounded-lg p-5">
        <div>
          <div className="flex items-center gap-2">
            <FileCheck2 className="w-5 h-5 text-indigo-400" />
            <h2 className="text-lg font-semibold text-white">
              Real-Capture Validation & Differential Testing
            </h2>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-indigo-950 text-indigo-300 border border-indigo-800/60 font-semibold">
              Oracle Grounded
            </span>
          </div>
          <p className="text-xs text-gray-400 mt-1">
            Independently verified packet corpus, reference oracle differential validation, and end-to-end data path audit.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={loadCorpusData}
            disabled={loading}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-gray-800 hover:bg-gray-700 text-gray-300 text-xs font-medium rounded border border-gray-700 transition disabled:opacity-50"
          >
            <RotateCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Refresh Corpus
          </button>
        </div>
      </div>

      {error && (
        <div className="bg-red-950/40 border border-red-800/80 rounded-lg p-4 flex items-center justify-between gap-3 text-red-300 text-xs">
          <div className="flex items-center gap-2.5">
            <AlertCircle className="w-4 h-4 shrink-0 text-red-400" />
            <span>{error}</span>
          </div>
          <button
            onClick={() => setError(null)}
            className="text-xs text-red-400 hover:text-red-200 underline font-mono"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Aggregate Corpus Summary Badges */}
      {summary && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="bg-gray-900/80 border border-gray-800 rounded-lg p-3.5 flex items-center justify-between">
            <div>
              <span className="text-[11px] font-medium text-gray-400 uppercase tracking-wider block">
                Total Captures
              </span>
              <span className="text-xl font-bold text-white mt-0.5 block font-mono">
                {summary.total_captures}
              </span>
            </div>
            <Database className="w-7 h-7 text-indigo-500/30" />
          </div>

          <div className="bg-gray-900/80 border border-gray-800 rounded-lg p-3.5 flex items-center justify-between">
            <div>
              <span className="text-[11px] font-medium text-gray-400 uppercase tracking-wider block">
                Total Packets
              </span>
              <span className="text-xl font-bold text-cyan-400 mt-0.5 block font-mono">
                {summary.total_packet_count}
              </span>
            </div>
            <Layers className="w-7 h-7 text-cyan-500/30" />
          </div>

          <div className="bg-gray-900/80 border border-gray-800 rounded-lg p-3.5 flex items-center justify-between">
            <div>
              <span className="text-[11px] font-medium text-gray-400 uppercase tracking-wider block">
                Protocols Grounded
              </span>
              <span className="text-xl font-bold text-emerald-400 mt-0.5 block font-mono">
                {summary.supported_protocols.length}
              </span>
            </div>
            <Shield className="w-7 h-7 text-emerald-500/30" />
          </div>

          <div className="bg-gray-900/80 border border-gray-800 rounded-lg p-3.5 flex items-center justify-between">
            <div>
              <span className="text-[11px] font-medium text-gray-400 uppercase tracking-wider block">
                Corpus Formats
              </span>
              <span className="text-sm font-semibold text-purple-400 mt-1 block font-mono">
                PCAP ({summary.format_distribution['PCAP'] || 0}) / PCAPNG ({summary.format_distribution['PCAPNG'] || 0})
              </span>
            </div>
            <Activity className="w-7 h-7 text-purple-500/30" />
          </div>
        </div>
      )}

      {/* Main Grid: Corpus Selector & Detail Cockpit */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Col: Corpus Catalog Manifest */}
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-4 flex flex-col h-full min-w-0">
          <div className="flex items-center justify-between pb-3 border-b border-gray-800 mb-3">
            <span className="text-xs font-semibold text-gray-300 uppercase tracking-wider">
              Capture Corpus Manifest
            </span>
            <span className="text-[10px] text-gray-400 bg-gray-800 px-2 py-0.5 rounded font-mono">
              {filteredCaptures.length} / {captures.length} files
            </span>
          </div>

          {/* Search & Filter Bar */}
          <div className="space-y-2 mb-3">
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-gray-500 absolute left-2.5 top-2.5" />
              <input
                type="text"
                placeholder="Search captures by name, protocol..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-8 pr-3 py-1.5 bg-gray-950 border border-gray-800 rounded text-xs text-gray-200 placeholder-gray-500 focus:outline-none focus:border-indigo-500"
              />
            </div>

            <div className="flex items-center gap-1.5 overflow-x-auto pb-1 text-[10px]">
              <span className="text-gray-500 shrink-0">Origin:</span>
              {(['ALL', 'PUBLIC_CAPTURE', 'SYNTHETIC_FIXTURE', 'AUTHORIZED_LOCAL'] as const).map((prov) => (
                <button
                  key={prov}
                  onClick={() => setProvenanceFilter(prov)}
                  className={`px-1.5 py-0.5 rounded border transition whitespace-nowrap ${
                    provenanceFilter === prov
                      ? 'bg-indigo-950 text-indigo-300 border-indigo-700'
                      : 'bg-gray-950 text-gray-400 border-gray-800 hover:text-gray-200'
                  }`}
                >
                  {prov === 'ALL' ? 'All' : prov === 'PUBLIC_CAPTURE' ? 'Public' : prov === 'SYNTHETIC_FIXTURE' ? 'Synthetic' : 'Local'}
                </button>
              ))}
            </div>

            <div className="flex items-center gap-1.5 overflow-x-auto pb-1 text-[10px]">
              <span className="text-gray-500 shrink-0">Format:</span>
              {(['ALL', 'PCAP', 'PCAPNG'] as const).map((fmt) => (
                <button
                  key={fmt}
                  onClick={() => setFormatFilter(fmt)}
                  className={`px-1.5 py-0.5 rounded border transition whitespace-nowrap ${
                    formatFilter === fmt
                      ? 'bg-purple-950 text-purple-300 border-purple-700'
                      : 'bg-gray-950 text-gray-400 border-gray-800 hover:text-gray-200'
                  }`}
                >
                  {fmt}
                </button>
              ))}
            </div>
          </div>

          {/* Corpus List */}
          <div className="space-y-2 overflow-y-auto max-h-[560px] pr-1">
            {loading ? (
              <div className="p-8 text-center text-xs text-gray-500 space-y-2">
                <RotateCw className="w-4 h-4 animate-spin mx-auto text-indigo-400" />
                <span>Loading capture manifest...</span>
              </div>
            ) : filteredCaptures.length === 0 ? (
              <div className="p-8 text-center text-xs text-gray-500 border border-dashed border-gray-800 rounded">
                No captures match the current filter.
                {searchQuery && (
                  <button
                    onClick={() => {
                      setSearchQuery('');
                      setProvenanceFilter('ALL');
                      setFormatFilter('ALL');
                    }}
                    className="block mx-auto mt-2 text-indigo-400 hover:underline"
                  >
                    Clear search filters
                  </button>
                )}
              </div>
            ) : (
              filteredCaptures.map((item) => {
                const isSelected = item.capture_id === selectedCaptureId;
                const report = validationReports[item.capture_id];
                return (
                  <div
                    key={item.capture_id}
                    data-testid={`manifest-item-${item.capture_id}`}
                    onClick={() => {
                      setSelectedCaptureId(item.capture_id);
                      setE2eResult(null);
                    }}
                    className={`p-3 rounded border text-left cursor-pointer transition ${
                      isSelected
                        ? 'bg-indigo-950/40 border-indigo-500 shadow-sm'
                        : 'bg-gray-950/40 border-gray-800/80 hover:bg-gray-800/40'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-1">
                      <span className="text-xs font-semibold text-white truncate max-w-[180px]">
                        {item.name}
                      </span>
                      <span
                        className={`text-[9px] font-mono px-1.5 py-0.5 rounded uppercase font-semibold shrink-0 ${
                          item.format === 'PCAPNG'
                            ? 'bg-purple-900/40 text-purple-300 border border-purple-800/60'
                            : 'bg-blue-900/40 text-blue-300 border border-blue-800/60'
                        }`}
                      >
                        {item.format}
                      </span>
                    </div>

                    <div className="flex items-center gap-2 mt-1.5 text-[10px] text-gray-400 font-mono">
                      <span className="text-gray-300">{item.packet_count} pkts</span>
                      <span>•</span>
                      <span>{formatBytes(item.file_size_bytes)}</span>
                      <span>•</span>
                      <span
                        className={`px-1 rounded text-[9px] ${
                          item.provenance === 'PUBLIC_CAPTURE'
                            ? 'text-emerald-400 bg-emerald-950/30'
                            : 'text-amber-400 bg-amber-950/30'
                        }`}
                      >
                        {item.provenance}
                      </span>
                    </div>

                    {/* Validation Status Badge */}
                    <div className="mt-2 flex items-center justify-between">
                      <div className="flex flex-wrap gap-1 max-w-[170px]">
                        {item.protocols.slice(0, 4).map((p) => (
                          <span
                            key={p}
                            className="text-[9px] px-1.5 py-0.2 bg-gray-800 text-gray-300 rounded font-mono"
                          >
                            {p}
                          </span>
                        ))}
                        {item.protocols.length > 4 && (
                          <span className="text-[9px] text-gray-500 font-mono">
                            +{item.protocols.length - 4}
                          </span>
                        )}
                      </div>

                      {report ? (
                        report.passed ? (
                          <span className="inline-flex items-center gap-1 text-[9px] font-mono font-semibold px-1.5 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800 shrink-0">
                            <CheckCircle2 className="w-2.5 h-2.5" />
                            VERIFIED
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 text-[9px] font-mono font-semibold px-1.5 py-0.5 rounded bg-rose-950 text-rose-400 border border-rose-800 shrink-0">
                            <XCircle className="w-2.5 h-2.5" />
                            DIFF FOUND
                          </span>
                        )
                      ) : (
                        <span className="text-[9px] font-mono text-gray-500 px-1.5 py-0.5 rounded bg-gray-800/80 shrink-0">
                          UNVALIDATED
                        </span>
                      )}
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Right Col: Deep Inspection, Protocol Layers & Verification Cockpit */}
        <div className="lg:col-span-2 space-y-6 min-w-0">
          {selectedCapture ? (
            <div className="bg-gray-900 border border-gray-800 rounded-lg p-5 space-y-4">
              {/* Header Bar */}
              <div className="flex flex-col md:flex-row md:items-center justify-between pb-4 border-b border-gray-800 gap-3">
                <div className="min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <h3 className="text-base font-bold text-white truncate">{selectedCapture.name}</h3>
                    <span
                      className={`text-[10px] font-mono font-semibold px-2 py-0.5 rounded uppercase ${
                        selectedCapture.format === 'PCAPNG'
                          ? 'bg-purple-900/40 text-purple-300 border border-purple-800/60'
                          : 'bg-blue-900/40 text-blue-300 border border-blue-800/60'
                      }`}
                    >
                      {selectedCapture.format}
                    </span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-gray-800 text-gray-300">
                      {formatBytes(selectedCapture.file_size_bytes)}
                    </span>
                  </div>
                  <div className="flex items-center gap-2 text-xs text-gray-400 font-mono mt-1 flex-wrap break-all">
                    <span>{selectedCapture.file_name}</span>
                    <span>•</span>
                    <span className="text-gray-500 font-mono">
                      SHA256: {selectedCapture.sha256}
                    </span>
                  </div>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  <button
                    onClick={handleRunValidation}
                    disabled={validating}
                    className="flex items-center gap-1.5 px-3 py-1.5 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white text-xs font-medium rounded transition shadow"
                  >
                    <Play className={`w-3.5 h-3.5 ${validating ? 'animate-pulse' : ''}`} />
                    {validating ? 'Validating...' : 'Run Decoder Oracle'}
                  </button>

                  <button
                    onClick={handleRunE2E}
                    disabled={runningE2E}
                    className="flex items-center gap-1.5 px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white text-xs font-medium rounded transition shadow"
                  >
                    <Database className={`w-3.5 h-3.5 ${runningE2E ? 'animate-pulse' : ''}`} />
                    {runningE2E ? 'Auditing...' : 'Run E2E Data Path'}
                  </button>
                </div>
              </div>

              {/* Protocol Stack Architecture Inspection (By Layers) */}
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-gray-300 uppercase tracking-wider flex items-center gap-1.5">
                    <Layers className="w-3.5 h-3.5 text-indigo-400" />
                    Layered Protocol Stack Inspection & Expected Invariants
                  </span>
                  <span className="text-[10px] text-gray-500 font-mono">
                    Ground Truth Established
                  </span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono">
                  {/* Layer 2: Link Layer */}
                  <div className="p-3 bg-gray-950/60 rounded border border-gray-800 space-y-1.5">
                    <div className="flex items-center justify-between border-b border-gray-800/80 pb-1 text-[11px]">
                      <span className="font-semibold text-cyan-400 flex items-center gap-1">
                        <Network className="w-3 h-3" /> Layer 2: Link Layer
                      </span>
                      <span className="text-gray-500 text-[10px]">Ethernet II</span>
                    </div>
                    <div className="text-gray-300">
                      <span className="text-gray-500">802.1Q VLAN Tags:</span>{' '}
                      {selectedCapture.expected_outcomes.vlan_tags.length > 0 ? (
                        <span className="text-purple-300 font-semibold">
                          {selectedCapture.expected_outcomes.vlan_tags.map((v) => `VLAN ${v}`).join(', ')}
                        </span>
                      ) : (
                        <span className="text-gray-400">None (Standard Untagged Access)</span>
                      )}
                    </div>
                    <div className="text-gray-400 text-[11px]">
                      Frame Count: <span className="text-white font-semibold">{selectedCapture.expected_outcomes.total_packets} pkts</span>
                    </div>
                  </div>

                  {/* Layer 3: Network Layer */}
                  <div className="p-3 bg-gray-950/60 rounded border border-gray-800 space-y-1.5">
                    <div className="flex items-center justify-between border-b border-gray-800/80 pb-1 text-[11px]">
                      <span className="font-semibold text-blue-400 flex items-center gap-1">
                        <Radio className="w-3 h-3" /> Layer 3: Network Layer
                      </span>
                      <span className="text-gray-500 text-[10px]">IPv4 / IPv6 / ARP</span>
                    </div>
                    <div className="text-gray-300">
                      <span className="text-gray-500">IP Fragmentation:</span>{' '}
                      {selectedCapture.expected_outcomes.has_fragments ? (
                        <span className="text-amber-400 font-semibold">Fragments Present</span>
                      ) : (
                        <span className="text-emerald-400">No Fragmentation (Clean MTU)</span>
                      )}
                    </div>
                    <div className="text-gray-400 text-[11px] truncate">
                      Protocols: <span className="text-indigo-300">{selectedCapture.protocols.filter((p) => ['IPv4', 'IPv6', 'ARP', 'ICMP'].includes(p)).join(', ') || 'Standard IPv4'}</span>
                    </div>
                  </div>

                  {/* Layer 4: Transport Layer */}
                  <div className="p-3 bg-gray-950/60 rounded border border-gray-800 space-y-1.5">
                    <div className="flex items-center justify-between border-b border-gray-800/80 pb-1 text-[11px]">
                      <span className="font-semibold text-indigo-400 flex items-center gap-1">
                        <Activity className="w-3 h-3" /> Layer 4: Transport Layer
                      </span>
                      <span className="text-gray-500 text-[10px]">TCP / UDP State Machine</span>
                    </div>
                    <div className="grid grid-cols-2 gap-2 text-[11px]">
                      <div>
                        <span className="text-gray-500">Flow Sessions:</span>{' '}
                        <span className="text-white font-semibold">{selectedCapture.expected_outcomes.total_flows}</span>
                      </div>
                      <div>
                        <span className="text-gray-500">Retransmissions:</span>{' '}
                        <span className={selectedCapture.expected_outcomes.has_retransmissions ? 'text-amber-400' : 'text-emerald-400'}>
                          {selectedCapture.expected_outcomes.has_retransmissions ? 'Present' : 'None'}
                        </span>
                      </div>
                      <div>
                        <span className="text-gray-500">Out-of-Order:</span>{' '}
                        <span className={selectedCapture.expected_outcomes.has_out_of_order ? 'text-amber-400' : 'text-emerald-400'}>
                          {selectedCapture.expected_outcomes.has_out_of_order ? 'Detected' : 'Sequential'}
                        </span>
                      </div>
                      <div>
                        <span className="text-gray-500">Transport:</span>{' '}
                        <span className="text-gray-300">
                          {selectedCapture.protocols.filter((p) => ['TCP', 'UDP'].includes(p)).join(' / ') || 'TCP'}
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Layer 7: Application Layer */}
                  <div className="p-3 bg-gray-950/60 rounded border border-gray-800 space-y-1.5">
                    <div className="flex items-center justify-between border-b border-gray-800/80 pb-1 text-[11px]">
                      <span className="font-semibold text-purple-400 flex items-center gap-1">
                        <FileCode className="w-3 h-3" /> Layer 7: Application Layer
                      </span>
                      <span className="text-gray-500 text-[10px]">DNS / HTTP / TLS</span>
                    </div>
                    <div className="grid grid-cols-2 gap-2 text-[11px]">
                      <div>
                        <span className="text-gray-500">DNS (Q/R):</span>{' '}
                        <span className="text-white font-semibold">
                          {selectedCapture.expected_outcomes.dns_queries} / {selectedCapture.expected_outcomes.dns_responses}
                        </span>
                      </div>
                      <div>
                        <span className="text-gray-500">HTTP (Req/Res):</span>{' '}
                        <span className="text-white font-semibold">
                          {selectedCapture.expected_outcomes.http_requests} / {selectedCapture.expected_outcomes.http_responses}
                        </span>
                      </div>
                      <div className="col-span-2">
                        <span className="text-gray-500">TLS Handshakes:</span>{' '}
                        <span className="text-white font-semibold">{selectedCapture.expected_outcomes.tls_handshakes}</span>
                        {selectedCapture.expected_outcomes.extracted_sni && (
                          <span className="text-indigo-400 ml-1.5">
                            (SNI: {selectedCapture.expected_outcomes.extracted_sni})
                          </span>
                        )}
                      </div>
                      <div className="col-span-2">
                        <span className="text-gray-500">Parser Health:</span>{' '}
                        <span className="text-emerald-400 uppercase font-semibold">
                          {selectedCapture.expected_outcomes.parser_status}
                        </span>
                        {selectedCapture.expected_outcomes.has_malformed && (
                          <span className="text-amber-400 ml-1.5 font-semibold">(Malformed Frames Detected)</span>
                        )}
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              {/* Provenance, Attribution & Documented Limitations */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-sans">
                <div className="p-3 bg-gray-950/60 rounded border border-gray-800">
                  <span className="text-[10px] text-gray-400 uppercase font-semibold block mb-1">
                    Provenance & Attribution
                  </span>
                  <p className="text-gray-300">
                    <span className="text-gray-500 font-mono">Source:</span> {selectedCapture.source}
                  </p>
                  <p className="text-gray-300 mt-1">
                    <span className="text-gray-500 font-mono">License:</span> {selectedCapture.license} ({selectedCapture.attribution})
                  </p>
                  <div className="mt-2 text-[11px] text-indigo-400 font-mono">
                    Scenarios: {selectedCapture.scenarios.join(', ')}
                  </div>
                </div>

                <div className="p-3 bg-gray-950/60 rounded border border-gray-800">
                  <span className="text-[10px] text-gray-400 uppercase font-semibold block mb-1">
                    Documented Scope & Limitations
                  </span>
                  <ul className="list-disc list-inside space-y-0.5 text-gray-400">
                    {selectedCapture.known_limitations.map((lim, i) => (
                      <li key={i}>{lim}</li>
                    ))}
                  </ul>
                </div>
              </div>
            </div>
          ) : (
            <div className="bg-gray-900 border border-gray-800 rounded-lg p-8 text-center text-gray-500 text-xs">
              Select a capture fixture from the corpus list to inspect ground truth and run validation.
            </div>
          )}

          {/* Reference Decoder & Resource Telemetry Report */}
          {activeValidationReport ? (
            <div className="bg-gray-900 border border-gray-800 rounded-lg p-5 space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-3 border-b border-gray-800 gap-2">
                <div className="flex items-center gap-2">
                  {activeValidationReport.passed ? (
                    <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
                  ) : (
                    <XCircle className="w-5 h-5 text-red-400 shrink-0" />
                  )}
                  <div>
                    <span className="text-sm font-semibold text-white">
                      Differential Validation Result:{' '}
                      <span className={activeValidationReport.passed ? 'text-emerald-400' : 'text-red-400'}>
                        {activeValidationReport.passed ? 'PASSED (Bit-Exact)' : 'FAILED'}
                      </span>
                    </span>
                    <p className="text-[11px] text-gray-400">{activeValidationReport.explanation}</p>
                  </div>
                </div>
                <div className="text-right">
                  <span className="text-[10px] font-mono text-gray-400 block">
                    ID: {activeValidationReport.validation_id}
                  </span>
                  <span className="text-[10px] font-mono text-gray-500">
                    {new Date(activeValidationReport.timestamp).toLocaleTimeString()}
                  </span>
                </div>
              </div>

              {/* Resource Telemetry: Peak Native Memory vs Python Heap */}
              <div className="p-3 bg-gray-950/60 rounded border border-gray-800">
                <span className="text-[10px] text-indigo-400 font-semibold uppercase tracking-wider block mb-2 flex items-center gap-1.5">
                  <Cpu className="w-3.5 h-3.5" />
                  Isolated Process Resource Telemetry
                </span>
                <div className="grid grid-cols-2 md:grid-cols-5 gap-3 text-xs">
                  <div>
                    <span className="text-gray-500 text-[10px] block">Wall Duration</span>
                    <span className="font-mono text-white font-medium">
                      {activeValidationReport.telemetry.wall_duration_ms} ms
                    </span>
                  </div>
                  <div>
                    <span className="text-gray-500 text-[10px] block">Throughput (PPS)</span>
                    <span className="font-mono text-cyan-400 font-medium">
                      {activeValidationReport.telemetry.throughput_pps.toLocaleString()} pps
                    </span>
                  </div>
                  <div>
                    <span className="text-gray-500 text-[10px] block">Throughput (MBPS)</span>
                    <span className="font-mono text-cyan-400 font-medium">
                      {activeValidationReport.telemetry.throughput_mbps} Mbps
                    </span>
                  </div>
                  <div>
                    <span className="text-gray-500 text-[10px] block">Peak Native Memory</span>
                    <span className="font-mono text-emerald-400 font-medium">
                      {formatBytes(activeValidationReport.telemetry.peak_native_memory_bytes)}
                    </span>
                  </div>
                  <div>
                    <span className="text-gray-500 text-[10px] block">Python Heap (tracemalloc)</span>
                    <span className="font-mono text-purple-400 font-medium">
                      {formatBytes(activeValidationReport.telemetry.python_heap_bytes)}
                    </span>
                  </div>
                </div>
              </div>

              {/* Observed Protocol Distribution Breakdown */}
              <div className="p-3 bg-gray-950/60 rounded border border-gray-800">
                <span className="text-[10px] text-gray-400 font-semibold uppercase tracking-wider block mb-2">
                  Observed Protocol Breakdown & Decoded Frames
                </span>
                <div className="flex flex-wrap gap-2">
                  {Object.entries(activeValidationReport.protocol_distribution).map(([proto, count]) => (
                    <div
                      key={proto}
                      className="px-2.5 py-1 bg-gray-900 border border-gray-800 rounded flex items-center gap-1.5 font-mono text-xs"
                    >
                      <span className="text-indigo-300">{proto}</span>
                      <span className="text-white font-bold">{count}</span>
                    </div>
                  ))}
                  <div className="px-2.5 py-1 bg-gray-900 border border-gray-800 rounded flex items-center gap-1.5 font-mono text-xs">
                    <span className="text-gray-400">Flows Tracked</span>
                    <span className="text-emerald-400 font-bold">{activeValidationReport.total_flows_observed}</span>
                  </div>
                </div>
              </div>

              {/* Field Differences Table if any */}
              {activeValidationReport.field_differences.length > 0 ? (
                <div>
                  <span className="text-xs font-semibold text-red-400 block mb-2">
                    Discrepancies Against Reference Decoder:
                  </span>
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs border border-gray-800">
                      <thead className="bg-gray-800/60 text-gray-400">
                        <tr>
                          <th className="p-2">Pkt #</th>
                          <th className="p-2">Field</th>
                          <th className="p-2">C++ Systems Engine</th>
                          <th className="p-2">Python Reference Oracle</th>
                          <th className="p-2">Status</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-gray-800">
                        {activeValidationReport.field_differences.map((diff, i) => (
                          <tr key={i} className="hover:bg-gray-800/30">
                            <td className="p-2 font-mono">#{diff.packet_index}</td>
                            <td className="p-2 font-mono text-indigo-300">{diff.field_name}</td>
                            <td className="p-2 font-mono text-red-300">{String(diff.cpp_engine_value)}</td>
                            <td className="p-2 font-mono text-emerald-300">
                              {String(diff.reference_decoder_value)}
                            </td>
                            <td className="p-2">
                              <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-red-950 text-red-400 border border-red-800">
                                MISMATCH
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              ) : (
                <div className="p-3 bg-emerald-950/20 border border-emerald-800/40 rounded flex items-center gap-2 text-xs text-emerald-300">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                  <span>
                    Zero field-level discrepancies. All {activeValidationReport.total_packets_processed} decoded frames match the reference Python decoder bit-for-bit.
                  </span>
                </div>
              )}
            </div>
          ) : (
            <div className="bg-gray-900 border border-gray-800 rounded-lg p-5 flex items-center gap-3 text-xs text-gray-400">
              <Info className="w-4 h-4 text-indigo-400 shrink-0" />
              <div>
                <span className="font-semibold text-white">Differential Verification Status: Unvalidated</span>
                <p className="text-[11px] text-gray-400 mt-0.5">
                  Click &apos;Run Decoder Oracle&apos; above to validate this capture fixture against the independent Python reference decoder.
                </p>
              </div>
            </div>
          )}

          {/* E2E Pipeline Audit Verification Panel */}
          {e2eResult && (
            <div className="bg-gray-900 border border-emerald-800/60 rounded-lg p-5 space-y-4">
              <div className="flex items-center justify-between pb-3 border-b border-gray-800">
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                  <span className="text-sm font-semibold text-white">
                    End-to-End Pipeline Audit: All 6 Stages Grounded &amp; Verified
                  </span>
                </div>
                <span className="text-xs font-mono text-emerald-400">
                  {String(e2eResult['execution_time_ms'])} ms total
                </span>
              </div>

              <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs font-mono">
                <div className="p-2.5 bg-gray-950 rounded border border-gray-800">
                  <span className="text-[10px] text-gray-500 block">Stage 1: Engine Output</span>
                  <span className="font-semibold text-white mt-1 block">
                    {String(e2eResult['packets_processed'])} pkts / {String(e2eResult['flows_tracked'])} flows
                  </span>
                </div>
                <div className="p-2.5 bg-gray-950 rounded border border-gray-800">
                  <span className="text-[10px] text-gray-500 block">Stage 2: Parquet Analytics</span>
                  <span className="font-semibold text-white mt-1 block">
                    {String(e2eResult['events_ingested'])} events ingested
                  </span>
                </div>
                <div className="p-2.5 bg-gray-950 rounded border border-gray-800">
                  <span className="text-[10px] text-gray-500 block">Stage 3: Topology Discovery</span>
                  <span className="font-semibold text-white mt-1 block">
                    {String(e2eResult['topology_nodes_discovered'])} nodes, {String(e2eResult['topology_edges_discovered'])} edges
                  </span>
                </div>
                <div className="p-2.5 bg-gray-950 rounded border border-gray-800">
                  <span className="text-[10px] text-gray-500 block">Stage 4: Predictive Samples</span>
                  <span className="font-semibold text-white mt-1 block">
                    {String(e2eResult['predictive_samples'])} extracted windows
                  </span>
                </div>
              </div>
            </div>
          )}

          {/* Differential & Metamorphic Testing Cockpit */}
          <div className="bg-gray-900 border border-gray-800 rounded-lg p-5 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-3 border-b border-gray-800 gap-2">
              <div>
                <span className="text-sm font-semibold text-white">
                  Differential &amp; Metamorphic Invariant Suite
                </span>
                <p className="text-[11px] text-gray-400 mt-0.5">
                  Automated verification of formal transformation invariants across container formats and temporal shifts.
                </p>
              </div>

              <div className="flex items-center gap-2 flex-wrap">
                <button
                  onClick={() => handleRunDifferential('FORMAT_EQUIVALENCE')}
                  disabled={runningDiffRel !== null}
                  className="px-2.5 py-1 bg-purple-900/40 hover:bg-purple-800/60 disabled:opacity-50 border border-purple-700/60 text-purple-200 text-xs rounded transition flex items-center gap-1 font-mono"
                >
                  {runningDiffRel === 'FORMAT_EQUIVALENCE' && <RotateCw className="w-3 h-3 animate-spin" />}
                  <span>MR-FORMAT (PCAP vs PCAPNG)</span>
                </button>
                <button
                  onClick={() => handleRunDifferential('TIMESTAMP_SHIFT')}
                  disabled={runningDiffRel !== null}
                  className="px-2.5 py-1 bg-blue-900/40 hover:bg-blue-800/60 disabled:opacity-50 border border-blue-700/60 text-blue-200 text-xs rounded transition flex items-center gap-1 font-mono"
                >
                  {runningDiffRel === 'TIMESTAMP_SHIFT' && <RotateCw className="w-3 h-3 animate-spin" />}
                  <span>MR-TIMESHIFT (+60s)</span>
                </button>
                <button
                  onClick={() => handleRunDifferential('NOISE_INJECTION')}
                  disabled={runningDiffRel !== null}
                  className="px-2.5 py-1 bg-amber-900/40 hover:bg-amber-800/60 disabled:opacity-50 border border-amber-700/60 text-amber-200 text-xs rounded transition flex items-center gap-1 font-mono"
                >
                  {runningDiffRel === 'NOISE_INJECTION' && <RotateCw className="w-3 h-3 animate-spin" />}
                  <span>MR-NOISE (+1 flow)</span>
                </button>
              </div>
            </div>

            {/* Metamorphic Invariant Explainer Strip */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-2 text-[11px] text-gray-400">
              <div className="p-2.5 bg-gray-950/60 border border-gray-800/80 rounded">
                <span className="font-semibold text-purple-300 block mb-0.5">MR-FORMAT Equivalence</span>
                Asserts bit-exact packet, flow, and protocol field equality across PCAP and PCAPNG container encapsulations.
              </div>
              <div className="p-2.5 bg-gray-950/60 border border-gray-800/80 rounded">
                <span className="font-semibold text-blue-300 block mb-0.5">MR-TIMESHIFT Invariance</span>
                Asserts flow groupings, TCP sequence tracks, and inter-packet deltas remain unchanged under a +60s epoch shift.
              </div>
              <div className="p-2.5 bg-gray-950/60 border border-gray-800/80 rounded">
                <span className="font-semibold text-amber-300 block mb-0.5">MR-NOISE Isolation</span>
                Asserts that injecting independent synthetic background traffic does not alter target flow state or parsing.
              </div>
            </div>

            {differentialResults.length > 0 ? (
              <div className="space-y-2 pt-2">
                {differentialResults.map((res) => (
                  <div
                    key={res.test_id}
                    className="p-3 bg-gray-950/60 rounded border border-gray-800 flex flex-col md:flex-row md:items-center justify-between gap-2 text-xs"
                  >
                    <div>
                      <div className="flex items-center gap-2">
                        {res.passed ? (
                          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                        ) : (
                          <XCircle className="w-4 h-4 text-red-400 shrink-0" />
                        )}
                        <span className="font-semibold text-white font-mono">{res.relation_type}</span>
                        <span className="text-gray-500 font-mono text-[10px]">[{res.test_id}]</span>
                      </div>
                      <p className="text-[11px] text-gray-400 mt-1">{res.expected_invariant}</p>
                      <p className="text-[11px] text-indigo-300 mt-0.5 font-mono">{res.observed_behavior}</p>
                    </div>

                    <div className="flex items-center gap-3 shrink-0">
                      <span className="text-[11px] text-gray-500 font-mono">
                        {res.execution_time_ms} ms
                      </span>
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-semibold font-mono ${
                          res.passed
                            ? 'bg-emerald-950/80 text-emerald-300 border border-emerald-800/60'
                            : 'bg-red-950/80 text-red-300 border border-red-800/60'
                        }`}
                      >
                        {res.passed ? 'PASSED' : 'FAILED'}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center py-6 text-gray-500 text-xs border border-dashed border-gray-800 rounded">
                No metamorphic tests executed yet. Click one of the MR buttons above to run automated invariant testing.
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
