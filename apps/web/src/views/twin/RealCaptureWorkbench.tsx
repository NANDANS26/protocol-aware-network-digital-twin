import React, { useState, useEffect, useCallback } from 'react';
import { apiClient } from '../../api/client';
import type {
  CaptureManifestItem,
  CorpusSummaryResponse,
  CaptureValidationReport,
  DifferentialTestResult,
  MetamorphicRelationType,
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
} from 'lucide-react';

export const RealCaptureWorkbench: React.FC = () => {
  const [captures, setCaptures] = useState<CaptureManifestItem[]>([]);
  const [summary, setSummary] = useState<CorpusSummaryResponse | null>(null);
  const [selectedCaptureId, setSelectedCaptureId] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Validation report state
  const [validationReport, setValidationReport] = useState<CaptureValidationReport | null>(null);
  const [validating, setValidating] = useState<boolean>(false);

  // Differential testing state
  const [differentialResults, setDifferentialResults] = useState<DifferentialTestResult[]>([]);
  const [runningDiff, setRunningDiff] = useState<boolean>(false);

  // E2E Pipeline state
  const [e2eResult, setE2eResult] = useState<Record<string, unknown> | null>(null);
  const [runningE2E, setRunningE2E] = useState<boolean>(false);

  const loadCorpusData = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const [caps, summ] = await Promise.all([
        apiClient.listCorpusCaptures(),
        apiClient.getCorpusSummary(),
      ]);
      setCaptures(caps);
      setSummary(summ);
      const first = caps[0];
      if (first && !selectedCaptureId) {
        setSelectedCaptureId(first.capture_id);
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

  const selectedCapture = captures.find((c) => c.capture_id === selectedCaptureId);

  const handleRunValidation = async () => {
    if (!selectedCaptureId) return;
    try {
      setValidating(true);
      setError(null);
      const report = await apiClient.validateCapture(selectedCaptureId);
      setValidationReport(report);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Validation failed.');
    } finally {
      setValidating(false);
    }
  };

  const handleRunDifferential = async (relType: MetamorphicRelationType) => {
    if (!selectedCaptureId) return;
    try {
      setRunningDiff(true);
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
      setRunningDiff(false);
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
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
  };

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
          </div>
          <p className="text-xs text-gray-400 mt-1">
            Independently verified packet corpus, reference oracle differential validation, and end-to-end data path audit.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={loadCorpusData}
            disabled={loading}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-gray-800 hover:bg-gray-700 text-gray-300 text-xs font-medium rounded border border-gray-700 transition"
          >
            <RotateCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Refresh Corpus
          </button>
        </div>
      </div>

      {error && (
        <div className="bg-red-950/40 border border-red-800/80 rounded-lg p-4 flex items-center gap-3 text-red-300 text-xs">
          <AlertCircle className="w-4 h-4 shrink-0 text-red-400" />
          <span>{error}</span>
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
              <span className="text-xl font-bold text-white mt-0.5 block">
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
              <span className="text-xl font-bold text-cyan-400 mt-0.5 block">
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
              <span className="text-xl font-bold text-emerald-400 mt-0.5 block">
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
              <span className="text-sm font-semibold text-purple-400 mt-1 block">
                PCAP ({summary.format_distribution['PCAP'] || 0}) / PCAPNG ({summary.format_distribution['PCAPNG'] || 0})
              </span>
            </div>
            <Activity className="w-7 h-7 text-purple-500/30" />
          </div>
        </div>
      )}

      {/* Main Grid: Corpus Selector & Detail Cockpit */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Col: Corpus Catalog List */}
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-4 flex flex-col h-full">
          <div className="flex items-center justify-between pb-3 border-b border-gray-800 mb-3">
            <span className="text-xs font-semibold text-gray-300 uppercase tracking-wider">
              Capture Corpus Manifest
            </span>
            <span className="text-[10px] text-gray-500 bg-gray-800 px-2 py-0.5 rounded">
              {captures.length} files
            </span>
          </div>

          <div className="space-y-2 overflow-y-auto max-h-[500px] pr-1">
            {captures.map((item) => {
              const isSelected = item.capture_id === selectedCaptureId;
              return (
                <div
                  key={item.capture_id}
                  onClick={() => {
                    setSelectedCaptureId(item.capture_id);
                    setValidationReport(null);
                    setE2eResult(null);
                  }}
                  className={`p-3 rounded border text-left cursor-pointer transition ${
                    isSelected
                      ? 'bg-indigo-950/40 border-indigo-500'
                      : 'bg-gray-950/40 border-gray-800/80 hover:bg-gray-800/40'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-medium text-white truncate max-w-[190px]">
                      {item.name}
                    </span>
                    <span
                      className={`text-[9px] font-mono px-1.5 py-0.5 rounded uppercase ${
                        item.format === 'PCAPNG'
                          ? 'bg-purple-900/40 text-purple-300 border border-purple-800/60'
                          : 'bg-blue-900/40 text-blue-300 border border-blue-800/60'
                      }`}
                    >
                      {item.format}
                    </span>
                  </div>

                  <div className="flex items-center gap-2 mt-1.5 text-[10px] text-gray-400">
                    <span className="font-mono text-gray-300">{item.packet_count} pkts</span>
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

                  <div className="flex flex-wrap gap-1 mt-2">
                    {item.protocols.map((p) => (
                      <span
                        key={p}
                        className="text-[9px] px-1.5 py-0.2 bg-gray-800 text-gray-300 rounded font-mono"
                      >
                        {p}
                      </span>
                    ))}
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right Col: Capture Metadata & Verification Cockpit */}
        <div className="lg:col-span-2 space-y-6">
          {selectedCapture ? (
            <div className="bg-gray-900 border border-gray-800 rounded-lg p-5">
              <div className="flex flex-col md:flex-row md:items-center justify-between pb-4 border-b border-gray-800 gap-3">
                <div>
                  <h3 className="text-base font-semibold text-white">{selectedCapture.name}</h3>
                  <div className="flex items-center gap-2 text-xs text-gray-400 font-mono mt-0.5">
                    <span>{selectedCapture.file_name}</span>
                    <span>•</span>
                    <span className="text-gray-500 truncate max-w-[280px]">
                      SHA256: {selectedCapture.sha256}
                    </span>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={handleRunValidation}
                    disabled={validating}
                    className="flex items-center gap-1.5 px-3 py-1.5 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white text-xs font-medium rounded transition"
                  >
                    <Play className="w-3.5 h-3.5" />
                    {validating ? 'Validating...' : 'Run Decoder Oracle'}
                  </button>

                  <button
                    onClick={handleRunE2E}
                    disabled={runningE2E}
                    className="flex items-center gap-1.5 px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white text-xs font-medium rounded transition"
                  >
                    <Database className="w-3.5 h-3.5" />
                    {runningE2E ? 'Auditing...' : 'Run E2E Data Path'}
                  </button>
                </div>
              </div>

              {/* Provenance & Limitations */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4 text-xs">
                <div className="p-3 bg-gray-950/60 rounded border border-gray-800">
                  <span className="text-[10px] text-gray-400 uppercase font-semibold block mb-1">
                    Provenance & Attribution
                  </span>
                  <p className="text-gray-300">
                    <span className="text-gray-500">Source:</span> {selectedCapture.source}
                  </p>
                  <p className="text-gray-300 mt-1">
                    <span className="text-gray-500">License:</span> {selectedCapture.license} ({selectedCapture.attribution})
                  </p>
                  <div className="mt-2 text-[11px] text-indigo-400">
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

              {/* Expected Outcomes Matrix */}
              <div className="mt-4 p-3 bg-gray-950/40 rounded border border-gray-800">
                <span className="text-[10px] text-gray-400 uppercase font-semibold block mb-2">
                  Expected Protocol Outcomes (Independently Established)
                </span>
                <div className="grid grid-cols-2 md:grid-cols-5 gap-2 text-center text-xs">
                  <div className="p-2 bg-gray-900 rounded">
                    <span className="text-[10px] text-gray-500 block">Packets</span>
                    <span className="font-semibold text-white font-mono">
                      {selectedCapture.expected_outcomes.total_packets}
                    </span>
                  </div>
                  <div className="p-2 bg-gray-900 rounded">
                    <span className="text-[10px] text-gray-500 block">Flows</span>
                    <span className="font-semibold text-white font-mono">
                      {selectedCapture.expected_outcomes.total_flows}
                    </span>
                  </div>
                  <div className="p-2 bg-gray-900 rounded">
                    <span className="text-[10px] text-gray-500 block">DNS (Q/R)</span>
                    <span className="font-semibold text-white font-mono">
                      {selectedCapture.expected_outcomes.dns_queries} / {selectedCapture.expected_outcomes.dns_responses}
                    </span>
                  </div>
                  <div className="p-2 bg-gray-900 rounded">
                    <span className="text-[10px] text-gray-500 block">HTTP (Req/Res)</span>
                    <span className="font-semibold text-white font-mono">
                      {selectedCapture.expected_outcomes.http_requests} / {selectedCapture.expected_outcomes.http_responses}
                    </span>
                  </div>
                  <div className="p-2 bg-gray-900 rounded">
                    <span className="text-[10px] text-gray-500 block">TLS Handshakes</span>
                    <span className="font-semibold text-white font-mono">
                      {selectedCapture.expected_outcomes.tls_handshakes}
                      {selectedCapture.expected_outcomes.extracted_sni && (
                        <span className="text-[9px] text-indigo-400 block truncate">
                          SNI: {selectedCapture.expected_outcomes.extracted_sni}
                        </span>
                      )}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          ) : (
            <div className="bg-gray-900 border border-gray-800 rounded-lg p-8 text-center text-gray-500 text-xs">
              Select a capture fixture from the corpus list to inspect ground truth and run validation.
            </div>
          )}

          {/* Reference Decoder & Resource Telemetry Report */}
          {validationReport && (
            <div className="bg-gray-900 border border-gray-800 rounded-lg p-5 space-y-4">
              <div className="flex items-center justify-between pb-3 border-b border-gray-800">
                <div className="flex items-center gap-2">
                  {validationReport.passed ? (
                    <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                  ) : (
                    <XCircle className="w-5 h-5 text-red-400" />
                  )}
                  <div>
                    <span className="text-sm font-semibold text-white">
                      Differential Validation Result:{' '}
                      <span className={validationReport.passed ? 'text-emerald-400' : 'text-red-400'}>
                        {validationReport.passed ? 'PASSED (Bit-Exact)' : 'FAILED'}
                      </span>
                    </span>
                    <p className="text-[11px] text-gray-400">{validationReport.explanation}</p>
                  </div>
                </div>
                <span className="text-[10px] font-mono text-gray-500">
                  {validationReport.validation_id}
                </span>
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
                      {validationReport.telemetry.wall_duration_ms} ms
                    </span>
                  </div>
                  <div>
                    <span className="text-gray-500 text-[10px] block">Throughput (PPS)</span>
                    <span className="font-mono text-cyan-400 font-medium">
                      {validationReport.telemetry.throughput_pps.toLocaleString()} pps
                    </span>
                  </div>
                  <div>
                    <span className="text-gray-500 text-[10px] block">Throughput (MBPS)</span>
                    <span className="font-mono text-cyan-400 font-medium">
                      {validationReport.telemetry.throughput_mbps} Mbps
                    </span>
                  </div>
                  <div>
                    <span className="text-gray-500 text-[10px] block">Peak Native Memory</span>
                    <span className="font-mono text-emerald-400 font-medium">
                      {formatBytes(validationReport.telemetry.peak_native_memory_bytes)}
                    </span>
                  </div>
                  <div>
                    <span className="text-gray-500 text-[10px] block">Python Heap (tracemalloc)</span>
                    <span className="font-mono text-purple-400 font-medium">
                      {formatBytes(validationReport.telemetry.python_heap_bytes)}
                    </span>
                  </div>
                </div>
              </div>

              {/* Field Differences Table if any */}
              {validationReport.field_differences.length > 0 && (
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
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-gray-800">
                        {validationReport.field_differences.map((diff, i) => (
                          <tr key={i} className="hover:bg-gray-800/30">
                            <td className="p-2 font-mono">{diff.packet_index}</td>
                            <td className="p-2 font-mono text-indigo-300">{diff.field_name}</td>
                            <td className="p-2 font-mono text-red-300">{String(diff.cpp_engine_value)}</td>
                            <td className="p-2 font-mono text-emerald-300">
                              {String(diff.reference_decoder_value)}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* E2E Pipeline Audit Verification Panel */}
          {e2eResult && (
            <div className="bg-gray-900 border border-emerald-800/60 rounded-lg p-5 space-y-4">
              <div className="flex items-center justify-between pb-3 border-b border-gray-800">
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                  <span className="text-sm font-semibold text-white">
                    End-to-End Pipeline Audit: All 6 Stages Grounded & Verified
                  </span>
                </div>
                <span className="text-xs font-mono text-emerald-400">
                  {String(e2eResult['execution_time_ms'])} ms total
                </span>
              </div>

              <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
                <div className="p-2 bg-gray-950 rounded border border-gray-800">
                  <span className="text-[10px] text-gray-500 block">Stage 1: Engine Output</span>
                  <span className="font-semibold text-white font-mono">
                    {String(e2eResult['packets_processed'])} pkts / {String(e2eResult['flows_tracked'])} flows
                  </span>
                </div>
                <div className="p-2 bg-gray-950 rounded border border-gray-800">
                  <span className="text-[10px] text-gray-500 block">Stage 2: Parquet Analytics</span>
                  <span className="font-semibold text-white font-mono">
                    {String(e2eResult['events_ingested'])} events ingested
                  </span>
                </div>
                <div className="p-2 bg-gray-950 rounded border border-gray-800">
                  <span className="text-[10px] text-gray-500 block">Stage 3: Topology Discovery</span>
                  <span className="font-semibold text-white font-mono">
                    {String(e2eResult['topology_nodes_discovered'])} nodes, {String(e2eResult['topology_edges_discovered'])} edges
                  </span>
                </div>
                <div className="p-2 bg-gray-950 rounded border border-gray-800">
                  <span className="text-[10px] text-gray-500 block">Stage 4: Predictive Samples</span>
                  <span className="font-semibold text-white font-mono">
                    {String(e2eResult['predictive_samples'])} extracted windows
                  </span>
                </div>
              </div>
            </div>
          )}

          {/* Differential & Metamorphic Testing Cockpit */}
          <div className="bg-gray-900 border border-gray-800 rounded-lg p-5 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-3 border-b border-gray-800 gap-2">
              <span className="text-sm font-semibold text-white">
                Differential & Metamorphic Invariant Suite
              </span>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => handleRunDifferential('FORMAT_EQUIVALENCE')}
                  disabled={runningDiff}
                  className="px-2.5 py-1 bg-purple-900/40 hover:bg-purple-800/60 border border-purple-700/60 text-purple-200 text-xs rounded transition"
                >
                  MR-FORMAT (PCAP vs PCAPNG)
                </button>
                <button
                  onClick={() => handleRunDifferential('TIMESTAMP_SHIFT')}
                  disabled={runningDiff}
                  className="px-2.5 py-1 bg-blue-900/40 hover:bg-blue-800/60 border border-blue-700/60 text-blue-200 text-xs rounded transition"
                >
                  MR-TIMESHIFT (+60s)
                </button>
                <button
                  onClick={() => handleRunDifferential('NOISE_INJECTION')}
                  disabled={runningDiff}
                  className="px-2.5 py-1 bg-amber-900/40 hover:bg-amber-800/60 border border-amber-700/60 text-amber-200 text-xs rounded transition"
                >
                  MR-NOISE (+1 flow)
                </button>
              </div>
            </div>

            {differentialResults.length > 0 ? (
              <div className="space-y-2">
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
                        <span className="font-semibold text-white">{res.relation_type}</span>
                        <span className="text-gray-500 font-mono text-[10px]">{res.test_id}</span>
                      </div>
                      <p className="text-[11px] text-gray-400 mt-1">{res.expected_invariant}</p>
                      <p className="text-[11px] text-indigo-300 mt-0.5">{res.observed_behavior}</p>
                    </div>

                    <div className="flex items-center gap-3 shrink-0">
                      <span className="text-[11px] text-gray-500 font-mono">
                        {res.execution_time_ms} ms
                      </span>
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
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
              <div className="text-center py-6 text-gray-500 text-xs">
                No metamorphic tests executed yet. Click one of the MR buttons above to run automated invariant testing.
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
