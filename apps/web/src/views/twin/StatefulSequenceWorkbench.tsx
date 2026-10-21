import React, { useState, useEffect, useCallback, useMemo } from 'react';
import {
  Layers,
  Play,
  RotateCw,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Download,
  Minimize2,
  FileCode,
  ShieldCheck,
  Zap,
  Info,
  Clock,
  ArrowRight,
  Shuffle,
  Search,
  X,
  Activity,
} from 'lucide-react';
import { apiClient } from '../../api/client';
import type {
  ProtocolSequence,
  SequenceExecutionResult,
  SequenceFinding,
  SequenceRegressionFixture,
  SequenceDifferentialResult,
  CoverageGapsResponse,
  CoverageGapItem,
  SequenceMutationType,
} from '../../types/sequences';

export const StatefulSequenceWorkbench: React.FC = () => {
  const [sequences, setSequences] = useState<ProtocolSequence[]>([]);
  const [selectedSequence, setSelectedSequence] = useState<ProtocolSequence | null>(null);
  const [executionResult, setExecutionResult] = useState<SequenceExecutionResult | null>(null);
  const [findings, setFindings] = useState<SequenceFinding[]>([]);
  const [regressions, setRegressions] = useState<SequenceRegressionFixture[]>([]);
  const [coverageGaps, setCoverageGaps] = useState<CoverageGapsResponse | null>(null);
  const [diffResult, setDiffResult] = useState<SequenceDifferentialResult | null>(null);
  const [diffError, setDiffError] = useState<string | null>(null);
  const [isDiffRunning, setIsDiffRunning] = useState(false);
  const [isRunning, setIsRunning] = useState(false);
  const [isGenerating, setIsGenerating] = useState(false);
  const [isMinimizing, setIsMinimizing] = useState(false);
  const [showCoverageModal, setShowCoverageModal] = useState(false);
  const [filterType, setFilterType] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [seed, setSeed] = useState(42);
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);

  const fetchSequences = useCallback(async () => {
    try {
      const typeParam = filterType === 'ALL' ? undefined : filterType;
      const list = await apiClient.listProtocolSequences(typeParam);
      setSequences(list || []);
      if (list && list.length > 0 && !selectedSequence) {
        setSelectedSequence(list[0] ?? null);
      }
    } catch (err) {
      console.error('Failed to load protocol sequences:', err);
      setSequences([]);
    }
  }, [filterType, selectedSequence]);

  const fetchFindingsAndRegressions = useCallback(async () => {
    try {
      const [fList, rList, gaps] = await Promise.all([
        apiClient.listSequenceFindings().catch(() => []),
        apiClient.listSequenceRegressions().catch(() => []),
        apiClient.getCoverageGaps().catch(() => null),
      ]);
      setFindings(fList || []);
      setRegressions(rList || []);
      setCoverageGaps(gaps);
    } catch (err) {
      console.error('Failed to load findings and regressions:', err);
    }
  }, []);

  useEffect(() => {
    fetchSequences();
    fetchFindingsAndRegressions();
  }, [fetchSequences, fetchFindingsAndRegressions]);

  const handleGenerateSuite = async () => {
    setIsGenerating(true);
    setActionSuccess(null);
    try {
      const generated = await apiClient.generateSequenceSuite(seed);
      setSequences(generated || []);
      if (generated && generated.length > 0) {
        setSelectedSequence(generated[0] ?? null);
      }
      await fetchFindingsAndRegressions();
      setActionSuccess(`Generated ${generated?.length ?? 0} canonical protocol sequences.`);
      setTimeout(() => setActionSuccess(null), 4000);
    } catch (err) {
      console.error('Failed to generate sequence suite:', err);
    } finally {
      setIsGenerating(false);
    }
  };

  const handleRunSequence = async (seqId: string) => {
    setIsRunning(true);
    setActionSuccess(null);
    try {
      const res = await apiClient.runProtocolSequence(seqId);
      setExecutionResult(res.execution);
      await fetchFindingsAndRegressions();
    } catch (err) {
      console.error('Sequence execution error:', err);
    } finally {
      setIsRunning(false);
    }
  };

  const handleMutateSequence = async (mutationType: SequenceMutationType) => {
    if (!selectedSequence) return;
    try {
      const mutated = await apiClient.mutateProtocolSequence(selectedSequence.sequence_id, [
        {
          mutation_type: mutationType,
          parameters: {},
          description: `UI Injected ${mutationType} mutation`,
        },
      ]);
      setSequences((prev) => [mutated, ...prev.filter((s) => s.sequence_id !== mutated.sequence_id)]);
      setSelectedSequence(mutated);
      setActionSuccess(`Injected ${mutationType} mutation into sequence.`);
      setTimeout(() => setActionSuccess(null), 4000);
    } catch (err) {
      console.error('Sequence mutation error:', err);
    }
  };

  const handleRunDifferential = async () => {
    if (!selectedSequence) return;
    setIsDiffRunning(true);
    setDiffError(null);
    try {
      const raw = await apiClient.runSequenceDifferential({
        sequence_id: selectedSequence.sequence_id,
        mode: 'pcap_vs_pcapng',
      });
      // Defensive normalization at API boundary
      const normalized: SequenceDifferentialResult = {
        ...raw,
        differences: Array.isArray(raw.differences) ? raw.differences : [],
        baseline_name: raw.baseline_name || 'PCAP Baseline',
        candidate_name: raw.candidate_name || 'PCAPNG Candidate',
        baseline_event_count: raw.baseline_event_count ?? raw.baseline_events_count ?? 0,
        candidate_event_count: raw.candidate_event_count ?? raw.candidate_events_count ?? 0,
        duration_ms: typeof raw.duration_ms === 'number' ? raw.duration_ms : 0,
      };
      setDiffResult(normalized);
    } catch (err: unknown) {
      console.error('Differential execution error:', err);
      const msg = err instanceof Error ? err.message : 'Differential verification execution failed.';
      setDiffError(msg);
    } finally {
      setIsDiffRunning(false);
    }
  };

  const handleMinimizeFinding = async (findingId: string) => {
    setIsMinimizing(true);
    try {
      await apiClient.minimizeSequenceFinding(findingId);
      await fetchFindingsAndRegressions();
      await fetchSequences();
      setActionSuccess(`Finding ${findingId.slice(0, 8)} minimized via delta debugging.`);
      setTimeout(() => setActionSuccess(null), 4000);
    } catch (err) {
      console.error('Minimization error:', err);
    } finally {
      setIsMinimizing(false);
    }
  };

  const handlePromoteRegression = async (findingId: string) => {
    const name = window.prompt('Enter regression test name:', `Regression for ${findingId}`);
    if (!name) return;
    try {
      await apiClient.promoteSequenceRegression(findingId, name);
      await fetchFindingsAndRegressions();
      setActionSuccess(`Finding promoted to permanent regression fixture.`);
      setTimeout(() => setActionSuccess(null), 4000);
    } catch (err) {
      console.error('Promotion error:', err);
    }
  };

  const handleDownloadBundle = async (findingId: string) => {
    try {
      const blob = await apiClient.exportSequenceBundle(findingId);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `reproduction_bundle_${findingId}.zip`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Download error:', err);
    }
  };

  // Safe boundary normalization for coverage gaps modal
  const supportedCapabilities = useMemo(() => {
    if (!coverageGaps) return [];
    return coverageGaps.supported_capabilities ?? coverageGaps.supported_stateful_semantics ?? [];
  }, [coverageGaps]);

  const documentedGaps = useMemo(() => {
    if (!coverageGaps) return [];
    const raw = coverageGaps.documented_coverage_gaps ?? coverageGaps.coverage_gaps_and_limitations ?? [];
    return raw.map((g: CoverageGapItem) => ({
      feature: g.feature || g.subsystem || 'Unspecified Protocol Feature',
      limitation_status: g.limitation_status || g.status || 'KNOWN_GAP',
      description: g.description || g.details || '',
      behavior: g.behavior || g.details || 'Documented behavioral limitation',
    }));
  }, [coverageGaps]);

  const filteredSequences = useMemo(() => {
    return sequences.filter((s) => {
      if (filterType !== 'ALL' && s.sequence_type !== filterType) return false;
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        return (
          s.name.toLowerCase().includes(q) ||
          s.sequence_id.toLowerCase().includes(q) ||
          s.sequence_type.toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [sequences, filterType, searchQuery]);

  return (
    <div className="space-y-6">
      {/* Top Header & Workstation Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-5 rounded-xl bg-card border border-border shadow-sm">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-lg bg-indigo-500/10 border border-indigo-500/20 text-indigo-400">
              <Layers className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-lg font-bold text-gray-100">
                  Stateful Protocol Fuzzing &amp; Multi-Packet Sequence Verification
                </h2>
                <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-indigo-500/10 text-indigo-400 border border-indigo-500/20 font-semibold">
                  Sequence Engine Active
                </span>
              </div>
              <p className="text-xs text-muted-foreground mt-0.5">
                Deterministic TCP handshake/teardown state tracking, out-of-order reassembly, cross-flow isolation, and delta-debugging minimization.
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            onClick={() => setShowCoverageModal(true)}
            className="px-3 py-2 rounded-lg bg-card hover:bg-muted text-gray-200 text-xs font-medium border border-border transition flex items-center gap-2"
          >
            <Info className="w-3.5 h-3.5 text-blue-400" />
            <span>Coverage Gaps &amp; Limits</span>
          </button>
          <button
            onClick={handleGenerateSuite}
            disabled={isGenerating}
            className="px-3.5 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold shadow-sm transition flex items-center gap-2 disabled:opacity-50"
          >
            <RotateCw className={`w-3.5 h-3.5 ${isGenerating ? 'animate-spin' : ''}`} />
            <span>{isGenerating ? 'Generating Suite...' : 'Generate Canonical Suite'}</span>
          </button>
        </div>
      </div>

      {/* Action Success Notification */}
      {actionSuccess && (
        <div className="p-3 rounded-lg bg-emerald-950/40 border border-emerald-800/60 text-emerald-300 text-xs flex items-center justify-between">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            <span>{actionSuccess}</span>
          </div>
          <button onClick={() => setActionSuccess(null)} className="text-emerald-400 hover:text-emerald-200">
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* Summary KPI Cards Strip */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-card border border-border">
          <div className="flex items-center justify-between text-xs text-muted-foreground">
            <span>Stored Sequences</span>
            <Layers className="w-3.5 h-3.5 text-indigo-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-gray-100 mt-1">{sequences.length}</div>
          <div className="text-[10px] text-muted-foreground mt-0.5">
            {sequences.filter((s) => s.is_supported).length} supported • {sequences.filter((s) => !s.is_supported).length} gaps
          </div>
        </div>

        <div className="p-4 rounded-xl bg-card border border-border">
          <div className="flex items-center justify-between text-xs text-muted-foreground">
            <span>Sequence Findings</span>
            <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-amber-400 mt-1">{findings.length}</div>
          <div className="text-[10px] text-muted-foreground mt-0.5">
            {findings.filter((f) => f.severity === 'CRITICAL').length} critical • {findings.filter((f) => f.minimized).length} minimized
          </div>
        </div>

        <div className="p-4 rounded-xl bg-card border border-border">
          <div className="flex items-center justify-between text-xs text-muted-foreground">
            <span>Regression Ledger</span>
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-emerald-400 mt-1">{regressions.length}</div>
          <div className="text-[10px] text-muted-foreground mt-0.5">Permanent CI/CD fixtures</div>
        </div>

        <div className="p-4 rounded-xl bg-card border border-border">
          <div className="flex items-center justify-between text-xs text-muted-foreground">
            <span>Generation Seed</span>
            <Activity className="w-3.5 h-3.5 text-cyan-400" />
          </div>
          <input
            type="number"
            value={seed}
            onChange={(e) => setSeed(parseInt(e.target.value) || 0)}
            className="w-full bg-muted border border-border rounded px-2 py-0.5 mt-1 text-sm font-bold text-indigo-400 font-mono focus:outline-none focus:border-indigo-500"
          />
          <div className="text-[10px] text-muted-foreground mt-0.5">Deterministic PRNG seed</div>
        </div>
      </div>

      {/* Differential Check Error Banner if present */}
      {diffError && (
        <div className="p-4 rounded-lg bg-rose-950/30 border border-rose-800/60 text-rose-300 text-xs flex items-center justify-between">
          <div className="flex items-center gap-3">
            <XCircle className="w-5 h-5 text-rose-400 shrink-0" />
            <div>
              <div className="font-semibold text-rose-200">Differential Verification Error</div>
              <div className="text-[11px] text-rose-300/80 mt-0.5">{diffError}</div>
            </div>
          </div>
          <button onClick={() => setDiffError(null)} className="text-xs text-rose-400 hover:text-rose-200">
            Dismiss
          </button>
        </div>
      )}

      {/* Differential Result Cockpit Banner */}
      {diffResult && (
        <div className={`p-4 rounded-xl border space-y-3 transition ${
          diffResult.equivalent
            ? 'bg-emerald-950/20 border-emerald-800/40 text-emerald-200'
            : 'bg-rose-950/20 border-rose-800/40 text-rose-200'
        }`}>
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="flex items-center gap-3">
              {diffResult.equivalent ? (
                <CheckCircle2 className="w-6 h-6 text-emerald-400 shrink-0" />
              ) : (
                <XCircle className="w-6 h-6 text-rose-400 shrink-0" />
              )}
              <div>
                <div className="text-sm font-bold flex items-center gap-2">
                  <span>Sequence Differential Equivalence:</span>
                  <span className={`px-2 py-0.5 rounded text-xs font-mono font-bold ${
                    diffResult.equivalent
                      ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                      : 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                  }`}>
                    {diffResult.equivalent ? 'EQUIVALENT OUTPUT CONFIRMED' : 'DIVERGENCE DETECTED'}
                  </span>
                </div>
                <div className="text-xs text-muted-foreground mt-0.5 font-mono">
                  {diffResult.baseline_name} ({diffResult.baseline_event_count} events) vs{' '}
                  {diffResult.candidate_name} ({diffResult.candidate_event_count} events) evaluated in{' '}
                  {diffResult.duration_ms.toFixed(1)}ms.
                </div>
              </div>
            </div>
            <div className="flex items-center gap-2 shrink-0">
              <span className="text-[11px] font-mono text-gray-400 px-2 py-1 rounded bg-black/30 border border-white/5">
                Mode: {diffResult.mode}
              </span>
              <button
                onClick={() => setDiffResult(null)}
                className="px-2 py-1 rounded text-xs text-muted-foreground hover:text-white bg-black/20 hover:bg-black/40"
              >
                Dismiss
              </button>
            </div>
          </div>

          {/* Divergences list if discrepancies were detected */}
          {(!diffResult.equivalent || (diffResult.differences && diffResult.differences.length > 0)) && (
            <div className="mt-3 p-3 rounded-lg bg-black/40 border border-rose-800/30 space-y-2">
              <div className="text-xs font-semibold text-rose-300 flex items-center gap-1.5">
                <AlertTriangle className="w-4 h-4 text-rose-400" />
                <span>Observed Semantic Divergences ({diffResult.differences?.length ?? 0}):</span>
              </div>
              {diffResult.differences && diffResult.differences.length > 0 ? (
                <ul className="space-y-1 pl-5 list-disc text-xs font-mono text-gray-300">
                  {diffResult.differences.map((d, idx) => (
                    <li key={idx} className="text-rose-200">{d}</li>
                  ))}
                </ul>
              ) : (
                <div className="text-xs text-gray-400 italic">
                  Exit codes or state machine terminal states differed between formats without individual event discrepancies.
                </div>
              )}
              {diffResult.diagnostic && (
                <div className="mt-2 p-2 rounded bg-black/60 border border-gray-800 font-mono text-[11px] text-gray-300">
                  <div className="text-[10px] text-gray-500 uppercase">Engine Diagnostic:</div>
                  <div>{diffResult.diagnostic}</div>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Main Split Layout: Sequence Selector (Left) & Inspector (Right) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Sequence Catalog */}
        <div className="lg:col-span-4 space-y-4">
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-gray-300 uppercase tracking-wider">
                Sequence Catalog ({filteredSequences.length})
              </span>
            </div>
            <div className="flex gap-2">
              <div className="relative flex-1">
                <Search className="w-3.5 h-3.5 text-gray-400 absolute left-2.5 top-2.5" />
                <input
                  type="text"
                  placeholder="Filter sequences..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="w-full bg-muted border border-border rounded pl-8 pr-2 py-1 text-xs text-gray-200 placeholder-gray-500 focus:outline-none focus:border-indigo-500"
                />
              </div>
              <select
                value={filterType}
                onChange={(e) => setFilterType(e.target.value)}
                className="bg-muted border border-border rounded px-2 py-1 text-xs text-gray-200 focus:outline-none focus:border-indigo-500"
              >
                <option value="ALL">All Types</option>
                <option value="TCP_HANDSHAKE_TEARDOWN">TCP Handshake</option>
                <option value="TCP_RETRANSMISSION_OOO">TCP Retransmit</option>
                <option value="TCP_RST_AND_ABORT">TCP RST Abort</option>
                <option value="TCP_SIMULTANEOUS_FLOWS">Simultaneous</option>
                <option value="IP_FRAGMENTATION">IP Fragment</option>
                <option value="HTTP_SEGMENTED_STREAM">HTTP Reassembly</option>
              </select>
            </div>
          </div>

          <div className="space-y-2 max-h-[640px] overflow-y-auto pr-1">
            {filteredSequences.map((seq) => {
              const isSelected = selectedSequence?.sequence_id === seq.sequence_id;
              return (
                <div
                  key={seq.sequence_id}
                  onClick={() => {
                    setSelectedSequence(seq);
                    setExecutionResult(null);
                    setDiffResult(null);
                    setDiffError(null);
                  }}
                  className={`p-3.5 rounded-xl border text-left cursor-pointer transition ${
                    isSelected
                      ? 'bg-indigo-950/20 border-indigo-500/50 shadow-sm'
                      : 'bg-card border-border hover:border-gray-700'
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-semibold text-gray-100 truncate">{seq.name}</span>
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-mono font-medium shrink-0 ${
                        seq.is_supported
                          ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                          : 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                      }`}
                    >
                      {seq.is_supported ? 'Supported' : 'Coverage Gap'}
                    </span>
                  </div>

                  <div className="flex items-center gap-3 mt-2 text-[11px] text-muted-foreground font-mono">
                    <span>{seq.steps.length} Steps</span>
                    <span>•</span>
                    <span>{seq.expected_flow_count} Flow(s)</span>
                    <span>•</span>
                    <span className="uppercase">{seq.format}</span>
                  </div>
                </div>
              );
            })}

            {filteredSequences.length === 0 && (
              <div className="p-8 text-center text-xs text-muted-foreground border border-dashed border-border rounded-xl">
                {sequences.length === 0
                  ? 'No sequences generated yet. Click "Generate Canonical Suite" above.'
                  : 'No sequences matching your filter query.'}
              </div>
            )}
          </div>
        </div>

        {/* Right Column: Sequence Details, Timeline & Execution Inspector */}
        <div className="lg:col-span-8 space-y-5">
          {selectedSequence ? (
            <>
              {/* Sequence Header & Action Controls */}
              <div className="p-4 rounded-xl bg-card border border-border space-y-3">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <div>
                    <h3 className="text-base font-bold text-gray-100">{selectedSequence.name}</h3>
                    <p className="text-xs text-muted-foreground mt-0.5">{selectedSequence.description}</p>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <button
                      onClick={handleRunDifferential}
                      disabled={isDiffRunning}
                      className="px-3 py-1.5 rounded-lg bg-muted hover:bg-border text-gray-200 text-xs font-medium border border-border flex items-center gap-1.5 transition disabled:opacity-50"
                    >
                      <Zap className={`w-3.5 h-3.5 text-amber-400 ${isDiffRunning ? 'animate-spin' : ''}`} />
                      <span>{isDiffRunning ? 'Comparing...' : 'Run Differential Check'}</span>
                    </button>
                    <button
                      onClick={() => handleRunSequence(selectedSequence.sequence_id)}
                      disabled={isRunning}
                      className="px-4 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold shadow-sm transition flex items-center gap-1.5 disabled:opacity-50"
                    >
                      <Play className="w-3.5 h-3.5 fill-current" />
                      <span>{isRunning ? 'Executing...' : 'Execute Sequence'}</span>
                    </button>
                  </div>
                </div>

                {/* Mutation Injectors */}
                <div className="pt-2 border-t border-border flex flex-wrap items-center gap-2 text-xs">
                  <span className="text-muted-foreground flex items-center gap-1 text-[11px]">
                    <Shuffle className="w-3 h-3 text-indigo-400" />
                    Inject Mutation:
                  </span>
                  <button
                    onClick={() => handleMutateSequence('INSERT_UNRELATED_NOISE')}
                    className="px-2 py-0.5 rounded bg-muted hover:bg-border text-gray-300 text-[11px] transition"
                  >
                    + Background Noise
                  </button>
                  <button
                    onClick={() => handleMutateSequence('REORDER_PACKETS')}
                    className="px-2 py-0.5 rounded bg-muted hover:bg-border text-gray-300 text-[11px] transition"
                  >
                    Swap Last 2 Steps
                  </button>
                  <button
                    onClick={() => handleMutateSequence('DUPLICATE_PACKET')}
                    className="px-2 py-0.5 rounded bg-muted hover:bg-border text-gray-300 text-[11px] transition"
                  >
                    Duplicate Packet
                  </button>
                  <button
                    onClick={() => handleMutateSequence('SHIFT_TIMESTAMPS')}
                    className="px-2 py-0.5 rounded bg-muted hover:bg-border text-gray-300 text-[11px] transition"
                  >
                    Shift Timestamps (+100ms)
                  </button>
                  <button
                    onClick={() => handleMutateSequence('TRUNCATE_SEQUENCE')}
                    className="px-2 py-0.5 rounded bg-muted hover:bg-border text-gray-300 text-[11px] transition"
                  >
                    Truncate Sequence
                  </button>
                </div>

                {selectedSequence.coverage_gap_notes && (
                  <div className="p-3 rounded-lg bg-amber-500/10 border border-amber-500/20 text-amber-200 text-xs flex items-start gap-2">
                    <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                    <div>
                      <div className="font-semibold">Documented Architectural Limitation</div>
                      <div className="text-[11px] mt-0.5 text-amber-300/80">{selectedSequence.coverage_gap_notes}</div>
                    </div>
                  </div>
                )}
              </div>

              {/* Execution Results Summary Strip */}
              {executionResult && (
                <div className="p-4 rounded-xl bg-card border border-border space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      {executionResult.exit_code === 0 ? (
                        <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                      ) : (
                        <XCircle className="w-4 h-4 text-rose-400" />
                      )}
                      <span className="text-xs font-semibold text-gray-100">
                        Execution Outcome: Exit Code {executionResult.exit_code} ({executionResult.duration_ms.toFixed(1)}ms)
                      </span>
                    </div>
                    <div className="flex items-center gap-2 text-[11px] font-mono">
                      <span className="text-muted-foreground">{executionResult.total_events_emitted} events</span>
                      <span>•</span>
                      <span className="text-muted-foreground">{executionResult.total_flows_detected} unique flow(s)</span>
                    </div>
                  </div>

                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-2 border-t border-border text-[11px]">
                    <div className="flex items-center gap-1.5">
                      <span className={`w-2 h-2 rounded-full ${executionResult.schema_valid ? 'bg-emerald-400' : 'bg-rose-400'}`} />
                      <span>Schema Valid (Draft 2020-12)</span>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <span className={`w-2 h-2 rounded-full ${executionResult.flow_isolation_verified ? 'bg-emerald-400' : 'bg-rose-400'}`} />
                      <span>Flow Isolation Verified</span>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <span className={`w-2 h-2 rounded-full ${!executionResult.crash_detected ? 'bg-emerald-400' : 'bg-rose-400'}`} />
                      <span>Zero Crash / Sanitizer Clean</span>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <span className={`w-2 h-2 rounded-full ${!executionResult.hang_timeout ? 'bg-emerald-400' : 'bg-rose-400'}`} />
                      <span>Bounded Runtime (&lt;5s)</span>
                    </div>
                  </div>
                </div>
              )}

              {/* Multi-Packet Sequence Ladder / Timeline View */}
              <div className="p-4 rounded-xl bg-card border border-border space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-gray-300 uppercase tracking-wider">
                    Packet Sequence Step Ladder ({selectedSequence.steps.length} Steps)
                  </span>
                  <span className="text-[11px] text-muted-foreground font-mono">
                    Base Epoch: 2026-04-17 08:00:00 UTC
                  </span>
                </div>

                <div className="space-y-2">
                  {selectedSequence.steps.map((step) => {
                    const isNoise = step.is_noise;
                    const flags = step.tcp_flags
                      ? Object.entries(step.tcp_flags)
                          .filter(([_, v]) => v)
                          .map(([k]) => k.toUpperCase())
                          .join('+')
                      : null;

                    return (
                      <div
                        key={step.step_index}
                        className={`p-3 rounded-lg border text-xs flex flex-col sm:flex-row sm:items-center justify-between gap-3 ${
                          isNoise ? 'bg-amber-950/10 border-amber-500/20' : 'bg-muted/40 border-border'
                        }`}
                      >
                        <div className="flex items-center gap-3">
                          <div className="w-6 h-6 rounded bg-card border border-border flex items-center justify-center font-mono font-bold text-[11px] text-gray-300 shrink-0">
                            {step.step_index}
                          </div>
                          <div>
                            <div className="flex items-center gap-2 font-mono text-[11px]">
                              <span className="text-indigo-400">
                                {step.source_ip}:{step.source_port ?? 0}
                              </span>
                              <ArrowRight className="w-3 h-3 text-muted-foreground" />
                              <span className="text-emerald-400">
                                {step.destination_ip}:{step.destination_port ?? 0}
                              </span>
                              <span className="px-1.5 py-0.2 rounded bg-card border border-border text-gray-200 uppercase font-semibold">
                                {step.protocol}
                              </span>
                              {flags && (
                                <span className="px-1.5 py-0.2 rounded bg-indigo-500/10 text-indigo-300 border border-indigo-500/20 font-bold">
                                  [{flags}]
                                </span>
                              )}
                            </div>
                            <div className="text-[11px] text-muted-foreground mt-0.5">
                              {step.label || 'Packet step'}
                            </div>
                          </div>
                        </div>

                        <div className="flex items-center gap-3 font-mono text-[11px] text-muted-foreground">
                          {step.tcp_seq !== undefined && <span>Seq: {step.tcp_seq}</span>}
                          {step.tcp_ack !== undefined && <span>Ack: {step.tcp_ack}</span>}
                          <span className="flex items-center gap-1 text-gray-400">
                            <Clock className="w-3 h-3" />
                            +{(step.timestamp_offset_ns / 1_000_000).toFixed(1)}ms
                          </span>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* State Transitions Table */}
              <div className="p-4 rounded-xl bg-card border border-border space-y-3">
                <span className="text-xs font-semibold text-gray-300 uppercase tracking-wider">
                  Expected State Transitions ({selectedSequence.expected_transitions.length})
                </span>
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs">
                    <thead>
                      <tr className="border-b border-border text-muted-foreground">
                        <th className="pb-2 font-medium">Step</th>
                        <th className="pb-2 font-medium">Flow ID</th>
                        <th className="pb-2 font-medium">Expected State</th>
                        <th className="pb-2 font-medium">Rationale</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-border/50">
                      {selectedSequence.expected_transitions.map((t, idx) => (
                        <tr key={idx} className="hover:bg-muted/30">
                          <td className="py-2 font-mono">{t.step_index}</td>
                          <td className="py-2 font-mono text-indigo-400 truncate max-w-[200px]">{t.flow_id}</td>
                          <td className="py-2">
                            <span className="px-2 py-0.5 rounded font-mono text-[11px] bg-indigo-500/10 text-indigo-300 border border-indigo-500/20 font-semibold">
                              {t.expected_state}
                            </span>
                          </td>
                          <td className="py-2 text-muted-foreground">{t.rationale}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </>
          ) : (
            <div className="p-12 text-center text-xs text-muted-foreground border border-dashed border-border rounded-xl">
              Select a sequence from the left catalog to inspect packet ladder and state machine transitions.
            </div>
          )}

          {/* Sequence Findings & Minimizer Section */}
          <div className="p-4 rounded-xl bg-card border border-border space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h4 className="text-sm font-semibold text-gray-100">
                  Sequence Findings &amp; Delta Debugging Minimizer ({findings.length})
                </h4>
                <p className="text-xs text-muted-foreground">
                  Anomalies, crashes, and state discrepancies detected during sequence execution.
                </p>
              </div>
            </div>

            <div className="space-y-3">
              {findings.map((f) => (
                <div key={f.finding_id} className="p-3.5 rounded-lg border border-border bg-muted/20 space-y-2">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase ${
                          f.severity === 'CRITICAL'
                            ? 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                            : 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                        }`}
                      >
                        {f.severity}
                      </span>
                      <span className="text-xs font-semibold text-gray-200">{f.title}</span>
                    </div>
                    <span className="text-[11px] text-muted-foreground font-mono">{f.category}</span>
                  </div>

                  <p className="text-xs text-muted-foreground">{f.description}</p>
                  <div className="p-2 rounded bg-card border border-border font-mono text-[11px] text-gray-300 overflow-x-auto">
                    {f.reproduction_command}
                  </div>

                  <div className="flex items-center justify-end gap-2 pt-1">
                    <button
                      onClick={() => handleMinimizeFinding(f.finding_id)}
                      disabled={isMinimizing || f.minimized}
                      className="px-2.5 py-1 rounded bg-muted hover:bg-border text-gray-200 text-xs font-medium border border-border flex items-center gap-1.5 disabled:opacity-50 transition"
                    >
                      <Minimize2 className="w-3.5 h-3.5 text-indigo-400" />
                      <span>{f.minimized ? 'Minimized' : 'Delta Minimize'}</span>
                    </button>
                    <button
                      onClick={() => handlePromoteRegression(f.finding_id)}
                      disabled={f.is_regression}
                      className="px-2.5 py-1 rounded bg-muted hover:bg-border text-gray-200 text-xs font-medium border border-border flex items-center gap-1.5 disabled:opacity-50 transition"
                    >
                      <FileCode className="w-3.5 h-3.5 text-emerald-400" />
                      <span>{f.is_regression ? 'Promoted' : 'Promote to Regression'}</span>
                    </button>
                    <button
                      onClick={() => handleDownloadBundle(f.finding_id)}
                      className="px-2.5 py-1 rounded bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold flex items-center gap-1.5 transition"
                    >
                      <Download className="w-3.5 h-3.5" />
                      <span>Download Repro Bundle</span>
                    </button>
                  </div>
                </div>
              ))}

              {findings.length === 0 && (
                <div className="p-6 text-center text-xs text-muted-foreground border border-dashed border-border rounded-lg">
                  Zero active sequence findings. All evaluated state machines conform to expectations.
                </div>
              )}
            </div>
          </div>

          {/* Regression Ledger Table */}
          <div className="p-4 rounded-xl bg-card border border-border space-y-3">
            <h4 className="text-sm font-semibold text-gray-100">
              Sequence Regression Test Ledger ({regressions.length})
            </h4>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-border text-muted-foreground">
                    <th className="pb-2 font-medium">Regression ID</th>
                    <th className="pb-2 font-medium">Name</th>
                    <th className="pb-2 font-medium">Sequence Type</th>
                    <th className="pb-2 font-medium">Expected Exit</th>
                    <th className="pb-2 font-medium">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/50">
                  {regressions.map((r) => (
                    <tr key={r.regression_id} className="hover:bg-muted/30">
                      <td className="py-2 font-mono text-indigo-400">{r.regression_id}</td>
                      <td className="py-2 text-gray-200">{r.name}</td>
                      <td className="py-2 font-mono text-[11px] text-muted-foreground">{r.sequence_type}</td>
                      <td className="py-2 font-mono">{r.expected_exit_code}</td>
                      <td className="py-2">
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-semibold">
                          Active Invariant
                        </span>
                      </td>
                    </tr>
                  ))}
                  {regressions.length === 0 && (
                    <tr>
                      <td colSpan={5} className="py-4 text-center text-muted-foreground">
                        No sequence regressions registered yet.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>

      {/* Coverage Gaps & Limitations Modal */}
      {showCoverageModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div className="bg-card border border-border rounded-xl max-w-2xl w-full p-6 space-y-4 shadow-xl">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <ShieldCheck className="w-5 h-5 text-indigo-400" />
                <h3 className="text-base font-bold text-gray-100">
                  Engine Coverage Boundaries &amp; Documented Limitations
                </h3>
              </div>
              <button
                onClick={() => setShowCoverageModal(false)}
                className="text-muted-foreground hover:text-gray-200 text-sm"
              >
                ✕
              </button>
            </div>

            <p className="text-xs text-muted-foreground">
              Engineering honesty is mandatory in this architecture. The following limitations reflect actual C++ analyzer capabilities.
            </p>

            <div className="space-y-3 max-h-[400px] overflow-y-auto">
              <div className="p-3 rounded-lg bg-muted/40 border border-border space-y-1.5">
                <div className="text-xs font-semibold text-emerald-400">Supported State Machines</div>
                <div className="flex flex-wrap gap-1.5">
                  {supportedCapabilities.length > 0 ? (
                    supportedCapabilities.map((cap, i) => (
                      <span
                        key={i}
                        className="px-2 py-0.5 rounded bg-card border border-border text-[11px] font-mono text-gray-300"
                      >
                        {cap}
                      </span>
                    ))
                  ) : (
                    <span className="text-xs text-muted-foreground italic">No capabilities recorded</span>
                  )}
                </div>
              </div>

              <div className="space-y-2">
                <div className="text-xs font-semibold text-amber-400">Explicit Architectural Coverage Gaps</div>
                {documentedGaps.length > 0 ? (
                  documentedGaps.map((gap, i) => (
                    <div key={i} className="p-3 rounded-lg bg-card border border-border space-y-1 text-xs">
                      <div className="flex items-center justify-between">
                        <span className="font-semibold text-gray-200">{gap.feature}</span>
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-amber-500/10 text-amber-400 border border-amber-500/20">
                          {gap.limitation_status}
                        </span>
                      </div>
                      <div className="text-muted-foreground text-[11px]">{gap.description}</div>
                      <div className="text-[11px] text-gray-300 font-mono">Engine Behavior: {gap.behavior}</div>
                    </div>
                  ))
                ) : (
                  <div className="text-xs text-muted-foreground italic">No architectural gaps documented</div>
                )}
              </div>
            </div>

            <div className="pt-2 flex justify-end">
              <button
                onClick={() => setShowCoverageModal(false)}
                className="px-4 py-1.5 rounded-lg bg-muted hover:bg-border text-gray-200 text-xs font-medium"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
