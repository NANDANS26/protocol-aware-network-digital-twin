import React, { useState, useEffect, useCallback } from 'react';
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
} from 'lucide-react';
import { apiClient } from '../../api/client';
import type {
  ProtocolSequence,
  SequenceExecutionResult,
  SequenceFinding,
  SequenceRegressionFixture,
  SequenceDifferentialResult,
  CoverageGapsResponse,
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
  const [isDiffRunning, setIsDiffRunning] = useState(false);
  const [isRunning, setIsRunning] = useState(false);
  const [isGenerating, setIsGenerating] = useState(false);
  const [isMinimizing, setIsMinimizing] = useState(false);
  const [showCoverageModal, setShowCoverageModal] = useState(false);
  const [filterType, setFilterType] = useState<string>('ALL');
  const [seed, setSeed] = useState(42);

  const fetchSequences = useCallback(async () => {
    try {
      const typeParam = filterType === 'ALL' ? undefined : filterType;
      const list = await apiClient.listProtocolSequences(typeParam);
      setSequences(list);
      if (list.length > 0 && !selectedSequence) {
        setSelectedSequence(list[0] ?? null);
      }
    } catch (err) {
      console.error('Failed to load protocol sequences:', err);
    }
  }, [filterType, selectedSequence]);

  const fetchFindingsAndRegressions = useCallback(async () => {
    try {
      const [fList, rList, gaps] = await Promise.all([
        apiClient.listSequenceFindings(),
        apiClient.listSequenceRegressions(),
        apiClient.getCoverageGaps(),
      ]);
      setFindings(fList);
      setRegressions(rList);
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
    try {
      const generated = await apiClient.generateSequenceSuite(seed);
      setSequences(generated);
      if (generated.length > 0) {
        setSelectedSequence(generated[0] ?? null);
      }
      await fetchFindingsAndRegressions();
    } catch (err) {
      console.error('Failed to generate sequence suite:', err);
    } finally {
      setIsGenerating(false);
    }
  };

  const handleRunSequence = async (seqId: string) => {
    setIsRunning(true);
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
      setSequences((prev) => [mutated, ...prev]);
      setSelectedSequence(mutated);
    } catch (err) {
      console.error('Sequence mutation error:', err);
    }
  };

  const handleRunDifferential = async () => {
    if (!selectedSequence) return;
    setIsDiffRunning(true);
    try {
      const diff = await apiClient.runSequenceDifferential({
        sequence_id: selectedSequence.sequence_id,
        mode: 'pcap_vs_pcapng',
      });
      setDiffResult(diff);
    } catch (err) {
      console.error('Differential execution error:', err);
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

  return (
    <div className="space-y-6">
      {/* Top Banner & Control Strip */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-5 rounded-xl bg-card border border-border shadow-sm">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-lg bg-indigo-500/10 border border-indigo-500/20 text-indigo-400">
              <Layers className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-lg font-bold text-gray-100">
                  Stateful Protocol Fuzzing & Multi-Packet Sequence Verification
                </h2>
                <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-indigo-500/10 text-indigo-400 border border-indigo-500/20 font-semibold">
                  Phase 05 Active
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
            <span>Coverage Gaps & Limits</span>
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

      {/* Metrics Row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-card border border-border">
          <div className="text-xs text-muted-foreground">Stored Sequences</div>
          <div className="text-xl font-bold text-gray-100 mt-1">{sequences.length}</div>
        </div>
        <div className="p-4 rounded-xl bg-card border border-border">
          <div className="text-xs text-muted-foreground">Sequence Findings</div>
          <div className="text-xl font-bold text-amber-400 mt-1">{findings.length}</div>
        </div>
        <div className="p-4 rounded-xl bg-card border border-border">
          <div className="text-xs text-muted-foreground">Promoted Regressions</div>
          <div className="text-xl font-bold text-emerald-400 mt-1">{regressions.length}</div>
        </div>
        <div className="p-4 rounded-xl bg-card border border-border">
          <div className="text-xs text-muted-foreground">Generation Seed</div>
          <input
            type="number"
            value={seed}
            onChange={(e) => setSeed(parseInt(e.target.value) || 0)}
            className="w-full bg-muted border border-border rounded px-2 py-0.5 mt-1 text-sm font-bold text-indigo-400 font-mono"
          />
        </div>
      </div>

      {/* Differential Banner if active */}
      {diffResult && (
        <div className={`p-4 rounded-lg border flex items-center justify-between gap-4 ${diffResult.equivalent ? 'bg-emerald-950/20 border-emerald-800/40 text-emerald-200' : 'bg-rose-950/20 border-rose-800/40 text-rose-200'}`}>
          <div className="flex items-center gap-3">
            {diffResult.equivalent ? <CheckCircle2 className="w-5 h-5 text-emerald-400" /> : <XCircle className="w-5 h-5 text-rose-400" />}
            <div>
              <div className="text-xs font-semibold">
                Sequence Differential Equivalence: {diffResult.equivalent ? 'EQUIVALENT OUTPUT CONFIRMED' : 'DIVERGENCE DETECTED'}
              </div>
              <div className="text-[11px] text-muted-foreground mt-0.5 font-mono">
                {diffResult.baseline_name} ({diffResult.baseline_event_count} events) vs {diffResult.candidate_name} ({diffResult.candidate_event_count} events) evaluated in {diffResult.duration_ms.toFixed(1)}ms.
              </div>
            </div>
          </div>
          <button onClick={() => setDiffResult(null)} className="text-xs text-muted-foreground hover:text-gray-200">
            Dismiss
          </button>
        </div>
      )}

      {/* Main Split Layout: Sequence Selector (Left) & Inspector (Right) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Sequence Catalog */}
        <div className="lg:col-span-4 space-y-4">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-gray-300 uppercase tracking-wider">Protocol Sequences</span>
            <select
              value={filterType}
              onChange={(e) => setFilterType(e.target.value)}
              className="bg-muted border border-border rounded px-2 py-1 text-xs text-gray-200"
            >
              <option value="ALL">All Types</option>
              <option value="TCP_HANDSHAKE_TEARDOWN">TCP Handshake/Teardown</option>
              <option value="TCP_RETRANSMISSION_OOO">TCP Retransmission/OOO</option>
              <option value="TCP_RST_AND_ABORT">TCP RST Abort</option>
              <option value="TCP_SIMULTANEOUS_FLOWS">Simultaneous Flows</option>
              <option value="IP_FRAGMENTATION">IP Fragmentation</option>
              <option value="HTTP_SEGMENTED_STREAM">HTTP Stream Reassembly</option>
            </select>
          </div>

          <div className="space-y-2 max-h-[640px] overflow-y-auto pr-1">
            {sequences.map((seq) => {
              const isSelected = selectedSequence?.sequence_id === seq.sequence_id;
              return (
                <div
                  key={seq.sequence_id}
                  onClick={() => {
                    setSelectedSequence(seq);
                    setExecutionResult(null);
                  }}
                  className={`p-3.5 rounded-xl border text-left cursor-pointer transition ${isSelected ? 'bg-indigo-950/20 border-indigo-500/50 shadow-sm' : 'bg-card border-border hover:border-gray-700'}`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-semibold text-gray-100 truncate">{seq.name}</span>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-medium ${seq.is_supported ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' : 'bg-amber-500/10 text-amber-400 border border-amber-500/20'}`}>
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

            {sequences.length === 0 && (
              <div className="p-8 text-center text-xs text-muted-foreground border border-dashed border-border rounded-xl">
                No sequences generated yet. Click "Generate Canonical Suite" above.
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
                  <div className="flex items-center gap-2">
                    <button
                      onClick={handleRunDifferential}
                      disabled={isDiffRunning}
                      className="px-3 py-1.5 rounded-lg bg-muted hover:bg-border text-gray-200 text-xs font-medium border border-border flex items-center gap-1.5"
                    >
                      <Zap className={`w-3.5 h-3.5 text-amber-400 ${isDiffRunning ? 'animate-spin' : ''}`} />
                      <span>PCAP vs PCAPNG</span>
                    </button>
                    <button
                      onClick={() => handleRunSequence(selectedSequence.sequence_id)}
                      disabled={isRunning}
                      className="px-4 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold shadow-sm transition flex items-center gap-1.5"
                    >
                      <Play className="w-3.5 h-3.5 fill-current" />
                      <span>{isRunning ? 'Executing...' : 'Execute Sequence'}</span>
                    </button>
                  </div>
                </div>

                {/* Mutation Injectors */}
                <div className="pt-2 border-t border-border flex flex-wrap items-center gap-2 text-xs">
                  <span className="text-muted-foreground flex items-center gap-1">
                    <Shuffle className="w-3 h-3" />
                    Inject Mutation:
                  </span>
                  <button
                    onClick={() => handleMutateSequence('INSERT_UNRELATED_NOISE')}
                    className="px-2 py-0.5 rounded bg-muted hover:bg-border text-gray-300 text-[11px]"
                  >
                    + Background ICMP Noise
                  </button>
                  <button
                    onClick={() => handleMutateSequence('REORDER_PACKETS')}
                    className="px-2 py-0.5 rounded bg-muted hover:bg-border text-gray-300 text-[11px]"
                  >
                    Swap Last 2 Steps
                  </button>
                  <button
                    onClick={() => handleMutateSequence('DUPLICATE_PACKET')}
                    className="px-2 py-0.5 rounded bg-muted hover:bg-border text-gray-300 text-[11px]"
                  >
                    Duplicate Packet
                  </button>
                  <button
                    onClick={() => handleMutateSequence('SHIFT_TIMESTAMPS')}
                    className="px-2 py-0.5 rounded bg-muted hover:bg-border text-gray-300 text-[11px]"
                  >
                    Shift Timestamps (+100ms)
                  </button>
                  <button
                    onClick={() => handleMutateSequence('TRUNCATE_SEQUENCE')}
                    className="px-2 py-0.5 rounded bg-muted hover:bg-border text-gray-300 text-[11px]"
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
                        className={`p-3 rounded-lg border text-xs flex flex-col sm:flex-row sm:items-center justify-between gap-3 ${isNoise ? 'bg-amber-950/10 border-amber-500/20' : 'bg-muted/40 border-border'}`}
                      >
                        <div className="flex items-center gap-3">
                          <div className="w-6 h-6 rounded bg-card border border-border flex items-center justify-center font-mono font-bold text-[11px] text-gray-300 shrink-0">
                            {step.step_index}
                          </div>
                          <div>
                            <div className="flex items-center gap-2 font-mono text-[11px]">
                              <span className="text-indigo-400">{step.source_ip}:{step.source_port ?? 0}</span>
                              <ArrowRight className="w-3 h-3 text-muted-foreground" />
                              <span className="text-emerald-400">{step.destination_ip}:{step.destination_port ?? 0}</span>
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
                          {step.tcp_seq !== undefined && (
                            <span>Seq: {step.tcp_seq}</span>
                          )}
                          {step.tcp_ack !== undefined && (
                            <span>Ack: {step.tcp_ack}</span>
                          )}
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
                  Sequence Findings & Delta Debugging Minimizer ({findings.length})
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
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase ${f.severity === 'CRITICAL' ? 'bg-rose-500/10 text-rose-400 border border-rose-500/20' : 'bg-amber-500/10 text-amber-400 border border-amber-500/20'}`}>
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
                      className="px-2.5 py-1 rounded bg-muted hover:bg-border text-gray-200 text-xs font-medium border border-border flex items-center gap-1.5 disabled:opacity-50"
                    >
                      <Minimize2 className="w-3.5 h-3.5 text-indigo-400" />
                      <span>{f.minimized ? 'Minimized' : 'Delta Minimize'}</span>
                    </button>
                    <button
                      onClick={() => handlePromoteRegression(f.finding_id)}
                      disabled={f.is_regression}
                      className="px-2.5 py-1 rounded bg-muted hover:bg-border text-gray-200 text-xs font-medium border border-border flex items-center gap-1.5 disabled:opacity-50"
                    >
                      <FileCode className="w-3.5 h-3.5 text-emerald-400" />
                      <span>{f.is_regression ? 'Promoted' : 'Promote to Regression'}</span>
                    </button>
                    <button
                      onClick={() => handleDownloadBundle(f.finding_id)}
                      className="px-2.5 py-1 rounded bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold flex items-center gap-1.5"
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
      {showCoverageModal && coverageGaps && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div className="bg-card border border-border rounded-xl max-w-2xl w-full p-6 space-y-4 shadow-xl">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <ShieldCheck className="w-5 h-5 text-indigo-400" />
                <h3 className="text-base font-bold text-gray-100">
                  Engine Coverage Boundaries & Documented Limitations
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
              Engineering honesty is mandatory in this architecture. The following limitations reflect the actual C++ analyzer capabilities.
            </p>

            <div className="space-y-3 max-h-[400px] overflow-y-auto">
              <div className="p-3 rounded-lg bg-muted/40 border border-border space-y-1.5">
                <div className="text-xs font-semibold text-emerald-400">Supported State Machines</div>
                <div className="flex flex-wrap gap-1.5">
                  {coverageGaps.supported_capabilities.map((cap, i) => (
                    <span key={i} className="px-2 py-0.5 rounded bg-card border border-border text-[11px] font-mono text-gray-300">
                      {cap}
                    </span>
                  ))}
                </div>
              </div>

              <div className="space-y-2">
                <div className="text-xs font-semibold text-amber-400">Explicit Architectural Coverage Gaps</div>
                {coverageGaps.documented_coverage_gaps.map((gap, i) => (
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
                ))}
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
