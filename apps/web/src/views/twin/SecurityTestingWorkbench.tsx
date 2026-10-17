import React, { useState, useEffect, useCallback } from 'react';
import {
  ShieldAlert,
  Bug,
  Play,
  RotateCw,
  Sliders,
  CheckCircle2,
  XCircle,
  FileCode,
  Download,
  Terminal,
  Zap,
  Minimize2,
  Filter,
  Layers,
} from 'lucide-react';
import { apiClient } from '../../api/client';
import { StatefulSequenceWorkbench } from './StatefulSequenceWorkbench';
import type {
  TestCampaign,
  TestCase,
  Finding,
  RegressionFixture,
  ProtocolTarget,
  GenerationStrategy,
  DifferentialResult,
  CampaignCreateRequest,
} from '../../types/testing';

const ALL_TARGETS: ProtocolTarget[] = [
  'ETHERNET',
  'VLAN',
  'IPV4',
  'IPV6',
  'TCP',
  'UDP',
  'DNS',
  'HTTP',
  'TLS_CLIENT_HELLO',
  'QUIC_CLASSIFIER',
];

const ALL_STRATEGIES: GenerationStrategy[] = [
  'BASELINE_CONFORMANCE',
  'MUTATION_FUZZING',
  'BOUNDARY_EDGE_CASES',
  'MALFORMED_INPUTS',
];

export const SecurityTestingWorkbench: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'campaigns' | 'sequences' | 'findings' | 'regressions'>('campaigns');
  const [campaigns, setCampaigns] = useState<TestCampaign[]>([]);
  const [selectedCampaign, setSelectedCampaign] = useState<TestCampaign | null>(null);
  const [testCases, setTestCases] = useState<TestCase[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [regressions, setRegressions] = useState<RegressionFixture[]>([]);
  const [diffResult, setDiffResult] = useState<DifferentialResult | null>(null);
  const [isDiffRunning, setIsDiffRunning] = useState(false);
  const [isLoading, setIsLoading] = useState(false);

  // Campaign launcher form state
  const [showLauncher, setShowLauncher] = useState(false);
  const [name, setName] = useState('Protocol Robustness Campaign');
  const [selectedTargets, setSelectedTargets] = useState<ProtocolTarget[]>([
    'IPV4',
    'TCP',
    'DNS',
    'HTTP',
  ]);
  const [selectedStrategies, setSelectedStrategies] = useState<GenerationStrategy[]>([
    'BASELINE_CONFORMANCE',
    'MUTATION_FUZZING',
    'MALFORMED_INPUTS',
  ]);
  const [maxCases, setMaxCases] = useState(3);
  const [seed, setSeed] = useState(1337);
  const [isLaunching, setIsLaunching] = useState(false);

  // Finding filter state
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');

  const fetchData = useCallback(async () => {
    setIsLoading(true);
    try {
      const [cList, fList, rList] = await Promise.all([
        apiClient.listTestingCampaigns(),
        apiClient.listTestingFindings(),
        apiClient.listRegressionFixtures(),
      ]);
      setCampaigns(cList);
      setFindings(fList);
      setRegressions(rList);

      if (cList.length > 0 && !selectedCampaign) {
        setSelectedCampaign(cList[0]!);
        const cases = await apiClient.listTestingCases(cList[0]!.campaign_id);
        setTestCases(cases);
      }
    } catch (e) {
      console.error('Failed to load testing data:', e);
    } finally {
      setIsLoading(false);
    }
  }, [selectedCampaign]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const handleSelectCampaign = async (c: TestCampaign) => {
    setSelectedCampaign(c);
    try {
      const cases = await apiClient.listTestingCases(c.campaign_id);
      setTestCases(cases);
    } catch (e) {
      console.error('Failed to load cases:', e);
    }
  };

  const handleLaunchCampaign = async () => {
    setIsLaunching(true);
    try {
      const req: CampaignCreateRequest = {
        name,
        protocol_targets: selectedTargets,
        strategies: selectedStrategies,
        max_cases_per_target: maxCases,
        seed,
        run_immediately: true,
      };
      const created = await apiClient.createTestingCampaign(req);
      setShowLauncher(false);
      await fetchData();
      setSelectedCampaign(created);
      const cases = await apiClient.listTestingCases(created.campaign_id);
      setTestCases(cases);
    } catch (e) {
      console.error('Failed to launch campaign:', e);
    } finally {
      setIsLaunching(false);
    }
  };

  const handleRunDifferential = async () => {
    setIsDiffRunning(true);
    try {
      const res = await apiClient.runQuickDifferential();
      setDiffResult(res);
    } catch (e) {
      console.error('Differential run failed:', e);
    } finally {
      setIsDiffRunning(false);
    }
  };

  const handleMinimizeFinding = async (findingId: string) => {
    try {
      const artifact = await apiClient.minimizeFinding(findingId);
      alert(`Minimization Complete: Reduced from ${artifact.original_size_bytes}B to ${artifact.minimized_size_bytes}B!`);
      await fetchData();
    } catch (e) {
      alert(`Minimization error: ${e}`);
    }
  };

  const handlePromoteFinding = async (findingId: string) => {
    const namePrompt = prompt('Enter a name for this permanent regression test:', 'Protocol Parser Boundary Regression');
    if (!namePrompt) return;
    try {
      const fixture = await apiClient.promoteFinding(findingId, namePrompt);
      alert(`Promoted finding to regression fixture: ${fixture.fixture_id}`);
      await fetchData();
    } catch (e) {
      alert(`Promotion error: ${e}`);
    }
  };

  const handleExportBundle = async (findingId: string) => {
    try {
      const blob = await apiClient.exportFindingBundle(findingId);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `reproduction_bundle_${findingId}.zip`;
      document.body.appendChild(a);
      a.click();
      a.remove();
    } catch (e) {
      alert(`Export error: ${e}`);
    }
  };

  const handleRunRegression = async (fixtureId: string) => {
    try {
      const res = await apiClient.runRegressionFixture(fixtureId);
      alert(`Regression Run Result: ${res.passed ? 'PASSED (Clean)' : 'FAILED (Regression Triggered)'}`);
      await fetchData();
    } catch (e) {
      alert(`Run failed: ${e}`);
    }
  };

  const filteredFindings = findings.filter((f) => {
    if (severityFilter === 'ALL') return true;
    return f.severity === severityFilter;
  });

  return (
    <div className="space-y-6">
      {/* Top Header & Operational Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-5 rounded-xl bg-card border border-border shadow-sm">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-lg bg-indigo-500/10 border border-indigo-500/20 text-indigo-400">
              <ShieldAlert className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-lg font-bold text-gray-100">
                  Protocol Security Testing & Differential Fuzzing
                </h2>
                <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-semibold">
                  Phase 04 Operational
                </span>
              </div>
              <p className="text-xs text-muted-foreground mt-0.5">
                Deterministic protocol test generation, metamorphic invariance proofs, and offline C++ parser fault isolation.
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            onClick={handleRunDifferential}
            disabled={isDiffRunning}
            className="px-3.5 py-2 rounded-lg bg-card hover:bg-muted text-gray-200 text-xs font-medium border border-border transition flex items-center gap-2"
          >
            <Zap className={`w-3.5 h-3.5 text-amber-400 ${isDiffRunning ? 'animate-spin' : ''}`} />
            <span>{isDiffRunning ? 'Running Diff...' : 'Run Differential Check'}</span>
          </button>
          <button
            onClick={() => setShowLauncher(true)}
            className="px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold shadow-sm transition flex items-center gap-2"
          >
            <Play className="w-3.5 h-3.5 fill-current" />
            <span>Configure & Launch Campaign</span>
          </button>
        </div>
      </div>

      {/* Differential Result Banner if present */}
      {diffResult && (
        <div className={`p-4 rounded-lg border flex items-center justify-between gap-4 ${diffResult.equivalent ? 'bg-emerald-950/20 border-emerald-800/40 text-emerald-200' : 'bg-rose-950/20 border-rose-800/40 text-rose-200'}`}>
          <div className="flex items-center gap-3">
            {diffResult.equivalent ? <CheckCircle2 className="w-5 h-5 text-emerald-400" /> : <XCircle className="w-5 h-5 text-rose-400" />}
            <div>
              <div className="text-xs font-semibold">
                Differential Equivalence Verification: {diffResult.equivalent ? 'PASSED' : 'DISCREPANCY DETECTED'}
              </div>
              <div className="text-[11px] text-muted-foreground mt-0.5 font-mono">
                Classic PCAP ({diffResult.baseline_events_count} events) vs PCAPNG ({diffResult.candidate_events_count} events) evaluated in {diffResult.duration_ms.toFixed(1)}ms.
              </div>
            </div>
          </div>
          <button onClick={() => setDiffResult(null)} className="text-xs text-muted-foreground hover:text-gray-200">
            Dismiss
          </button>
        </div>
      )}

      {/* Metrics Summary Strip */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-card border border-border">
          <div className="text-xs text-muted-foreground">Active Campaigns</div>
          <div className="text-xl font-bold text-gray-100 mt-1">{campaigns.length}</div>
        </div>
        <div className="p-4 rounded-xl bg-card border border-border">
          <div className="text-xs text-muted-foreground">Total Cases Executed</div>
          <div className="text-xl font-bold text-indigo-400 mt-1">
            {campaigns.reduce((acc, c) => acc + c.cases_executed, 0)}
          </div>
        </div>
        <div className="p-4 rounded-xl bg-card border border-border">
          <div className="text-xs text-muted-foreground">Safe Header Rejections</div>
          <div className="text-xl font-bold text-emerald-400 mt-1">
            {campaigns.reduce((acc, c) => acc + c.rejected_count, 0)}
          </div>
        </div>
        <div className="p-4 rounded-xl bg-card border border-border">
          <div className="text-xs text-muted-foreground">Triaged Findings</div>
          <div className="text-xl font-bold text-amber-400 mt-1">{findings.length}</div>
        </div>
      </div>

      {/* Workbench Subtabs */}
      <div className="flex items-center gap-2 border-b border-border pb-2">
        <button
          onClick={() => setActiveTab('campaigns')}
          className={`px-3 py-1.5 rounded-lg text-xs font-medium transition flex items-center gap-2 ${activeTab === 'campaigns' ? 'bg-indigo-600/10 text-indigo-400 border border-indigo-500/30' : 'text-muted-foreground hover:text-gray-200'}`}
        >
          <Sliders className="w-3.5 h-3.5" />
          <span>Campaigns & Test Cases</span>
        </button>
        <button
          onClick={() => setActiveTab('sequences')}
          className={`px-3 py-1.5 rounded-lg text-xs font-medium transition flex items-center gap-2 ${activeTab === 'sequences' ? 'bg-indigo-600/10 text-indigo-400 border border-indigo-500/30' : 'text-muted-foreground hover:text-gray-200'}`}
        >
          <Layers className="w-3.5 h-3.5" />
          <span>Stateful Sequences & State Machine</span>
        </button>
        <button
          onClick={() => setActiveTab('findings')}
          className={`px-3 py-1.5 rounded-lg text-xs font-medium transition flex items-center gap-2 ${activeTab === 'findings' ? 'bg-indigo-600/10 text-indigo-400 border border-indigo-500/30' : 'text-muted-foreground hover:text-gray-200'}`}
        >
          <Bug className="w-3.5 h-3.5" />
          <span>Findings & Defect Triage ({findings.length})</span>
        </button>
        <button
          onClick={() => setActiveTab('regressions')}
          className={`px-3 py-1.5 rounded-lg text-xs font-medium transition flex items-center gap-2 ${activeTab === 'regressions' ? 'bg-indigo-600/10 text-indigo-400 border border-indigo-500/30' : 'text-muted-foreground hover:text-gray-200'}`}
        >
          <FileCode className="w-3.5 h-3.5" />
          <span>Regression Test Ledger ({regressions.length})</span>
        </button>
      </div>

      {/* Tab 1: Campaigns & Test Cases */}
      {activeTab === 'campaigns' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="text-xs text-muted-foreground">Select Campaign:</span>
              <select
                value={selectedCampaign?.campaign_id || ''}
                onChange={(e) => {
                  const c = campaigns.find((x) => x.campaign_id === e.target.value);
                  if (c) handleSelectCampaign(c);
                }}
                className="bg-muted border border-border rounded px-2.5 py-1 text-xs text-gray-200"
              >
                {campaigns.map((c) => (
                  <option key={c.campaign_id} value={c.campaign_id}>
                    {c.name} ({c.status})
                  </option>
                ))}
              </select>
            </div>
            <button
              onClick={fetchData}
              className="p-1.5 rounded hover:bg-muted text-muted-foreground hover:text-gray-200"
              title="Refresh"
            >
              <RotateCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
            </button>
          </div>

          {selectedCampaign && (
            <div className="p-4 rounded-xl bg-card border border-border space-y-3">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-semibold text-gray-100">{selectedCampaign.name}</h3>
                  <div className="text-[11px] text-muted-foreground font-mono mt-0.5">
                    ID: {selectedCampaign.campaign_id} • Seed: {selectedCampaign.seed} • Duration: {selectedCampaign.duration_ms}ms
                  </div>
                </div>
                <span className="px-2 py-0.5 rounded text-[11px] font-mono uppercase bg-indigo-500/10 text-indigo-400 border border-indigo-500/20 font-semibold">
                  {selectedCampaign.status}
                </span>
              </div>

              {/* Progress bar */}
              <div className="w-full bg-muted rounded-full h-2 overflow-hidden">
                <div
                  className="bg-indigo-500 h-2 rounded-full transition-all duration-300"
                  style={{
                    width: `${selectedCampaign.total_cases > 0 ? (selectedCampaign.cases_executed / selectedCampaign.total_cases) * 100 : 0}%`,
                  }}
                />
              </div>

              <div className="flex items-center gap-6 text-xs text-muted-foreground pt-1">
                <div>Total Cases: <span className="text-gray-200 font-semibold">{selectedCampaign.total_cases}</span></div>
                <div>Executed: <span className="text-indigo-400 font-semibold">{selectedCampaign.cases_executed}</span></div>
                <div>Valid Passes: <span className="text-emerald-400 font-semibold">{selectedCampaign.passed_count}</span></div>
                <div>Safe Rejections: <span className="text-blue-400 font-semibold">{selectedCampaign.rejected_count}</span></div>
                <div>Findings / Failures: <span className="text-rose-400 font-semibold">{selectedCampaign.findings_count}</span></div>
              </div>
            </div>
          )}

          {/* Test cases table */}
          <div className="rounded-xl border border-border bg-card overflow-hidden">
            <div className="px-4 py-3 bg-muted/40 border-b border-border flex items-center justify-between">
              <span className="text-xs font-semibold text-gray-200">
                Generated Test Cases ({testCases.length})
              </span>
            </div>
            <div className="overflow-x-auto max-h-96">
              <table className="w-full text-left text-xs">
                <thead className="bg-muted/60 text-muted-foreground font-medium border-b border-border">
                  <tr>
                    <th className="px-3 py-2">Index</th>
                    <th className="px-3 py-2">Target</th>
                    <th className="px-3 py-2">Strategy</th>
                    <th className="px-3 py-2">Mutation Sequence</th>
                    <th className="px-3 py-2">Expected</th>
                    <th className="px-3 py-2">Status</th>
                    <th className="px-3 py-2">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {testCases.map((tc) => (
                    <tr key={tc.case_id} className="hover:bg-muted/30">
                      <td className="px-3 py-2 font-mono text-[11px] text-muted-foreground">{tc.test_index}</td>
                      <td className="px-3 py-2 font-semibold text-gray-200">{tc.protocol_target}</td>
                      <td className="px-3 py-2 text-muted-foreground">{tc.generation_strategy}</td>
                      <td className="px-3 py-2 font-mono text-[11px] text-indigo-400">
                        {tc.mutation_sequence.join(', ') || 'NONE'}
                      </td>
                      <td className="px-3 py-2 text-[11px]">{tc.expected_behavior}</td>
                      <td className="px-3 py-2">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-semibold ${tc.status === 'PASSED' ? 'bg-emerald-500/10 text-emerald-400' : 'bg-rose-500/10 text-rose-400'}`}>
                          {tc.status}
                        </span>
                      </td>
                      <td className="px-3 py-2">
                        <button
                          onClick={async () => {
                            await apiClient.rerunTestCase(tc.case_id);
                            alert(`Rerun complete for ${tc.case_id}`);
                          }}
                          className="px-2 py-0.5 rounded bg-muted hover:bg-border text-gray-300 text-[11px]"
                        >
                          Rerun
                        </button>
                      </td>
                    </tr>
                  ))}
                  {testCases.length === 0 && (
                    <tr>
                      <td colSpan={7} className="text-center py-6 text-muted-foreground">
                        No test cases generated. Select or launch a campaign above.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Tab 2: Findings & Defect Triage */}
      {activeTab === 'findings' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2 space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Filter className="w-3.5 h-3.5 text-muted-foreground" />
                <span className="text-xs text-muted-foreground">Severity:</span>
                <select
                  value={severityFilter}
                  onChange={(e) => setSeverityFilter(e.target.value)}
                  className="bg-muted border border-border rounded px-2.5 py-1 text-xs text-gray-200"
                >
                  <option value="ALL">All Severities</option>
                  <option value="CRITICAL">Critical</option>
                  <option value="HIGH">High</option>
                  <option value="MEDIUM">Medium</option>
                  <option value="LOW">Low</option>
                </select>
              </div>
            </div>

            <div className="rounded-xl border border-border bg-card overflow-hidden">
              <table className="w-full text-left text-xs">
                <thead className="bg-muted/60 text-muted-foreground font-medium border-b border-border">
                  <tr>
                    <th className="px-3 py-2">Severity</th>
                    <th className="px-3 py-2">Protocol</th>
                    <th className="px-3 py-2">Category</th>
                    <th className="px-3 py-2">Actual Behavior</th>
                    <th className="px-3 py-2">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {filteredFindings.map((f) => (
                    <tr
                      key={f.finding_id}
                      onClick={() => setSelectedFinding(f)}
                      className={`cursor-pointer hover:bg-muted/40 transition ${selectedFinding?.finding_id === f.finding_id ? 'bg-indigo-950/20' : ''}`}
                    >
                      <td className="px-3 py-2">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-semibold ${f.severity === 'CRITICAL' ? 'bg-rose-500/20 text-rose-300' : f.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-300' : 'bg-amber-500/20 text-amber-300'}`}>
                          {f.severity}
                        </span>
                      </td>
                      <td className="px-3 py-2 font-semibold text-gray-200">{f.protocol_target}</td>
                      <td className="px-3 py-2 font-mono text-[11px] text-muted-foreground">{f.failure_category}</td>
                      <td className="px-3 py-2 text-[11px] text-gray-300 truncate max-w-xs">{f.actual_behavior}</td>
                      <td className="px-3 py-2 font-mono text-[10px] uppercase text-indigo-400">{f.status}</td>
                    </tr>
                  ))}
                  {filteredFindings.length === 0 && (
                    <tr>
                      <td colSpan={5} className="text-center py-8 text-muted-foreground">
                        Zero defect findings detected. All protocol parsers successfully rejected or accepted inputs within expected contracts.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Finding Detail Inspector Drawer */}
          <div className="space-y-4">
            {selectedFinding ? (
              <div className="p-5 rounded-xl bg-card border border-border space-y-4">
                <div className="flex items-center justify-between border-b border-border pb-3">
                  <div>
                    <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-muted text-gray-300">
                      {selectedFinding.finding_id}
                    </span>
                    <h4 className="text-sm font-bold text-gray-100 mt-1">{selectedFinding.protocol_target} Defect</h4>
                  </div>
                  <span className="text-xs font-semibold text-rose-400">{selectedFinding.severity}</span>
                </div>

                <div className="space-y-2 text-xs">
                  <div>
                    <span className="text-muted-foreground">Failure Category:</span>{' '}
                    <span className="font-mono text-gray-200">{selectedFinding.failure_category}</span>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Parser Component:</span>{' '}
                    <span className="font-mono text-gray-200">{selectedFinding.parser_component}</span>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Fixture SHA-256:</span>
                    <div className="font-mono text-[11px] text-indigo-400 break-all mt-0.5">
                      {selectedFinding.input_hash}
                    </div>
                  </div>
                </div>

                <div>
                  <span className="text-xs text-muted-foreground">Reproduction Command:</span>
                  <div className="p-2.5 rounded bg-muted/80 border border-border font-mono text-[11px] text-emerald-400 flex items-center justify-between mt-1">
                    <span>{selectedFinding.reproduction_command}</span>
                    <button
                      onClick={() => navigator.clipboard.writeText(selectedFinding.reproduction_command)}
                      className="text-muted-foreground hover:text-gray-200"
                      title="Copy CLI Command"
                    >
                      <Terminal className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>

                <div>
                  <span className="text-xs text-muted-foreground">Diagnostic Trace:</span>
                  <div className="p-2.5 rounded bg-muted/80 border border-border font-mono text-[11px] text-gray-300 max-h-32 overflow-y-auto mt-1">
                    {selectedFinding.diagnostic}
                  </div>
                </div>

                {/* Actions */}
                <div className="space-y-2 pt-2 border-t border-border">
                  <button
                    onClick={() => handleMinimizeFinding(selectedFinding.finding_id)}
                    className="w-full px-3 py-2 rounded bg-indigo-900/40 hover:bg-indigo-900/60 text-indigo-300 text-xs font-medium border border-indigo-700/50 flex items-center justify-center gap-2"
                  >
                    <Minimize2 className="w-3.5 h-3.5" />
                    <span>Run Delta Debugging Minimizer</span>
                  </button>
                  <button
                    onClick={() => handlePromoteFinding(selectedFinding.finding_id)}
                    className="w-full px-3 py-2 rounded bg-emerald-900/40 hover:bg-emerald-900/60 text-emerald-300 text-xs font-medium border border-emerald-700/50 flex items-center justify-center gap-2"
                  >
                    <FileCode className="w-3.5 h-3.5" />
                    <span>Promote to Regression Fixture</span>
                  </button>
                  <button
                    onClick={() => handleExportBundle(selectedFinding.finding_id)}
                    className="w-full px-3 py-2 rounded bg-muted hover:bg-border text-gray-300 text-xs font-medium flex items-center justify-center gap-2"
                  >
                    <Download className="w-3.5 h-3.5" />
                    <span>Export Reproduction Bundle (ZIP)</span>
                  </button>
                </div>
              </div>
            ) : (
              <div className="p-8 rounded-xl border border-dashed border-border text-center text-muted-foreground text-xs">
                Select a finding from the table to inspect reproduction metadata, run minimization, or promote to regression.
              </div>
            )}
          </div>
        </div>
      )}

      {/* Tab 3: Regression Test Ledger */}
      {activeTab === 'regressions' && (
        <div className="space-y-4">
          <div className="p-4 rounded-xl bg-card border border-border">
            <h3 className="text-sm font-semibold text-gray-100">Permanent Regression Verification Suite</h3>
            <p className="text-xs text-muted-foreground mt-0.5">
              Promoted defect fixtures guaranteed to execute on every build to prevent parser regressions.
            </p>
          </div>

          <div className="rounded-xl border border-border bg-card overflow-hidden">
            <table className="w-full text-left text-xs">
              <thead className="bg-muted/60 text-muted-foreground font-medium border-b border-border">
                <tr>
                  <th className="px-3 py-2">Fixture ID</th>
                  <th className="px-3 py-2">Name</th>
                  <th className="px-3 py-2">Target</th>
                  <th className="px-3 py-2">Category</th>
                  <th className="px-3 py-2">Last Run</th>
                  <th className="px-3 py-2">Status</th>
                  <th className="px-3 py-2">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {regressions.map((r) => (
                  <tr key={r.fixture_id} className="hover:bg-muted/30">
                    <td className="px-3 py-2 font-mono text-[11px] text-muted-foreground">{r.fixture_id}</td>
                    <td className="px-3 py-2 font-semibold text-gray-200">{r.name}</td>
                    <td className="px-3 py-2">{r.protocol_target}</td>
                    <td className="px-3 py-2 font-mono text-[11px] text-muted-foreground">{r.failure_category}</td>
                    <td className="px-3 py-2 text-muted-foreground">{r.last_run_at ? new Date(r.last_run_at).toLocaleTimeString() : 'Never'}</td>
                    <td className="px-3 py-2">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-semibold ${r.last_run_passed === true ? 'bg-emerald-500/10 text-emerald-400' : r.last_run_passed === false ? 'bg-rose-500/10 text-rose-400' : 'bg-muted text-gray-400'}`}>
                        {r.last_run_passed === true ? 'PASSED' : r.last_run_passed === false ? 'FAILED' : 'UNTESTED'}
                      </span>
                    </td>
                    <td className="px-3 py-2">
                      <button
                        onClick={() => handleRunRegression(r.fixture_id)}
                        className="px-2.5 py-1 rounded bg-indigo-600/20 hover:bg-indigo-600/40 text-indigo-300 text-[11px] font-medium border border-indigo-500/30"
                      >
                        Re-run
                      </button>
                    </td>
                  </tr>
                ))}
                {regressions.length === 0 && (
                  <tr>
                    <td colSpan={7} className="text-center py-6 text-muted-foreground">
                      No regression fixtures registered. Confirmed findings can be promoted to permanent regression fixtures.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Tab 4: Stateful Sequences & State Machine (Phase 05) */}
      {activeTab === 'sequences' && <StatefulSequenceWorkbench />}

      {/* Campaign Launcher Modal */}
      {showLauncher && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-card border border-border rounded-xl max-w-xl w-full p-6 space-y-4 shadow-xl">
            <div className="flex items-center justify-between border-b border-border pb-3">
              <h3 className="text-base font-bold text-gray-100 flex items-center gap-2">
                <Play className="w-4 h-4 text-indigo-400" />
                <span>Configure Protocol Security Campaign</span>
              </h3>
              <button onClick={() => setShowLauncher(false)} className="text-muted-foreground hover:text-gray-200">
                ✕
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div>
                <label className="text-muted-foreground">Campaign Name</label>
                <input
                  type="text"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  className="w-full bg-muted border border-border rounded px-3 py-1.5 mt-1 text-gray-200"
                />
              </div>

              <div>
                <label className="text-muted-foreground">Protocol Targets</label>
                <div className="grid grid-cols-3 gap-2 mt-1">
                  {ALL_TARGETS.map((t) => (
                    <label key={t} className="flex items-center gap-2 p-2 rounded bg-muted/50 border border-border cursor-pointer">
                      <input
                        type="checkbox"
                        checked={selectedTargets.includes(t)}
                        onChange={(e) => {
                          if (e.target.checked) setSelectedTargets([...selectedTargets, t]);
                          else setSelectedTargets(selectedTargets.filter((x) => x !== t));
                        }}
                        className="rounded border-border text-indigo-600"
                      />
                      <span className="text-[11px] text-gray-200 font-mono">{t}</span>
                    </label>
                  ))}
                </div>
              </div>

              <div>
                <label className="text-muted-foreground">Generation Strategies</label>
                <div className="grid grid-cols-2 gap-2 mt-1">
                  {ALL_STRATEGIES.map((s) => (
                    <label key={s} className="flex items-center gap-2 p-2 rounded bg-muted/50 border border-border cursor-pointer">
                      <input
                        type="checkbox"
                        checked={selectedStrategies.includes(s)}
                        onChange={(e) => {
                          if (e.target.checked) setSelectedStrategies([...selectedStrategies, s]);
                          else setSelectedStrategies(selectedStrategies.filter((x) => x !== s));
                        }}
                        className="rounded border-border text-indigo-600"
                      />
                      <span className="text-[11px] text-gray-200">{s}</span>
                    </label>
                  ))}
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-muted-foreground">Max Cases per Target</label>
                  <input
                    type="number"
                    min={1}
                    max={20}
                    value={maxCases}
                    onChange={(e) => setMaxCases(parseInt(e.target.value) || 1)}
                    className="w-full bg-muted border border-border rounded px-3 py-1.5 mt-1 text-gray-200 font-mono"
                  />
                </div>
                <div>
                  <label className="text-muted-foreground">Deterministic Random Seed</label>
                  <input
                    type="number"
                    value={seed}
                    onChange={(e) => setSeed(parseInt(e.target.value) || 0)}
                    className="w-full bg-muted border border-border rounded px-3 py-1.5 mt-1 text-gray-200 font-mono"
                  />
                </div>
              </div>
            </div>

            <div className="flex items-center justify-end gap-2.5 pt-3 border-t border-border">
              <button
                onClick={() => setShowLauncher(false)}
                className="px-3.5 py-1.5 rounded bg-muted hover:bg-border text-gray-300 text-xs font-medium"
              >
                Cancel
              </button>
              <button
                onClick={handleLaunchCampaign}
                disabled={isLaunching || selectedTargets.length === 0}
                className="px-4 py-1.5 rounded bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold flex items-center gap-2"
              >
                {isLaunching ? <RotateCw className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5 fill-current" />}
                <span>{isLaunching ? 'Generating & Executing...' : 'Execute Campaign'}</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
