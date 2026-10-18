import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  CheckCircle2,
  XCircle,
  Play,
  RotateCw,
  Search,
  Clock,
  Sparkles,
  ChevronDown,
  ChevronRight,
  ShieldCheck,
  AlertTriangle,
} from 'lucide-react';
import { apiClient } from '../../api/client';
import type {
  AdversarialCategory,
  AdversarialTestCase,
  AdversarialRunSummary,
} from '../../types/hardening';

export const AdversarialHardeningWorkbench: React.FC = () => {
  const [cases, setCases] = useState<AdversarialTestCase[]>([]);
  const [runSummary, setRunSummary] = useState<AdversarialRunSummary | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [running, setRunning] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [expandedTestId, setExpandedTestId] = useState<string | null>(null);

  useEffect(() => {
    loadInitialData();
  }, []);

  const loadInitialData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [casesData, latestRun] = await Promise.all([
        apiClient.getHardeningCases(),
        apiClient.getLatestHardeningRun(),
      ]);
      setCases(casesData);
      setRunSummary(latestRun);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to load adversarial hardening data');
    } finally {
      setLoading(false);
    }
  };

  const handleRunSuite = async () => {
    setRunning(true);
    setError(null);
    try {
      const summary = await apiClient.runHardeningSuite();
      setRunSummary(summary);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Execution of hardening suite failed');
    } finally {
      setRunning(false);
    }
  };

  // Combine test case metadata with latest result
  const testItems = cases.map((c) => {
    const res = runSummary?.results.find((r) => r.test_id === c.test_id);
    return {
      case: c,
      result: res,
    };
  });

  const filteredItems = testItems.filter((item) => {
    const matchesCategory =
      selectedCategory === 'ALL' || item.case.category === selectedCategory;
    const matchesSearch =
      searchQuery === '' ||
      item.case.test_id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      item.case.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      item.case.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
      item.case.hand_verifiable_oracle.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesCategory && matchesSearch;
  });

  const categories: { key: string; label: string }[] = [
    { key: 'ALL', label: 'All Disciplines' },
    { key: 'ROUTING_FORWARDING', label: 'Routing & Forwarding' },
    { key: 'SECURITY_ISOLATION', label: 'Security & Isolation' },
    { key: 'CONFIG_CONSISTENCY', label: 'Config Consistency' },
    { key: 'PARSER_RESILIENCE', label: 'Parser Resilience' },
    { key: 'PREDICTIVE_INTEGRITY', label: 'Predictive Integrity' },
    { key: 'METAMORPHIC_INVARIANCE', label: 'Metamorphic Invariance' },
  ];

  const getCategoryColor = (cat: AdversarialCategory) => {
    switch (cat) {
      case 'ROUTING_FORWARDING':
        return 'bg-cyan-950/60 text-cyan-400 border-cyan-800/60';
      case 'SECURITY_ISOLATION':
        return 'bg-rose-950/60 text-rose-400 border-rose-800/60';
      case 'CONFIG_CONSISTENCY':
        return 'bg-purple-950/60 text-purple-400 border-purple-800/60';
      case 'PARSER_RESILIENCE':
        return 'bg-amber-950/60 text-amber-400 border-amber-800/60';
      case 'PREDICTIVE_INTEGRITY':
        return 'bg-blue-950/60 text-blue-400 border-blue-800/60';
      case 'METAMORPHIC_INVARIANCE':
        return 'bg-emerald-950/60 text-emerald-400 border-emerald-800/60';
      default:
        return 'bg-gray-800 text-gray-300 border-gray-700';
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-5 bg-gradient-to-r from-amber-950/40 via-gray-900 to-indigo-950/40 border border-amber-800/40 rounded-xl">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-6 h-6 text-amber-400" />
            <h2 className="text-lg font-bold text-white tracking-wide">
              Adversarial Verification & Hardening Suite
            </h2>
            <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-amber-500/20 text-amber-300 border border-amber-500/30">
              Ground Truth Verified
            </span>
          </div>
          <p className="text-xs text-gray-400 max-w-2xl leading-relaxed">
            Independent, hand-verifiable oracles covering longest-prefix match tie-breaking, interface down state enforcement, self-referencing next-hop loop prevention, strict evidence determinism (no false PASS), subnet ACL shadowing, C++ fragment reassembly resilience, and predictive split integrity.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={loadInitialData}
            disabled={loading || running}
            className="px-3 py-2 text-xs font-medium text-gray-300 bg-gray-800 hover:bg-gray-700 border border-gray-700 rounded-lg flex items-center gap-1.5 transition disabled:opacity-50"
          >
            <RotateCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <button
            onClick={handleRunSuite}
            disabled={running}
            className="px-4 py-2 text-xs font-semibold text-white bg-amber-600 hover:bg-amber-500 rounded-lg flex items-center gap-2 shadow-lg shadow-amber-950/50 transition disabled:opacity-50"
          >
            <Play className={`w-3.5 h-3.5 fill-current ${running ? 'animate-pulse' : ''}`} />
            {running ? 'Executing Suite...' : 'Run Hardening Suite'}
          </button>
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

      {/* Metric Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <div className="p-4 bg-gray-900/70 border border-gray-800 rounded-lg">
          <div className="text-[11px] font-medium text-gray-400 uppercase tracking-wider">Total Oracles</div>
          <div className="text-2xl font-bold font-mono text-white mt-1">{cases.length}</div>
          <div className="text-[10px] text-gray-400 mt-0.5">Hand-verifiable fixtures</div>
        </div>

        <div className="p-4 bg-gray-900/70 border border-gray-800 rounded-lg">
          <div className="text-[11px] font-medium text-gray-400 uppercase tracking-wider">Verified Passed</div>
          <div className="text-2xl font-bold font-mono text-emerald-400 mt-1">
            {runSummary ? runSummary.passed_cases : '—'}
          </div>
          <div className="text-[10px] text-emerald-400 mt-0.5">
            {runSummary ? `${Math.round((runSummary.passed_cases / (runSummary.total_cases || 1)) * 100)}% pass rate` : 'Awaiting run'}
          </div>
        </div>

        <div className="p-4 bg-gray-900/70 border border-gray-800 rounded-lg">
          <div className="text-[11px] font-medium text-gray-400 uppercase tracking-wider">Failed Defects</div>
          <div className={`text-2xl font-bold font-mono mt-1 ${runSummary && runSummary.failed_cases > 0 ? 'text-rose-400' : 'text-gray-400'}`}>
            {runSummary ? runSummary.failed_cases : '0'}
          </div>
          <div className="text-[10px] text-gray-400 mt-0.5">0 tolerated regressions</div>
        </div>

        <div className="p-4 bg-gray-900/70 border border-gray-800 rounded-lg">
          <div className="text-[11px] font-medium text-gray-400 uppercase tracking-wider">Suite Latency</div>
          <div className="text-2xl font-bold font-mono text-cyan-400 mt-1">
            {runSummary ? `${runSummary.duration_ms} ms` : '—'}
          </div>
          <div className="text-[10px] text-cyan-400 mt-0.5">End-to-end execution</div>
        </div>

        <div className="p-4 bg-gray-900/70 border border-gray-800 rounded-lg">
          <div className="text-[11px] font-medium text-gray-400 uppercase tracking-wider">Overall Integrity</div>
          <div className="mt-1">
            {runSummary?.all_passed ? (
              <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded text-xs font-bold bg-emerald-950 text-emerald-400 border border-emerald-800">
                <ShieldCheck className="w-3.5 h-3.5" /> VERIFIED
              </span>
            ) : runSummary ? (
              <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded text-xs font-bold bg-rose-950 text-rose-400 border border-rose-800">
                <AlertTriangle className="w-3.5 h-3.5" /> DEFECT DETECTED
              </span>
            ) : (
              <span className="text-xs text-gray-400">Not executed</span>
            )}
          </div>
          <div className="text-[10px] text-gray-400 mt-0.5">Immutability & Oracles</div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col md:flex-row items-center justify-between gap-3 bg-gray-900/60 p-3 rounded-lg border border-gray-800">
        <div className="flex flex-wrap items-center gap-1.5 w-full md:w-auto">
          {categories.map((cat) => (
            <button
              key={cat.key}
              onClick={() => setSelectedCategory(cat.key)}
              className={`px-3 py-1 text-xs rounded-md font-medium transition ${
                selectedCategory === cat.key
                  ? 'bg-amber-600 text-white'
                  : 'bg-gray-800/70 text-gray-400 hover:text-gray-200 hover:bg-gray-800'
              }`}
            >
              {cat.label}
            </button>
          ))}
        </div>

        <div className="relative w-full md:w-64">
          <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-gray-400" />
          <input
            type="text"
            placeholder="Search test oracles..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-gray-950 border border-gray-800 rounded-md pl-9 pr-3 py-1.5 text-xs text-gray-200 placeholder-gray-500 focus:outline-none focus:border-amber-500"
          />
        </div>
      </div>

      {/* Adversarial Test List */}
      <div className="space-y-3">
        {filteredItems.map(({ case: c, result: res }) => {
          const isExpanded = expandedTestId === c.test_id;
          const passed = res?.passed ?? false;

          return (
            <div
              key={c.test_id}
              className={`border rounded-lg bg-gray-900/50 transition ${
                res
                  ? passed
                    ? 'border-emerald-900/40 hover:border-emerald-700/60'
                    : 'border-rose-900/40 hover:border-rose-700/60'
                  : 'border-gray-800 hover:border-gray-700'
              }`}
            >
              <div
                onClick={() => setExpandedTestId(isExpanded ? null : c.test_id)}
                className="p-4 flex items-center justify-between cursor-pointer select-none"
              >
                <div className="flex items-center gap-3">
                  <button className="text-gray-400 hover:text-gray-200">
                    {isExpanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
                  </button>

                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs font-bold text-amber-400">{c.test_id}</span>
                      <span className="text-xs font-semibold text-white">{c.name}</span>
                      <span
                        className={`text-[10px] font-medium px-2 py-0.5 rounded border ${getCategoryColor(
                          c.category
                        )}`}
                      >
                        {c.category}
                      </span>
                    </div>
                    <div className="text-xs text-gray-400 line-clamp-1">{c.description}</div>
                  </div>
                </div>

                <div className="flex items-center gap-4">
                  {res ? (
                    <div className="flex items-center gap-2">
                      {passed ? (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-semibold bg-emerald-950/80 text-emerald-400 border border-emerald-800">
                          <CheckCircle2 className="w-3.5 h-3.5" /> PASS
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-semibold bg-rose-950/80 text-rose-400 border border-rose-800">
                          <XCircle className="w-3.5 h-3.5" /> FAIL
                        </span>
                      )}
                      <span className="font-mono text-xs text-gray-400">{res.execution_time_ms} ms</span>
                    </div>
                  ) : (
                    <span className="text-xs text-gray-500 italic">Not evaluated</span>
                  )}
                </div>
              </div>

              {/* Expanded Details Pane */}
              {isExpanded && (
                <div className="p-4 border-t border-gray-800 bg-gray-950/40 space-y-4 text-xs">
                  {/* Hand-verifiable Oracle */}
                  <div>
                    <div className="text-[11px] font-semibold text-amber-400 uppercase tracking-wider mb-1 flex items-center gap-1.5">
                      <Sparkles className="w-3.5 h-3.5" />
                      Hand-Verifiable Oracle & Mathematical Rationale
                    </div>
                    <div className="p-3 bg-amber-950/20 border border-amber-900/40 rounded-lg text-amber-200/90 leading-relaxed">
                      {c.hand_verifiable_oracle}
                    </div>
                  </div>

                  {/* Expected vs Actual Grid */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    <div className="p-3 bg-gray-900/70 border border-gray-800 rounded-lg space-y-1.5">
                      <div className="text-[11px] font-semibold text-gray-400 uppercase tracking-wider">
                        Expected Outcome
                      </div>
                      <div className="flex items-center justify-between text-xs font-mono">
                        <span className="text-gray-400">Status:</span>
                        <span className="text-emerald-400 font-bold">{c.expected_status}</span>
                      </div>
                      <div className="flex items-center justify-between text-xs font-mono">
                        <span className="text-gray-400">Reason Code:</span>
                        <span className="text-cyan-400">{c.expected_reason_code}</span>
                      </div>
                    </div>

                    <div className="p-3 bg-gray-900/70 border border-gray-800 rounded-lg space-y-1.5">
                      <div className="text-[11px] font-semibold text-gray-400 uppercase tracking-wider">
                        Engine Observation
                      </div>
                      <div className="flex items-center justify-between text-xs font-mono">
                        <span className="text-gray-400">Status:</span>
                        <span
                          className={`font-bold ${
                            res?.actual_status === c.expected_status ? 'text-emerald-400' : 'text-rose-400'
                          }`}
                        >
                          {res?.actual_status ?? '—'}
                        </span>
                      </div>
                      <div className="flex items-center justify-between text-xs font-mono">
                        <span className="text-gray-400">Reason Code:</span>
                        <span
                          className={`${
                            res?.actual_reason_code === c.expected_reason_code ? 'text-cyan-400' : 'text-amber-400'
                          }`}
                        >
                          {res?.actual_reason_code ?? '—'}
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Result Details / Diagnostic Evidence */}
                  {res?.details && (
                    <div>
                      <div className="text-[11px] font-semibold text-gray-400 uppercase tracking-wider mb-1">
                        Diagnostic Evidence & Trace
                      </div>
                      <div className="p-3 bg-gray-900 border border-gray-800 rounded-lg font-mono text-[11px] text-gray-300 break-all leading-normal">
                        {res.details}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}

        {filteredItems.length === 0 && (
          <div className="text-center py-12 text-gray-500 text-xs">
            No adversarial test cases match the active filter or query.
          </div>
        )}
      </div>

      {/* Footer Audit Information */}
      <div className="p-4 bg-gray-900/40 border border-gray-800 rounded-lg text-xs text-gray-400 flex flex-col md:flex-row items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <Clock className="w-3.5 h-3.5 text-gray-500" />
          <span>
            Latest Audit Run: {runSummary?.run_id ?? 'None'} at{' '}
            {runSummary?.timestamp ? new Date(runSummary.timestamp).toLocaleString() : 'N/A'}
          </span>
        </div>
        <div className="text-gray-400">
          Persistent Storage: <code className="text-amber-400 font-mono">data/hardening/latest_adversarial_run.json</code>
        </div>
      </div>
    </div>
  );
};
