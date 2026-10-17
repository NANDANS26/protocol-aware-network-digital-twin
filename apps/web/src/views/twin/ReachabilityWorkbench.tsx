import React, { useState } from 'react';
import type {
  NetworkModel,
  ReachabilityQuery,
  ReachabilityResult,
  TransportProtocolConstraint,
} from '../../types/simulation';
import {
  Compass,
  CheckCircle,
  XCircle,
  AlertTriangle,
  ArrowRight,
  ShieldAlert,
  Route,
  Activity,
  Layers,
} from 'lucide-react';

interface Props {
  models: NetworkModel[];
  selectedModelId: string;
  onSelectModel: (modelId: string) => void;
  onEvaluate: (query: ReachabilityQuery) => Promise<ReachabilityResult | null>;
  loading: boolean;
}

export const ReachabilityWorkbench: React.FC<Props> = ({
  models,
  selectedModelId,
  onSelectModel,
  onEvaluate,
  loading,
}) => {
  const currentModel = models.find((m) => m.model_id === selectedModelId);

  // Form states
  const [sourceIp, setSourceIp] = useState<string>('10.0.1.100');
  const [destinationIp, setDestinationIp] = useState<string>('10.0.2.200');
  const [protocol, setProtocol] = useState<TransportProtocolConstraint>('TCP');
  const [destinationPort, setDestinationPort] = useState<number>(443);
  const sourcePort = 49152;

  // Result state
  const [result, setResult] = useState<ReachabilityResult | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedModelId) return;

    const query: ReachabilityQuery = {
      model_id: selectedModelId,
      source_ip: sourceIp.trim(),
      destination_ip: destinationIp.trim(),
      protocol,
      destination_port: protocol === 'ICMP' ? undefined : destinationPort,
      source_port: protocol === 'ICMP' ? undefined : sourcePort,
    };

    const res = await onEvaluate(query);
    if (res) {
      setResult(res);
    }
  };

  const setPreset = (src: string, dst: string, proto: TransportProtocolConstraint, port: number) => {
    setSourceIp(src);
    setDestinationIp(dst);
    setProtocol(proto);
    setDestinationPort(port);
  };

  return (
    <div className="space-y-6">
      {/* Configuration Header & Preset Selector */}
      <div className="bg-surface/60 border border-gray-800 rounded-lg p-5">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-gray-800/80 pb-4 mb-4">
          <div>
            <h2 className="text-sm font-bold text-white flex items-center gap-2">
              <Compass className="w-4 h-4 text-indigo-400" />
              Deterministic Reachability & Packet Forwarding Workbench
            </h2>
            <p className="text-xs text-gray-400 mt-0.5">
              Simulate packet traversal using formal Longest-Prefix-Match, route-metric tie breaking, and directional firewall ACLs.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <label className="text-xs font-medium text-gray-300">Active Model:</label>
            <select
              value={selectedModelId}
              onChange={(e) => onSelectModel(e.target.value)}
              className="bg-slate-950 border border-gray-700 rounded px-2.5 py-1 text-xs text-gray-200 focus:outline-none focus:border-indigo-500 font-mono"
            >
              {models.length === 0 ? (
                <option value="">No models built</option>
              ) : (
                models.map((m) => (
                  <option key={m.model_id} value={m.model_id}>
                    {m.name} ({m.model_id.slice(0, 10)})
                  </option>
                ))
              )}
            </select>
          </div>
        </div>

        {/* Quick presets */}
        {currentModel && (
          <div className="flex items-center gap-2 mb-4 text-xs">
            <span className="text-gray-400 font-medium">Quick Probes:</span>
            <button
              type="button"
              onClick={() => setPreset('10.0.1.100', '10.0.2.200', 'TCP', 443)}
              className="px-2 py-0.5 rounded bg-gray-800 hover:bg-gray-700 text-gray-300 font-mono text-[11px] transition"
            >
              Web HTTPS (443)
            </button>
            <button
              type="button"
              onClick={() => setPreset('10.0.1.100', '10.0.2.200', 'TCP', 5432)}
              className="px-2 py-0.5 rounded bg-gray-800 hover:bg-gray-700 text-gray-300 font-mono text-[11px] transition"
            >
              PostgreSQL (5432)
            </button>
            <button
              type="button"
              onClick={() => setPreset('198.51.100.50', '10.0.1.50', 'TCP', 22)}
              className="px-2 py-0.5 rounded bg-gray-800 hover:bg-gray-700 text-gray-300 font-mono text-[11px] transition"
            >
              External SSH (22)
            </button>
          </div>
        )}

        {/* Query Input Form */}
        <form onSubmit={handleSubmit} className="grid grid-cols-1 md:grid-cols-6 gap-3">
          <div className="md:col-span-2">
            <label className="block text-[11px] font-medium text-gray-300 mb-1">Source IP Address</label>
            <input
              type="text"
              value={sourceIp}
              onChange={(e) => setSourceIp(e.target.value)}
              placeholder="e.g. 10.0.1.100"
              className="w-full bg-slate-950 border border-gray-700 rounded px-2.5 py-1.5 text-xs text-gray-200 font-mono focus:outline-none focus:border-indigo-500"
              required
            />
          </div>

          <div className="md:col-span-2">
            <label className="block text-[11px] font-medium text-gray-300 mb-1">Destination IP Address</label>
            <input
              type="text"
              value={destinationIp}
              onChange={(e) => setDestinationIp(e.target.value)}
              placeholder="e.g. 10.0.2.200"
              className="w-full bg-slate-950 border border-gray-700 rounded px-2.5 py-1.5 text-xs text-gray-200 font-mono focus:outline-none focus:border-indigo-500"
              required
            />
          </div>

          <div>
            <label className="block text-[11px] font-medium text-gray-300 mb-1">Protocol</label>
            <select
              value={protocol}
              onChange={(e) => setProtocol(e.target.value as TransportProtocolConstraint)}
              className="w-full bg-slate-950 border border-gray-700 rounded px-2.5 py-1.5 text-xs text-gray-200 font-mono focus:outline-none focus:border-indigo-500"
            >
              <option value="TCP">TCP</option>
              <option value="UDP">UDP</option>
              <option value="ICMP">ICMP</option>
              <option value="ANY">ANY</option>
            </select>
          </div>

          <div>
            <label className="block text-[11px] font-medium text-gray-300 mb-1">Dst Port</label>
            <input
              type="number"
              value={destinationPort}
              onChange={(e) => setDestinationPort(parseInt(e.target.value) || 0)}
              disabled={protocol === 'ICMP'}
              min={1}
              max={65535}
              className="w-full bg-slate-950 border border-gray-700 rounded px-2.5 py-1.5 text-xs text-gray-200 font-mono focus:outline-none focus:border-indigo-500 disabled:opacity-40"
            />
          </div>

          <div className="md:col-span-6 flex justify-end gap-2 pt-2">
            <button
              type="submit"
              disabled={loading || !selectedModelId}
              className="px-4 py-1.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded text-xs font-semibold flex items-center gap-1.5 shadow-sm transition disabled:opacity-50"
            >
              <Activity className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
              <span>Evaluate Forwarding Path</span>
            </button>
          </div>
        </form>
      </div>

      {/* Results Display */}
      {result && (
        <div className="space-y-4">
          {/* Status Banner */}
          <div
            className={`p-4 rounded-lg border flex flex-col sm:flex-row sm:items-center justify-between gap-3 ${
              result.status === 'REACHABLE'
                ? 'bg-emerald-950/40 border-emerald-800/80 text-emerald-200'
                : result.status === 'BLOCKED'
                ? 'bg-rose-950/40 border-rose-800/80 text-rose-200'
                : 'bg-amber-950/40 border-amber-800/80 text-amber-200'
            }`}
          >
            <div className="flex items-center gap-3">
              {result.status === 'REACHABLE' ? (
                <CheckCircle className="w-6 h-6 text-emerald-400 shrink-0" />
              ) : result.status === 'BLOCKED' ? (
                <XCircle className="w-6 h-6 text-rose-400 shrink-0" />
              ) : (
                <AlertTriangle className="w-6 h-6 text-amber-400 shrink-0" />
              )}
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-bold text-sm tracking-wide">{result.status}</span>
                  <span className="font-mono text-xs px-2 py-0.5 rounded bg-black/40 border border-current font-semibold">
                    {result.reason_code}
                  </span>
                </div>
                <p className="text-xs opacity-90 mt-0.5">{result.explanation}</p>
              </div>
            </div>

            <div className="flex items-center gap-4 text-xs font-mono shrink-0">
              <div>
                <span className="text-gray-400 block text-[10px] uppercase">Policies Evaluated</span>
                <span className="font-bold text-white">{result.evaluated_policy_count}</span>
              </div>
              <div>
                <span className="text-gray-400 block text-[10px] uppercase">Route Matches</span>
                <span className="font-bold text-white">{result.route_decisions_count}</span>
              </div>
              <div>
                <span className="text-gray-400 block text-[10px] uppercase">Hops</span>
                <span className="font-bold text-white">{result.path.length}</span>
              </div>
            </div>
          </div>

          {/* Blocking Rule Alert */}
          {result.blocking_rule && (
            <div className="bg-rose-950/30 border border-rose-800 rounded-lg p-4">
              <h3 className="text-xs font-bold text-rose-300 uppercase tracking-wider flex items-center gap-1.5 mb-2">
                <ShieldAlert className="w-4 h-4 text-rose-400" />
                Firewall Drop Enforcement
              </h3>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
                <div>
                  <span className="text-gray-400 block text-[10px]">Blocking Node</span>
                  <span className="text-white font-semibold">{result.blocking_rule.node_label}</span>
                </div>
                <div>
                  <span className="text-gray-400 block text-[10px]">Rule Action & Direction</span>
                  <span className="text-rose-400 font-semibold">
                    {result.blocking_rule.rule_action} ({result.blocking_rule.direction})
                  </span>
                </div>
                <div>
                  <span className="text-gray-400 block text-[10px]">Rule ID / Number</span>
                  <span className="text-gray-200">
                    {result.blocking_rule.rule_id || `Rule #${result.blocking_rule.rule_number || 'Default'}`}
                  </span>
                </div>
                <div>
                  <span className="text-gray-400 block text-[10px]">Reason</span>
                  <span className="text-rose-300">{result.blocking_rule.reason_code}</span>
                </div>
              </div>
            </div>
          )}

          {/* Hop-by-Hop Visual Trace */}
          <div className="bg-surface/50 border border-gray-800 rounded-lg p-4">
            <h3 className="text-xs font-bold text-gray-300 uppercase tracking-wider flex items-center gap-1.5 mb-4">
              <Route className="w-4 h-4 text-cyan-400" />
              Forwarding Path Hop Sequence
            </h3>

            {result.path.length === 0 ? (
              <div className="text-gray-500 text-xs italic">No hops traversed before termination.</div>
            ) : (
              <div className="space-y-3">
                {result.path.map((hop, index) => (
                  <div key={hop.hop_index} className="flex items-start gap-3">
                    {/* Index bubble */}
                    <div className="w-6 h-6 rounded-full bg-indigo-950 border border-indigo-700/60 flex items-center justify-center text-[11px] font-bold text-indigo-300 shrink-0 mt-0.5">
                      {hop.hop_index}
                    </div>

                    {/* Hop card */}
                    <div className="flex-1 bg-slate-950 border border-gray-800 rounded p-3 text-xs font-mono">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <span className="font-bold text-white text-sm flex items-center gap-1.5">
                          <Layers className="w-3.5 h-3.5 text-indigo-400" />
                          {hop.node_label}
                        </span>
                        {hop.routed_destination_prefix && (
                          <span className="px-2 py-0.5 rounded bg-cyan-950/60 text-cyan-300 border border-cyan-800/40 text-[11px]">
                            LPM: {hop.routed_destination_prefix}
                          </span>
                        )}
                        {hop.next_hop_ip && (
                          <span className="text-gray-400 text-[11px]">
                            Next Hop: <span className="text-gray-200">{hop.next_hop_ip}</span>
                          </span>
                        )}
                      </div>

                      {hop.notes && <p className="text-gray-400 text-xs mt-1.5">{hop.notes}</p>}
                    </div>

                    {index < result.path.length - 1 && (
                      <div className="self-center hidden sm:block text-gray-600">
                        <ArrowRight className="w-4 h-4" />
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Model Limitations or Evidence */}
          {result.evidence_ids && result.evidence_ids.length > 0 && (
            <div className="bg-surface/30 border border-gray-800/80 rounded-lg p-3 text-xs font-mono">
              <span className="text-gray-400 block text-[10px] uppercase font-bold mb-1">Backing Evidence Records</span>
              <div className="flex flex-wrap gap-1.5">
                {result.evidence_ids.map((ev) => (
                  <span key={ev} className="px-2 py-0.5 rounded bg-gray-800/80 text-gray-300 text-[11px]">
                    {ev}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
