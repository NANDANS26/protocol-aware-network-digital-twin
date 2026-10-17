import React, { useState } from 'react';
import { apiClient } from '../api/client';
import type { AnalysisJob, FlowSummary } from '../types/analysis';
import type { NetworkEvent } from '@contracts/network_event';

export const ObservatoryView: React.FC = () => {
  const [currentJob, setCurrentJob] = useState<AnalysisJob | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'flows' | 'events'>('flows');
  const [selectedFlow, setSelectedFlow] = useState<FlowSummary | null>(null);
  const [events, setEvents] = useState<NetworkEvent[]>([]);
  const [loadingEvents, setLoadingEvents] = useState<boolean>(false);
  const [protocolFilter, setProtocolFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');

  const handleFileUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    setLoading(true);
    setError(null);
    setSelectedFlow(null);

    try {
      const resp = await apiClient.uploadCapture(file);
      const job = await apiClient.getJob(resp.job_id);
      setCurrentJob(job);
      if (activeTab === 'events') {
        loadEvents(resp.job_id);
      }
    } catch (err: any) {
      setError(err.message || 'Failed to analyze uploaded capture file.');
    } finally {
      setLoading(false);
    }
  };

  const handleRunDemo = async (format: 'pcap' | 'pcapng') => {
    setLoading(true);
    setError(null);
    setSelectedFlow(null);

    try {
      const resp = await apiClient.runDemoAnalysis(format);
      const job = await apiClient.getJob(resp.job_id);
      setCurrentJob(job);
      if (activeTab === 'events') {
        loadEvents(resp.job_id);
      }
    } catch (err: any) {
      setError(err.message || `Failed to run demo on ${format}.`);
    } finally {
      setLoading(false);
    }
  };

  const loadEvents = async (jobId: string) => {
    setLoadingEvents(true);
    try {
      const resp = await apiClient.getJobEvents(jobId, 0, 100);
      setEvents(resp.events);
    } catch (err: any) {
      console.error('Failed to load events', err);
    } finally {
      setLoadingEvents(false);
    }
  };

  const handleTabSwitch = (tab: 'flows' | 'events') => {
    setActiveTab(tab);
    if (tab === 'events' && currentJob && events.length === 0) {
      loadEvents(currentJob.job_id);
    }
  };

  const summary = currentJob?.summary;

  const filteredFlows = (summary?.flows || []).filter((f) => {
    if (protocolFilter !== 'ALL' && f.ip_proto.toUpperCase() !== protocolFilter) {
      return false;
    }
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchIp = f.src_ip.includes(q) || f.dst_ip.includes(q);
      const matchApp = f.app_protocol.toLowerCase().includes(q);
      const matchInfo = f.info.toLowerCase().includes(q);
      const matchId = f.flow_id.toLowerCase().includes(q);
      return matchIp || matchApp || matchInfo || matchId;
    }
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Top Banner / Ingestion Control */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-6 shadow-sm">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-emerald-950 text-emerald-400 border border-emerald-800">
                Phase 01 Operational
              </span>
              <span className="text-xs text-slate-400 font-mono">C++20 Ingestion Engine</span>
            </div>
            <h1 className="text-xl font-bold text-slate-100 mt-1">Network Observatory</h1>
            <p className="text-sm text-slate-400 mt-0.5">
              High-throughput offline capture ingestion, zero-copy protocol decoding, and stateful flow reconstruction.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <label className="cursor-pointer inline-flex items-center px-4 py-2 border border-blue-600 rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none transition-colors">
              <span>{loading ? 'Processing...' : 'Upload PCAP / PCAPNG'}</span>
              <input
                type="file"
                accept=".pcap,.pcapng,.cap"
                className="hidden"
                disabled={loading}
                onChange={handleFileUpload}
              />
            </label>

            <button
              onClick={() => handleRunDemo('pcap')}
              disabled={loading}
              className="px-3 py-2 border border-slate-700 rounded-md text-sm font-medium text-slate-200 bg-slate-800 hover:bg-slate-700 transition-colors disabled:opacity-50"
            >
              Load Sample PCAP
            </button>

            <button
              onClick={() => handleRunDemo('pcapng')}
              disabled={loading}
              className="px-3 py-2 border border-slate-700 rounded-md text-sm font-medium text-slate-200 bg-slate-800 hover:bg-slate-700 transition-colors disabled:opacity-50"
            >
              Load Sample PCAPNG
            </button>
          </div>
        </div>

        {error && (
          <div className="mt-4 p-3 bg-red-950/50 border border-red-800/80 rounded-md text-sm text-red-300">
            {error}
          </div>
        )}
      </div>

      {/* Metrics Dashboard */}
      {summary ? (
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4">
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
            <div className="text-xs text-slate-400">Total Packets</div>
            <div className="text-2xl font-bold text-slate-100 mt-1">{summary.total_packets.toLocaleString()}</div>
            <div className="text-xs text-slate-500 mt-1">{summary.total_bytes.toLocaleString()} bytes</div>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
            <div className="text-xs text-slate-400">Total Flows</div>
            <div className="text-2xl font-bold text-slate-100 mt-1">{summary.total_flows.toLocaleString()}</div>
            <div className="text-xs text-emerald-400 mt-1">Bidirectional 5-tuple</div>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
            <div className="text-xs text-slate-400">Engine Speed</div>
            <div className="text-2xl font-bold text-slate-100 mt-1">
              {summary.packets_per_sec.toLocaleString(undefined, { maximumFractionDigits: 0 })}
            </div>
            <div className="text-xs text-slate-500 mt-1">packets / sec</div>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
            <div className="text-xs text-slate-400">Throughput</div>
            <div className="text-2xl font-bold text-slate-100 mt-1">
              {summary.throughput_mbps.toFixed(2)}
            </div>
            <div className="text-xs text-slate-500 mt-1">Mbps ({summary.duration_ms.toFixed(2)} ms)</div>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
            <div className="text-xs text-slate-400">App Transactions</div>
            <div className="text-2xl font-bold text-slate-100 mt-1">
              {summary.http_requests + summary.dns_queries + summary.tls_handshakes}
            </div>
            <div className="text-xs text-slate-500 mt-1">
              {summary.dns_queries} DNS | {summary.http_requests} HTTP | {summary.tls_handshakes} TLS
            </div>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
            <div className="text-xs text-slate-400">Parser Integrity</div>
            <div className="text-2xl font-bold text-emerald-400 mt-1">
              {summary.parser_status_counts['ok'] || 0}
            </div>
            <div className="text-xs text-slate-500 mt-1">
              {(summary.parser_status_counts['malformed'] || 0) + (summary.parser_status_counts['checksum_error'] || 0)} errors
            </div>
          </div>
        </div>
      ) : (
        <div className="bg-slate-900/60 border border-dashed border-slate-800 rounded-lg p-12 text-center">
          <p className="text-slate-400 text-sm">
            No capture loaded yet. Upload a PCAP/PCAPNG file or click one of the sample buttons above to run the real C++ analysis pipeline.
          </p>
        </div>
      )}

      {/* Protocol & TCP State Breakdown */}
      {summary && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
            <h3 className="text-sm font-semibold text-slate-200 mb-3">Protocol Distribution</h3>
            <div className="flex flex-wrap gap-2">
              {Object.entries(summary.protocol_counts).map(([proto, cnt]) => (
                <div
                  key={proto}
                  className="px-3 py-1.5 bg-slate-800/80 border border-slate-700/60 rounded text-xs flex items-center gap-2"
                >
                  <span className="font-semibold text-slate-300">{proto}</span>
                  <span className="font-mono text-emerald-400">{cnt}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
            <h3 className="text-sm font-semibold text-slate-200 mb-3">TCP Connection States</h3>
            <div className="flex flex-wrap gap-2">
              {Object.entries(summary.tcp_state_counts).length > 0 ? (
                Object.entries(summary.tcp_state_counts).map(([st, cnt]) => (
                  <div
                    key={st}
                    className="px-3 py-1.5 bg-slate-800/80 border border-slate-700/60 rounded text-xs flex items-center gap-2"
                  >
                    <span className="font-semibold text-slate-300">{st}</span>
                    <span className="font-mono text-cyan-400">{cnt}</span>
                  </div>
                ))
              ) : (
                <span className="text-xs text-slate-500">No TCP flows present in this capture</span>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Main View Area: Flows vs Events Tab */}
      {summary && (
        <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden shadow-sm">
          <div className="border-b border-slate-800 px-6 py-3 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="flex items-center space-x-2">
              <button
                onClick={() => handleTabSwitch('flows')}
                className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
                  activeTab === 'flows'
                    ? 'bg-blue-600/20 text-blue-400 border border-blue-500/30'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Reconstructed Flows ({summary.flows.length})
              </button>
              <button
                onClick={() => handleTabSwitch('events')}
                className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
                  activeTab === 'events'
                    ? 'bg-blue-600/20 text-blue-400 border border-blue-500/30'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Canonical Event Stream ({summary.total_packets})
              </button>
            </div>

            {activeTab === 'flows' && (
              <div className="flex items-center gap-3">
                <select
                  value={protocolFilter}
                  onChange={(e) => setProtocolFilter(e.target.value)}
                  className="bg-slate-800 border border-slate-700 text-slate-200 text-xs rounded px-2.5 py-1 focus:outline-none"
                >
                  <option value="ALL">All Protocols</option>
                  <option value="TCP">TCP Only</option>
                  <option value="UDP">UDP Only</option>
                  <option value="ICMP">ICMP Only</option>
                </select>

                <input
                  type="text"
                  placeholder="Filter by IP, Host, or Flow ID..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="bg-slate-800 border border-slate-700 text-slate-200 text-xs rounded px-2.5 py-1 focus:outline-none w-48 sm:w-64"
                />
              </div>
            )}
          </div>

          {activeTab === 'flows' ? (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs text-slate-300">
                <thead className="bg-slate-950/60 text-slate-400 border-b border-slate-800 font-mono">
                  <tr>
                    <th className="px-4 py-2.5">Flow ID</th>
                    <th className="px-4 py-2.5">Proto</th>
                    <th className="px-4 py-2.5">Endpoint A</th>
                    <th className="px-4 py-2.5">Endpoint B</th>
                    <th className="px-4 py-2.5">State</th>
                    <th className="px-4 py-2.5">Packets (Fwd/Rev)</th>
                    <th className="px-4 py-2.5">Bytes (Fwd/Rev)</th>
                    <th className="px-4 py-2.5">App Proto</th>
                    <th className="px-4 py-2.5">Info / Transaction</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono">
                  {filteredFlows.length > 0 ? (
                    filteredFlows.map((flow) => (
                      <tr
                        key={flow.flow_id}
                        onClick={() => setSelectedFlow(flow)}
                        className={`hover:bg-slate-800/40 cursor-pointer transition-colors ${
                          selectedFlow?.flow_id === flow.flow_id ? 'bg-blue-950/40 border-l-2 border-blue-500' : ''
                        }`}
                      >
                        <td className="px-4 py-2 text-slate-400 truncate max-w-[120px]">{flow.flow_id}</td>
                        <td className="px-4 py-2">
                          <span
                            className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${
                              flow.ip_proto === 'TCP'
                                ? 'bg-cyan-950 text-cyan-400 border border-cyan-800'
                                : flow.ip_proto === 'UDP'
                                ? 'bg-amber-950 text-amber-400 border border-amber-800'
                                : 'bg-purple-950 text-purple-400 border border-purple-800'
                            }`}
                          >
                            {flow.ip_proto}
                          </span>
                        </td>
                        <td className="px-4 py-2">
                          {flow.src_ip}
                          {flow.src_port > 0 ? `:${flow.src_port}` : ''}
                        </td>
                        <td className="px-4 py-2">
                          {flow.dst_ip}
                          {flow.dst_port > 0 ? `:${flow.dst_port}` : ''}
                        </td>
                        <td className="px-4 py-2">
                          <span className="text-slate-300 font-medium">{flow.state}</span>
                        </td>
                        <td className="px-4 py-2">
                          {flow.packets_forward} / {flow.packets_reverse}
                        </td>
                        <td className="px-4 py-2">
                          {flow.bytes_forward} / {flow.bytes_reverse}
                        </td>
                        <td className="px-4 py-2">
                          {flow.app_protocol !== 'UNKNOWN' ? (
                            <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-emerald-950 text-emerald-400 border border-emerald-800">
                              {flow.app_protocol}
                            </span>
                          ) : (
                            <span className="text-slate-500">—</span>
                          )}
                        </td>
                        <td className="px-4 py-2 text-slate-400 truncate max-w-[200px]">{flow.info || '—'}</td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan={9} className="px-4 py-8 text-center text-slate-500 font-sans">
                        No flows match the current filters.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="p-4">
              {loadingEvents ? (
                <div className="py-8 text-center text-slate-400">Loading canonical events...</div>
              ) : (
                <div className="space-y-2 max-h-[500px] overflow-y-auto font-mono text-xs">
                  {events.map((ev) => (
                    <div
                      key={ev.event_id}
                      className="p-2.5 bg-slate-950 border border-slate-800 rounded hover:border-slate-700 transition-colors"
                    >
                      <div className="flex items-center justify-between text-slate-400 mb-1">
                        <span className="text-emerald-400">{ev.event_id}</span>
                        <span>{ev.timestamp_iso}</span>
                      </div>
                      <div className="text-slate-300">
                        {ev.link_layer?.source_mac} → {ev.link_layer?.destination_mac} |{' '}
                        {ev.network_layer ? `${ev.network_layer.source_ip} → ${ev.network_layer.destination_ip}` : 'Non-IP'}{' '}
                        {ev.transport_layer ? `| ${ev.transport_layer.protocol} (${ev.transport_layer.source_port} → ${ev.transport_layer.destination_port})` : ''}
                        {ev.application_layer ? ` | App: ${ev.application_layer.protocol}` : ''}
                      </div>
                      {ev.application_layer?.sanitized_preview && (
                        <div className="mt-1 text-[11px] text-slate-500 truncate">
                          Preview: {ev.application_layer.sanitized_preview}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Selected Flow Detail Drawer */}
      {selectedFlow && (
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-6 shadow-sm">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
            <div>
              <h3 className="text-sm font-bold text-slate-200">Flow Inspection Detail</h3>
              <p className="text-xs font-mono text-slate-400">{selectedFlow.flow_id}</p>
            </div>
            <button
              onClick={() => setSelectedFlow(null)}
              className="text-xs text-slate-400 hover:text-slate-200"
            >
              Close
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs font-mono">
            <div className="bg-slate-950 p-3 rounded border border-slate-800 space-y-1">
              <div className="text-slate-500 uppercase text-[10px]">Endpoint Configuration</div>
              <div>Protocol: <span className="text-slate-200">{selectedFlow.ip_proto}</span></div>
              <div>Source: <span className="text-slate-200">{selectedFlow.src_ip}:{selectedFlow.src_port}</span></div>
              <div>Destination: <span className="text-slate-200">{selectedFlow.dst_ip}:{selectedFlow.dst_port}</span></div>
              <div>VLAN: <span className="text-slate-200">{selectedFlow.vlan_id ?? 'None'}</span></div>
            </div>

            <div className="bg-slate-950 p-3 rounded border border-slate-800 space-y-1">
              <div className="text-slate-500 uppercase text-[10px]">State & Telemetry</div>
              <div>TCP State: <span className="text-cyan-400 font-bold">{selectedFlow.state}</span></div>
              <div>Duration: <span className="text-slate-200">{selectedFlow.duration_ms.toFixed(2)} ms</span></div>
              <div>Retransmissions: <span className="text-slate-200">{selectedFlow.retransmissions}</span></div>
              <div>Out of Order: <span className="text-slate-200">{selectedFlow.out_of_order}</span></div>
            </div>

            <div className="bg-slate-950 p-3 rounded border border-slate-800 space-y-1">
              <div className="text-slate-500 uppercase text-[10px]">Application Layer Metadata</div>
              <div>Application: <span className="text-emerald-400 font-bold">{selectedFlow.app_protocol}</span></div>
              <div>Information: <span className="text-slate-200">{selectedFlow.info || 'None'}</span></div>
              <div>Total Packets: <span className="text-slate-200">{selectedFlow.packets_forward + selectedFlow.packets_reverse}</span></div>
              <div>Total Bytes: <span className="text-slate-200">{(selectedFlow.bytes_forward + selectedFlow.bytes_reverse).toLocaleString()} bytes</span></div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
