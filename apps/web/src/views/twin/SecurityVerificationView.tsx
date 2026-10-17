import React, { useState } from 'react';
import type {
  NetworkModel,
  SecurityInvariant,
  VerificationResult,
  InvariantSeverity,
  InvariantType,
} from '../../types/simulation';
import {
  ShieldCheck,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Activity,
  Plus,
  ChevronDown,
  ChevronUp,
  FileCode,
} from 'lucide-react';

interface Props {
  models: NetworkModel[];
  selectedModelId: string;
  onSelectModel: (modelId: string) => void;
  invariants: SecurityInvariant[];
  verificationResults: VerificationResult[];
  onRunVerification: (modelId: string) => Promise<VerificationResult[]>;
  onCreateInvariant: (inv: SecurityInvariant) => Promise<void>;
  loading: boolean;
}

export const SecurityVerificationView: React.FC<Props> = ({
  models,
  selectedModelId,
  onSelectModel,
  invariants,
  verificationResults,
  onRunVerification,
  onCreateInvariant,
  loading,
}) => {
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [expandedWitnessId, setExpandedWitnessId] = useState<string | null>(null);
  const [showAddModal, setShowAddModal] = useState<boolean>(false);

  // New invariant form state
  const [newName, setNewName] = useState<string>('');
  const [newDescription, setNewDescription] = useState<string>('');
  const [newType, setNewType] = useState<InvariantType>('ISOLATION');
  const [newSeverity, setNewSeverity] = useState<InvariantSeverity>('HIGH');
  const [newSrc, setNewSrc] = useState<string>('zone-untrusted');
  const [newDst, setNewDst] = useState<string>('10.0.1.50/32');
  const [newPort, setNewPort] = useState<number>(443);

  const filteredInvariants = invariants.filter((inv) => {
    if (severityFilter === 'ALL') return true;
    return inv.severity === severityFilter;
  });

  const getResultForInvariant = (invId: string): VerificationResult | undefined => {
    return verificationResults.find((r) => r.invariant_id === invId);
  };

  const handleAddInvariant = async (e: React.FormEvent) => {
    e.preventDefault();
    const inv: SecurityInvariant = {
      invariant_id: `inv-${Date.now()}`,
      name: newName.trim(),
      description: newDescription.trim(),
      invariant_type: newType,
      severity: newSeverity,
      definition: {
        source_zone_or_cidr: newSrc.trim() || undefined,
        destination_zone_or_cidr: newDst.trim() || undefined,
        service_ip: newDst.trim() || undefined,
        service_port: newPort || undefined,
        allowed_ports: newType === 'PORT_RESTRICTION' ? [newPort] : undefined,
      },
    };

    await onCreateInvariant(inv);
    setShowAddModal(false);
    setNewName('');
    setNewDescription('');
  };

  return (
    <div className="space-y-6">
      {/* Control Bar */}
      <div className="bg-surface/60 border border-gray-800 rounded-lg p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-sm font-bold text-white flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            Security Invariant Verification Engine
          </h2>
          <p className="text-xs text-gray-400 mt-0.5">
            Formal mathematical assertions over reachability, zone isolation, and port exposure with counterexample witness generation.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-2">
            <label className="text-xs font-medium text-gray-300">Target Model:</label>
            <select
              value={selectedModelId}
              onChange={(e) => onSelectModel(e.target.value)}
              className="bg-slate-950 border border-gray-700 rounded px-2.5 py-1 text-xs text-gray-200 focus:outline-none focus:border-indigo-500 font-mono"
            >
              {models.map((m) => (
                <option key={m.model_id} value={m.model_id}>
                  {m.name} ({m.model_id.slice(0, 10)})
                </option>
              ))}
            </select>
          </div>

          <div className="flex items-center gap-2">
            <label className="text-xs font-medium text-gray-300">Severity:</label>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="bg-slate-950 border border-gray-700 rounded px-2.5 py-1 text-xs text-gray-200 focus:outline-none focus:border-indigo-500"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>
          </div>

          <button
            onClick={() => setShowAddModal(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-gray-800 hover:bg-gray-700 text-gray-200 text-xs font-medium border border-gray-700 transition"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Add Invariant</span>
          </button>

          <button
            onClick={() => onRunVerification(selectedModelId)}
            disabled={loading || !selectedModelId}
            className="flex items-center gap-1.5 px-4 py-1.5 rounded bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold shadow-sm transition disabled:opacity-50"
          >
            <Activity className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Run Verification</span>
          </button>
        </div>
      </div>

      {/* Invariant Ledger Table */}
      <div className="bg-surface/50 border border-gray-800 rounded-lg overflow-hidden">
        <div className="p-4 border-b border-gray-800 flex items-center justify-between">
          <h3 className="text-xs font-bold text-gray-300 uppercase tracking-wider flex items-center gap-2">
            <FileCode className="w-4 h-4 text-indigo-400" />
            Security Invariant Ledger ({filteredInvariants.length})
          </h3>
          {verificationResults.length > 0 && (
            <div className="flex items-center gap-3 text-xs font-mono">
              <span className="text-emerald-400 flex items-center gap-1">
                <CheckCircle className="w-3.5 h-3.5" />
                {verificationResults.filter((r) => r.status === 'PASS').length} Pass
              </span>
              <span className="text-rose-400 flex items-center gap-1">
                <XCircle className="w-3.5 h-3.5" />
                {verificationResults.filter((r) => r.status === 'FAIL').length} Fail
              </span>
              <span className="text-amber-400 flex items-center gap-1">
                <AlertTriangle className="w-3.5 h-3.5" />
                {verificationResults.filter((r) => r.status === 'INDETERMINATE').length} Indeterminate
              </span>
            </div>
          )}
        </div>

        {filteredInvariants.length === 0 ? (
          <div className="p-8 text-center text-gray-500 text-xs italic">
            No invariants configured for this filter. Click "Add Invariant" to define formal safety properties.
          </div>
        ) : (
          <div className="divide-y divide-gray-800">
            {filteredInvariants.map((inv) => {
              const res = getResultForInvariant(inv.invariant_id);
              const isExpanded = expandedWitnessId === inv.invariant_id;

              return (
                <div key={inv.invariant_id} className="p-4 hover:bg-slate-900/30 transition">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-semibold text-white">{inv.name}</span>
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-indigo-950 text-indigo-300 border border-indigo-800/40 font-semibold">
                          {inv.invariant_type}
                        </span>
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-mono font-semibold uppercase ${
                            inv.severity === 'CRITICAL'
                              ? 'bg-rose-950 text-rose-300 border border-rose-800/60'
                              : inv.severity === 'HIGH'
                              ? 'bg-amber-950 text-amber-300 border border-amber-800/60'
                              : 'bg-blue-950 text-blue-300 border border-blue-800/60'
                          }`}
                        >
                          {inv.severity}
                        </span>
                      </div>
                      <p className="text-xs text-gray-400">{inv.description}</p>
                    </div>

                    <div className="flex items-center gap-3 shrink-0">
                      {res ? (
                        <div className="flex items-center gap-2">
                          <span
                            className={`px-2.5 py-1 rounded text-xs font-mono font-bold flex items-center gap-1.5 ${
                              res.status === 'PASS'
                                ? 'bg-emerald-950/70 text-emerald-300 border border-emerald-800/60'
                                : res.status === 'FAIL'
                                ? 'bg-rose-950/70 text-rose-300 border border-rose-800/60'
                                : 'bg-amber-950/70 text-amber-300 border border-amber-800/60'
                            }`}
                          >
                            {res.status === 'PASS' ? (
                              <CheckCircle className="w-3.5 h-3.5 text-emerald-400" />
                            ) : res.status === 'FAIL' ? (
                              <XCircle className="w-3.5 h-3.5 text-rose-400" />
                            ) : (
                              <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                            )}
                            {res.status}
                          </span>

                          {res.witness_path && res.witness_path.length > 0 && (
                            <button
                              onClick={() => setExpandedWitnessId(isExpanded ? null : inv.invariant_id)}
                              className="px-2.5 py-1 rounded bg-gray-800 hover:bg-gray-700 text-gray-200 text-xs font-mono flex items-center gap-1 border border-gray-700"
                            >
                              <span>Witness Path ({res.witness_path.length})</span>
                              {isExpanded ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                            </button>
                          )}
                        </div>
                      ) : (
                        <span className="text-gray-500 text-xs italic font-mono">Not evaluated</span>
                      )}
                    </div>
                  </div>

                  {res && (
                    <div className="mt-2 text-xs font-mono text-gray-300 bg-black/30 p-2.5 rounded border border-gray-800/60">
                      <div className="flex items-center justify-between">
                        <span>{res.explanation}</span>
                        <span className="text-gray-500 text-[10px]">Reason: {res.reason_code}</span>
                      </div>
                      {res.limitations && res.limitations.length > 0 && (
                        <div className="mt-1 text-amber-400 text-[11px] flex items-center gap-1">
                          <AlertTriangle className="w-3 h-3 shrink-0" />
                          <span>Limitation: {res.limitations.join('; ')}</span>
                        </div>
                      )}
                    </div>
                  )}

                  {/* Expanded Witness Path Counterexample */}
                  {isExpanded && res?.witness_path && (
                    <div className="mt-3 p-3 bg-slate-950 border border-rose-900/60 rounded-lg space-y-2">
                      <div className="text-xs font-bold text-rose-300 uppercase tracking-wider flex items-center gap-1.5">
                        <XCircle className="w-3.5 h-3.5 text-rose-400" />
                        Counterexample Witness Path Traversed
                      </div>
                      <div className="space-y-1.5 text-xs font-mono">
                        {res.witness_path.map((hop) => (
                          <div key={hop.hop_index} className="flex items-center gap-2 text-gray-300">
                            <span className="w-5 h-5 rounded-full bg-rose-950 border border-rose-800 flex items-center justify-center text-[10px] text-rose-300 shrink-0">
                              {hop.hop_index}
                            </span>
                            <span className="font-semibold text-white">{hop.node_label}</span>
                            {hop.routed_destination_prefix && (
                              <span className="text-gray-400 text-[11px]">via {hop.routed_destination_prefix}</span>
                            )}
                            {hop.notes && <span className="text-gray-500 text-[11px]">({hop.notes})</span>}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Add Invariant Modal */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 bg-black/75 flex items-center justify-center p-4">
          <form
            onSubmit={handleAddInvariant}
            className="bg-surface border border-gray-700 rounded-lg shadow-xl max-w-lg w-full p-5 space-y-4"
          >
            <div>
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Plus className="w-4 h-4 text-indigo-400" />
                Define Security Invariant
              </h3>
              <p className="text-xs text-gray-400 mt-0.5">
                Formulate an invariant property to be deterministically checked across the network state.
              </p>
            </div>

            <div className="space-y-3 text-xs">
              <div>
                <label className="block text-gray-300 font-medium mb-1">Invariant Name</label>
                <input
                  type="text"
                  value={newName}
                  onChange={(e) => setNewName(e.target.value)}
                  placeholder="e.g. PCI-DSS Cardholder Zone Isolation"
                  className="w-full bg-slate-950 border border-gray-700 rounded px-3 py-1.5 text-gray-200 focus:outline-none focus:border-indigo-500 font-mono"
                  required
                />
              </div>

              <div>
                <label className="block text-gray-300 font-medium mb-1">Description</label>
                <input
                  type="text"
                  value={newDescription}
                  onChange={(e) => setNewDescription(e.target.value)}
                  placeholder="e.g. External untrusted internet sources cannot establish TCP sessions to PCI database"
                  className="w-full bg-slate-950 border border-gray-700 rounded px-3 py-1.5 text-gray-200 focus:outline-none focus:border-indigo-500"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-gray-300 font-medium mb-1">Invariant Type</label>
                  <select
                    value={newType}
                    onChange={(e) => setNewType(e.target.value as InvariantType)}
                    className="w-full bg-slate-950 border border-gray-700 rounded px-3 py-1.5 text-gray-200 focus:outline-none focus:border-indigo-500 font-mono"
                  >
                    <option value="ISOLATION">ISOLATION</option>
                    <option value="REQUIRED_REACHABILITY">REQUIRED_REACHABILITY</option>
                    <option value="PORT_RESTRICTION">PORT_RESTRICTION</option>
                    <option value="MANAGEMENT_PLANE_ISOLATION">MANAGEMENT_PLANE_ISOLATION</option>
                    <option value="CONFIGURATION_CONSISTENCY">CONFIGURATION_CONSISTENCY</option>
                  </select>
                </div>

                <div>
                  <label className="block text-gray-300 font-medium mb-1">Severity</label>
                  <select
                    value={newSeverity}
                    onChange={(e) => setNewSeverity(e.target.value as InvariantSeverity)}
                    className="w-full bg-slate-950 border border-gray-700 rounded px-3 py-1.5 text-gray-200 focus:outline-none focus:border-indigo-500 font-mono"
                  >
                    <option value="CRITICAL">CRITICAL</option>
                    <option value="HIGH">HIGH</option>
                    <option value="MEDIUM">MEDIUM</option>
                    <option value="LOW">LOW</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-gray-300 font-medium mb-1">Source Zone / CIDR</label>
                  <input
                    type="text"
                    value={newSrc}
                    onChange={(e) => setNewSrc(e.target.value)}
                    placeholder="e.g. zone-untrusted"
                    className="w-full bg-slate-950 border border-gray-700 rounded px-3 py-1.5 text-gray-200 focus:outline-none focus:border-indigo-500 font-mono"
                  />
                </div>

                <div>
                  <label className="block text-gray-300 font-medium mb-1">Target IP / CIDR</label>
                  <input
                    type="text"
                    value={newDst}
                    onChange={(e) => setNewDst(e.target.value)}
                    placeholder="e.g. 10.0.1.50/32"
                    className="w-full bg-slate-950 border border-gray-700 rounded px-3 py-1.5 text-gray-200 focus:outline-none focus:border-indigo-500 font-mono"
                  />
                </div>
              </div>

              {newType === 'PORT_RESTRICTION' && (
                <div>
                  <label className="block text-gray-300 font-medium mb-1">Approved Port</label>
                  <input
                    type="number"
                    value={newPort}
                    onChange={(e) => setNewPort(parseInt(e.target.value) || 443)}
                    className="w-full bg-slate-950 border border-gray-700 rounded px-3 py-1.5 text-gray-200 focus:outline-none focus:border-indigo-500 font-mono"
                  />
                </div>
              )}
            </div>

            <div className="flex justify-end gap-2 pt-3 border-t border-gray-800">
              <button
                type="button"
                onClick={() => setShowAddModal(false)}
                className="px-3 py-1.5 rounded bg-gray-800 hover:bg-gray-700 text-gray-300 text-xs font-medium"
              >
                Cancel
              </button>
              <button
                type="submit"
                className="px-4 py-1.5 rounded bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-medium shadow"
              >
                Save Invariant
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
};
