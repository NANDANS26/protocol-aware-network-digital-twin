import React, { useState } from 'react';
import type { HealthStatusResponse } from '@contracts/health';
import type { NetworkEvent } from '@contracts/network_event';
import { SubsystemCard } from '../components/SubsystemCard';
import { apiClient } from '../api/client';
import {
  Code2,
  CheckCircle,
  AlertOctagon,
  Layers,
  Inbox,
} from 'lucide-react';

interface OverviewViewProps {
  health: HealthStatusResponse | null;
  readiness: HealthStatusResponse | null;
  onRefresh: () => void;
}

export const OverviewView: React.FC<OverviewViewProps> = ({
  health,
  readiness,
}) => {
  const [contractValidationResult, setContractValidationResult] = useState<string | null>(null);
  const [isValidating, setIsValidating] = useState<boolean>(false);

  const handleTestEventValidation = async (type: 'valid' | 'invalid') => {
    setIsValidating(true);
    setContractValidationResult(null);

    const baseEvent: NetworkEvent = {
      schema_version: '1.0.0',
      event_id: '550e8400-e29b-41d4-a716-446655440000',
      timestamp_ns: 1729153800000000000,
      timestamp_iso: new Date().toISOString(),
      source_id: 'sensor-test-edge',
      flow_id: 'flow-tcp-syn-01',
      flow_direction: 'forward',
      link_layer: {
        source_mac: type === 'valid' ? '00:1A:2B:3C:4D:5E' : 'INVALID_MAC',
        destination_mac: '00:1A:2B:3C:4D:5F',
        ether_type: 2048,
      },
      network_layer: {
        version: 'IPv4',
        source_ip: '192.168.1.50',
        destination_ip: '10.0.0.1',
        ttl_or_hop_limit: 64,
      },
      transport_layer: {
        protocol: 'TCP',
        source_port: 49152,
        destination_port: 443,
        tcp_flags: { syn: true, ack: false },
      },
      parser_status: {
        status: 'ok',
        bytes_consumed: 54,
        bytes_remaining: 0,
      },
      provenance: {
        packet_index: 0,
        wire_length_bytes: 64,
        capture_length_bytes: 64,
        capture_interface: 'eth0',
      },
    };

    try {
      const res = await apiClient.validateEvent(baseEvent);
      setContractValidationResult(
        JSON.stringify(
          {
            test_type: type,
            status: 'HTTP 200 OK - Passed Schema & Pydantic Validation',
            response: res,
          },
          null,
          2
        )
      );
    } catch (err: any) {
      setContractValidationResult(
        JSON.stringify(
          {
            test_type: type,
            status: `HTTP ${err.statusCode || 'Error'} - Expected Validation Failure`,
            error: err.message,
            details: err.details,
            request_id: err.requestId,
          },
          null,
          2
        )
      );
    } finally {
      setIsValidating(false);
    }
  };

  const subsystems = [
    {
      id: 'api_service',
      name: 'FastAPI Backend Foundation',
      phase: 'Phase 00 Foundation',
      description: 'Typed asynchronous API runtime with request correlation, centralized error handling, and CORS restrictions.',
    },
    {
      id: 'protocol_analysis_engine',
      name: 'C++20 Protocol Analysis Engine',
      phase: 'Phase 01 Systems Engine',
      description: 'Zero-copy packet source abstraction, frame decoders, state machines, and structured event streaming.',
    },
    {
      id: 'flow_tracker',
      name: 'Flow & Connection State Tracker',
      phase: 'Phase 01 Systems Engine',
      description: 'Bidirectional 5-tuple canonical flow hashing, TCP state reconstruction, and session reassembly.',
    },
    {
      id: 'database',
      name: 'Persistent Metadata Store (PostgreSQL)',
      phase: 'Phase 02 Data & Topology',
      description: 'Versioned relational schema and migrations for capture catalogs, session records, and audit events.',
    },
    {
      id: 'network_digital_twin',
      name: 'Versioned Network Digital Twin',
      phase: 'Phase 03 Digital Twin',
      description: 'Evidence-based topology reconstruction, reachability models, and active device state representations.',
    },
    {
      id: 'security_verification_engine',
      name: 'Security Verification Engine',
      phase: 'Phase 04 Security Engine',
      description: 'Deterministic security policy verification, invariant checking, and counterexample generation.',
    },
  ];

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="p-5 rounded-lg border border-blue-900/40 bg-gradient-to-r from-blue-950/40 to-surface-raised flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="px-2 py-0.5 rounded bg-blue-600/30 text-blue-300 text-xs font-mono font-medium border border-blue-500/30">
              System State
            </span>
            <h2 className="text-base font-semibold text-gray-100">
              Enterprise Engineering Foundation Active
            </h2>
          </div>
          <p className="text-xs text-gray-300 max-w-2xl leading-relaxed">
            Phase 00 establishes the verified C++20 engine skeleton, FastAPI service baseline, React engineering workstation,
            and canonical structured-event contracts. Subsystems reflect true operational state without simulated metrics.
          </p>
        </div>

        <div className="flex items-center gap-3 shrink-0">
          <div className="p-3 rounded bg-surface border border-surface-border text-center">
            <div className="text-[10px] uppercase font-mono text-gray-400">Schema Version</div>
            <div className="text-sm font-mono font-bold text-blue-400">
              {health?.schema_version || '1.0.0'}
            </div>
          </div>
          <div className="p-3 rounded bg-surface border border-surface-border text-center">
            <div className="text-[10px] uppercase font-mono text-gray-400">Dependency Readiness</div>
            <div className="text-sm font-mono font-bold text-emerald-400">
              {readiness?.status === 'healthy' ? 'READY' : 'DEGRADED'}
            </div>
          </div>
        </div>
      </div>

      {/* Subsystem Telemetry Grid */}
      <section aria-labelledby="subsystems-heading">
        <div className="flex items-center justify-between mb-3">
          <h3 id="subsystems-heading" className="text-sm font-semibold text-gray-200 flex items-center gap-2">
            <Layers className="w-4 h-4 text-blue-400" />
            <span>Platform Subsystems Operational Registry</span>
          </h3>
          <span className="text-xs font-mono text-gray-400">
            6 Subsystems Registered
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {subsystems.map((sub) => (
            <SubsystemCard
              key={sub.id}
              id={sub.id}
              name={sub.name}
              phase={sub.phase}
              report={health?.subsystems?.[sub.id]}
              description={sub.description}
            />
          ))}
        </div>
      </section>

      {/* Live Event Contract Verification Section */}
      <section aria-labelledby="contract-heading" className="p-5 rounded-lg bg-surface border border-surface-border">
        <div className="flex items-center justify-between mb-3">
          <div>
            <h3 id="contract-heading" className="text-sm font-semibold text-gray-200 flex items-center gap-2">
              <Code2 className="w-4 h-4 text-emerald-400" />
              <span>Full-Stack Contract & Schema Verifier</span>
            </h3>
            <p className="text-xs text-gray-400 mt-0.5">
              Dispatches structured NetworkEvents from React to the backend validation endpoint to verify strict JSON Schema & Pydantic conformance.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => handleTestEventValidation('valid')}
              disabled={isValidating}
              className="px-3 py-1.5 rounded bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-300 border border-emerald-500/30 text-xs font-mono font-medium transition disabled:opacity-50 flex items-center gap-1.5"
            >
              <CheckCircle className="w-3.5 h-3.5" />
              <span>Send Valid Event</span>
            </button>
            <button
              onClick={() => handleTestEventValidation('invalid')}
              disabled={isValidating}
              className="px-3 py-1.5 rounded bg-rose-600/20 hover:bg-rose-600/30 text-rose-300 border border-rose-500/30 text-xs font-mono font-medium transition disabled:opacity-50 flex items-center gap-1.5"
            >
              <AlertOctagon className="w-3.5 h-3.5" />
              <span>Send Malformed MAC</span>
            </button>
          </div>
        </div>

        {contractValidationResult && (
          <div className="mt-3">
            <div className="text-[10px] font-mono text-gray-400 mb-1 uppercase tracking-wider">
              Verification Response Stream:
            </div>
            <pre className="p-3 rounded bg-background border border-surface-border text-xs font-mono text-gray-200 overflow-x-auto max-h-56">
              {contractValidationResult}
            </pre>
          </div>
        )}
      </section>

      {/* Honest Empty State for Captures */}
      <section className="p-6 rounded-lg bg-surface/50 border border-surface-border/60 text-center">
        <div className="w-10 h-10 rounded-full bg-surface-raised border border-surface-border flex items-center justify-center mx-auto mb-3 text-gray-400">
          <Inbox className="w-5 h-5" />
        </div>
        <h4 className="text-sm font-medium text-gray-200 mb-1">
          No Packet Captures or Digital Twin Topologies Loaded
        </h4>
        <p className="text-xs text-gray-400 max-w-md mx-auto leading-relaxed mb-4">
          The engineering foundation is initialized. PCAP ingestion pipelines, live interface monitoring,
          and graph reconstruction will activate in Phase 01 and Phase 03.
        </p>
        <span className="text-[11px] font-mono px-2.5 py-1 rounded bg-surface border border-surface-border text-gray-400">
          Status: Ready for Phase 01 systems engine ingestion
        </span>
      </section>
    </div>
  );
};
