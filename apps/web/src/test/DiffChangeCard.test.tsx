import { describe, it, expect } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { DiffChangeCard } from '../views/twin/DiffChangeCard';

describe('DiffChangeCard component', () => {
  it('renders a plain string explanation safely', () => {
    render(<DiffChangeCard change="Added node 10.0.0.1 due to ARP broadcast." index={0} />);

    expect(screen.getByText('ANNOUNCEMENT')).toBeInTheDocument();
    expect(screen.getByText('Added node 10.0.0.1 due to ARP broadcast.')).toBeInTheDocument();
  });

  it('renders a typed node change object', () => {
    const nodeChange = {
      type: 'added_entity',
      node_id: 'node-server-01',
      explanation: 'Newly discovered server host: db-primary.local',
    };

    render(<DiffChangeCard change={nodeChange} index={1} />);

    expect(screen.getByText('ENTITY')).toBeInTheDocument();
    expect(screen.getByText('added_entity')).toBeInTheDocument();
    expect(screen.getByText('node-server-01')).toBeInTheDocument();
    expect(screen.getByText('Newly discovered server host: db-primary.local')).toBeInTheDocument();
  });

  it('renders a typed edge change object with evidence class and expandable evidence IDs', () => {
    const edgeChange = {
      type: 'added_relationship',
      edge_id: 'edge-192-168-1-100->192.168.1.200',
      evidence_class: 'DIRECT_OBSERVATION',
      explanation: 'Newly observed communication (TCP) between 192.168.1.100 and 192.168.1.200 (150 packets)',
      evidence_ids: ['ev-pcap-001', 'ev-pcap-002'],
    };

    render(<DiffChangeCard change={edgeChange} index={2} />);

    expect(screen.getByText('RELATIONSHIP')).toBeInTheDocument();
    expect(screen.getByText('DIRECT_OBSERVATION')).toBeInTheDocument();
    expect(screen.getByText('edge-192-168-1-100->192.168.1.200')).toBeInTheDocument();
    expect(
      screen.getByText(/Newly observed communication \(TCP\) between 192\.168\.1\.100 and 192\.168\.1\.200/)
    ).toBeInTheDocument();

    // Evidence drawer is collapsed initially
    expect(screen.queryByText('ev-pcap-001')).not.toBeInTheDocument();

    // Click to expand evidence drawer
    const evidenceBtn = screen.getByRole('button', { name: /Evidence Records \(2\)/i });
    fireEvent.click(evidenceBtn);

    expect(screen.getByText('ev-pcap-001')).toBeInTheDocument();
    expect(screen.getByText('ev-pcap-002')).toBeInTheDocument();
  });

  it('handles missing optional fields and null values without crashing', () => {
    const sparseChange = {
      type: null,
      edge_id: undefined,
      node_id: null,
      explanation: '',
      evidence_ids: null,
    };

    render(<DiffChangeCard change={sparseChange} index={3} />);

    // Should have safe fallback representations without crashing
    expect(screen.getAllByText(/change/i).length).toBeGreaterThanOrEqual(1);
  });

  it('handles unknown change types and renders metadata details drawer', () => {
    const unknownChange = {
      type: 'anomalous_latency_spike',
      target_resource: 'switch-core-01',
      latency_delta_ms: 45.2,
      explanation: 'Unexpected latency surge on core uplink',
    };

    render(<DiffChangeCard change={unknownChange} index={4} />);

    expect(screen.getByText('ANOMALOUS LATENCY SPIKE')).toBeInTheDocument();
    expect(screen.getByText('Unexpected latency surge on core uplink')).toBeInTheDocument();

    const detailsBtn = screen.getByRole('button', { name: /Field Details & Changes/i });
    fireEvent.click(detailsBtn);

    expect(screen.getByText(/latency_delta_ms/i)).toBeInTheDocument();
  });

  it('renders field changes cleanly when present', () => {
    const modifiedRecord = {
      type: 'modified_entity',
      node_id: 'node-asset-55',
      changes: {
        label: { from: 'web-dev-old', to: 'web-prod-new' },
        node_type: { from: 'UNKNOWN', to: 'SERVER' },
      },
      explanation: 'Updated device classification and hostname',
    };

    render(<DiffChangeCard change={modifiedRecord} index={5} />);

    expect(screen.getByText('ENTITY')).toBeInTheDocument();
    expect(screen.getByText('node-asset-55')).toBeInTheDocument();

    const detailsBtn = screen.getByRole('button', { name: /Field Details & Changes/i });
    fireEvent.click(detailsBtn);

    expect(screen.getByText('web-dev-old')).toBeInTheDocument();
    expect(screen.getByText('web-prod-new')).toBeInTheDocument();
  });
});
