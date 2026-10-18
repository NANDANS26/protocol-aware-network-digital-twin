import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import App from '../App';
import { apiClient } from '../api/client';
import type { HealthStatusResponse } from '@contracts/health';

vi.mock('../api/client', () => {
  return {
    apiClient: {
      getHealth: vi.fn(),
      getReadiness: vi.fn(),
      validateEvent: vi.fn(),
      listAssets: vi.fn().mockResolvedValue([]),
      listSegments: vi.fn().mockResolvedValue([]),
      listServices: vi.fn().mockResolvedValue([]),
      listRelationships: vi.fn().mockResolvedValue([]),
      listEvidence: vi.fn().mockResolvedValue([]),
      getTopology: vi.fn().mockResolvedValue({
        nodes: [],
        edges: [],
        generated_at_iso: '2026-10-17T10:00:00Z',
        node_count: 0,
        edge_count: 0,
        subnets_count: 0,
        services_count: 0,
      }),
      listSnapshots: vi.fn().mockResolvedValue([]),
      listCaptures: vi.fn().mockResolvedValue([]),
      listImports: vi.fn().mockResolvedValue([]),
      listInvestigations: vi.fn().mockResolvedValue([]),
    },
  };
});

describe('Application Shell & Navigation', () => {
  const mockHealth: HealthStatusResponse = {
    status: 'healthy',
    timestamp: '2026-10-17T08:30:00Z',
    version: '0.1.0',
    schema_version: '1.0.0',
    environment: 'development',
    subsystems: {
      api_service: {
        status: 'ok',
        operational_state: 'operational',
        details: 'FastAPI host operational on 127.0.0.1:8000',
        last_checked: '2026-10-17T08:30:00Z',
      },
      protocol_analysis_engine: {
        status: 'planned',
        operational_state: 'planned',
        details: 'C++20 ingestion engine scheduled for Phase 01.',
        last_checked: '2026-10-17T08:30:00Z',
      },
      flow_tracker: {
        status: 'planned',
        operational_state: 'planned',
        details: 'Flow tracking scheduled for Phase 01.',
        last_checked: '2026-10-17T08:30:00Z',
      },
      database: {
        status: 'disabled',
        operational_state: 'unavailable',
        details: 'Stateless foundation mode.',
        last_checked: '2026-10-17T08:30:00Z',
      },
    },
  };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders application title and navigation modules', async () => {
    vi.mocked(apiClient.getHealth).mockResolvedValue(mockHealth);
    vi.mocked(apiClient.getReadiness).mockResolvedValue(mockHealth);

    render(<App />);

    expect(screen.getByText(/Protocol Digital Twin/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /System Overview/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Network Observatory/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Network Digital Twin/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Scenario Laboratory/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Protocol Research Lab/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Investigation Workspace/i })).toBeInTheDocument();

    await waitFor(() => {
      expect(screen.getByText(/API Live \(0\.1\.0\)/i)).toBeInTheDocument();
    });
  });

  it('displays error banner and retry action on backend connection failure', async () => {
    vi.mocked(apiClient.getHealth).mockRejectedValue({
      error: 'NetworkError',
      message: 'Failed to connect to backend service',
      statusCode: 503,
      requestId: 'req-err-12345',
    });
    vi.mocked(apiClient.getReadiness).mockRejectedValue({
      error: 'NetworkError',
      message: 'Failed to connect to backend service',
    });

    render(<App />);

    await waitFor(() => {
      expect(screen.getByTestId('error-banner')).toBeInTheDocument();
      expect(screen.getByText(/Backend Connection Failure: NetworkError/i)).toBeInTheDocument();
      expect(screen.getByText(/Retry Connection/i)).toBeInTheDocument();
    });
  });

  it('navigates across integrated operational views truthfully', async () => {
    vi.mocked(apiClient.getHealth).mockResolvedValue(mockHealth);
    vi.mocked(apiClient.getReadiness).mockResolvedValue(mockHealth);

    render(<App />);

    await waitFor(() => {
      expect(screen.getByText(/API Live \(0\.1\.0\)/i)).toBeInTheDocument();
    });

    // Click on Network Observatory tab -> renders real observatory view
    const observatoryBtn = screen.getByRole('button', { name: /Network Observatory/i });
    fireEvent.click(observatoryBtn);

    await waitFor(() => {
      expect(screen.getByText(/High-throughput offline capture ingestion/i)).toBeInTheDocument();
      expect(screen.getByText(/Upload PCAP \/ PCAPNG/i)).toBeInTheDocument();
    });

    // Click on Network Digital Twin tab -> renders operational Network Twin view
    const twinBtn = screen.getByRole('button', { name: /Network Digital Twin/i });
    fireEvent.click(twinBtn);

    await waitFor(() => {
      expect(screen.getByRole('heading', { level: 1, name: /Network Digital Twin/i })).toBeInTheDocument();
      expect(screen.getByText(/Twin Operational/i)).toBeInTheDocument();
    });

    // Click on Scenario Laboratory tab -> renders operational Scenario Laboratory
    const labBtn = screen.getByRole('button', { name: /Scenario Laboratory/i });
    fireEvent.click(labBtn);

    await waitFor(() => {
      expect(screen.getByTestId('scenario-laboratory')).toBeInTheDocument();
      expect(screen.getByText(/Deterministic Security Verification & What-If Simulation/i)).toBeInTheDocument();
    });

    // Click on Investigation Workspace tab -> renders operational Investigation Workbench
    const invBtn = screen.getByRole('button', { name: /Investigation Workspace/i });
    fireEvent.click(invBtn);

    await waitFor(() => {
      expect(screen.getByText(/Evidence-Backed Network Incident Investigation & Reproducible Replay/i)).toBeInTheDocument();
      expect(screen.getByText(/Replay & Integrity Verified/i)).toBeInTheDocument();
    });
  });
});
