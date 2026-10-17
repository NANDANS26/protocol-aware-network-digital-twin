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
    expect(screen.getByText(/Overview & Foundation/i)).toBeInTheDocument();
    expect(screen.getByText(/Network Observatory/i)).toBeInTheDocument();
    expect(screen.getByText(/Network Twin/i)).toBeInTheDocument();

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

  it('navigates to planned placeholder views truthfully without fake metrics', async () => {
    vi.mocked(apiClient.getHealth).mockResolvedValue(mockHealth);
    vi.mocked(apiClient.getReadiness).mockResolvedValue(mockHealth);

    render(<App />);

    await waitFor(() => {
      expect(screen.getByText(/API Live \(0\.1\.0\)/i)).toBeInTheDocument();
    });

    // Click on Network Observatory tab
    const observatoryBtn = screen.getByRole('button', { name: /Network Observatory/i });
    fireEvent.click(observatoryBtn);

    await waitFor(() => {
      expect(screen.getByTestId('placeholder-view')).toBeInTheDocument();
      expect(screen.getByText(/Module Status: Planned Architecture Component/i)).toBeInTheDocument();
      expect(screen.getByText(/Reliability & Truthfulness Policy/i)).toBeInTheDocument();
    });
  });
});
