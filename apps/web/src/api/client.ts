import type { HealthStatusResponse } from '@contracts/health';
import type { NetworkEvent } from '@contracts/network_event';

export interface ApiClientConfig {
  baseUrl?: string;
  timeoutMs?: number;
}

export interface ApiError {
  error: string;
  message: string;
  statusCode?: number;
  requestId?: string;
  details?: unknown;
}

export class NetworkTwinApiClient {
  private baseUrl: string;
  private timeoutMs: number;

  constructor(config: ApiClientConfig = {}) {
    this.baseUrl = config.baseUrl || '/api/v1';
    this.timeoutMs = config.timeoutMs || 8000;
  }

  private async request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
    const url = `${this.baseUrl}${endpoint}`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    const headers: Record<string, string> = {
      'Accept': 'application/json',
      ...((options.headers as Record<string, string>) || {}),
    };

    if (options.body && typeof options.body === 'string') {
      headers['Content-Type'] = 'application/json';
    }

    try {
      const response = await fetch(url, {
        ...options,
        headers,
        signal: controller.signal,
      });

      clearTimeout(timer);

      const requestId = response.headers.get('x-request-id') || undefined;

      if (!response.ok) {
        let errorData: any = {};
        try {
          errorData = await response.json();
        } catch {
          errorData = { message: response.statusText };
        }

        const apiError: ApiError = {
          error: errorData.error || 'RequestFailed',
          message: errorData.message || `HTTP ${response.status}: ${response.statusText}`,
          statusCode: response.status,
          requestId: errorData.request_id || requestId,
          details: errorData.details,
        };
        throw apiError;
      }

      return (await response.json()) as T;
    } catch (err: unknown) {
      clearTimeout(timer);
      if ((err as Error).name === 'AbortError') {
        const timeoutError: ApiError = {
          error: 'TimeoutError',
          message: `Request to ${endpoint} timed out after ${this.timeoutMs}ms`,
        };
        throw timeoutError;
      }
      if ((err as ApiError).statusCode) {
        throw err;
      }
      const networkError: ApiError = {
        error: 'NetworkError',
        message: err instanceof Error ? err.message : 'Failed to reach API server',
      };
      throw networkError;
    }
  }

  async getHealth(): Promise<HealthStatusResponse> {
    return this.request<HealthStatusResponse>('/health');
  }

  async getReadiness(): Promise<HealthStatusResponse> {
    return this.request<HealthStatusResponse>('/ready');
  }

  async getVersion(): Promise<{
    app_name: string;
    app_version: string;
    schema_version: string;
    environment: string;
  }> {
    return this.request('/version');
  }

  async getEventSchema(): Promise<Record<string, unknown>> {
    return this.request('/events/schema');
  }

  async validateEvent(event: NetworkEvent): Promise<{
    valid: boolean;
    event_id: string;
    schema_version: string;
    parser_status: string;
    source_id: string;
    timestamp_ns: number;
    timestamp_iso: string;
  }> {
    return this.request('/events/validate', {
      method: 'POST',
      body: JSON.stringify(event),
    });
  }
}

export const apiClient = new NetworkTwinApiClient();
