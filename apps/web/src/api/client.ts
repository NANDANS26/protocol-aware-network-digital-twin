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

  async uploadCapture(file: File): Promise<import('../types/analysis').JobUploadResponse> {
    const formData = new FormData();
    formData.append('file', file);
    return this.request<import('../types/analysis').JobUploadResponse>('/analysis/upload', {
      method: 'POST',
      body: formData,
    });
  }

  async runDemoAnalysis(format: 'pcap' | 'pcapng' = 'pcap'): Promise<import('../types/analysis').JobUploadResponse> {
    return this.request<import('../types/analysis').JobUploadResponse>(`/analysis/demo?format=${format}`, {
      method: 'POST',
    });
  }

  async listJobs(): Promise<import('../types/analysis').AnalysisJob[]> {
    return this.request<import('../types/analysis').AnalysisJob[]>('/analysis/jobs');
  }

  async getJob(jobId: string): Promise<import('../types/analysis').AnalysisJob> {
    return this.request<import('../types/analysis').AnalysisJob>(`/analysis/jobs/${jobId}`);
  }

  async getJobFlows(
    jobId: string,
    ipProto?: string,
    offset = 0,
    limit = 100
  ): Promise<import('../types/analysis').FlowListResponse> {
    const query = new URLSearchParams({ offset: String(offset), limit: String(limit) });
    if (ipProto) query.set('ip_proto', ipProto);
    return this.request<import('../types/analysis').FlowListResponse>(`/analysis/jobs/${jobId}/flows?${query.toString()}`);
  }

  async getJobEvents(
    jobId: string,
    offset = 0,
    limit = 100,
    status?: string
  ): Promise<import('../types/analysis').EventListResponse> {
    const query = new URLSearchParams({ offset: String(offset), limit: String(limit) });
    if (status) query.set('status', status);
    return this.request<import('../types/analysis').EventListResponse>(`/analysis/jobs/${jobId}/events?${query.toString()}`);
  }

  // --- Phase 02 Intelligence & Topology Endpoints ---

  async listAssets(params?: { q?: string; status?: string; limit?: number; offset?: number }): Promise<import('../types/intelligence').Asset[]> {
    const query = new URLSearchParams();
    if (params?.q) query.set('q', params.q);
    if (params?.status) query.set('status', params.status);
    if (params?.limit !== undefined) query.set('limit', String(params.limit));
    if (params?.offset !== undefined) query.set('offset', String(params.offset));
    const qs = query.toString();
    return this.request<import('../types/intelligence').Asset[]>(`/assets${qs ? `?${qs}` : ''}`);
  }

  async getAsset(assetId: string): Promise<import('../types/intelligence').Asset> {
    return this.request<import('../types/intelligence').Asset>(`/assets/${assetId}`);
  }

  async getAssetRelationships(assetId: string, limit = 100): Promise<import('../types/intelligence').CommunicationRelationship[]> {
    return this.request<import('../types/intelligence').CommunicationRelationship[]>(`/assets/${assetId}/relationships?limit=${limit}`);
  }

  async listSegments(): Promise<import('../types/intelligence').NetworkSegment[]> {
    return this.request<import('../types/intelligence').NetworkSegment[]>('/segments');
  }

  async listServices(assetId?: string): Promise<import('../types/intelligence').NetworkService[]> {
    const qs = assetId ? `?asset_id=${encodeURIComponent(assetId)}` : '';
    return this.request<import('../types/intelligence').NetworkService[]>(`/services${qs}`);
  }

  async listRelationships(params?: { assetId?: string; limit?: number; offset?: number }): Promise<import('../types/intelligence').CommunicationRelationship[]> {
    const query = new URLSearchParams();
    if (params?.assetId) query.set('asset_id', params.assetId);
    if (params?.limit !== undefined) query.set('limit', String(params.limit));
    if (params?.offset !== undefined) query.set('offset', String(params.offset));
    const qs = query.toString();
    return this.request<import('../types/intelligence').CommunicationRelationship[]>(`/relationships${qs ? `?${qs}` : ''}`);
  }

  async listEvidence(params?: { sourceArtifactId?: string; evidenceType?: string; limit?: number; offset?: number }): Promise<import('../types/intelligence').EvidenceRecord[]> {
    const query = new URLSearchParams();
    if (params?.sourceArtifactId) query.set('source_artifact_id', params.sourceArtifactId);
    if (params?.evidenceType) query.set('evidence_type', params.evidenceType);
    if (params?.limit !== undefined) query.set('limit', String(params.limit));
    if (params?.offset !== undefined) query.set('offset', String(params.offset));
    const qs = query.toString();
    return this.request<import('../types/intelligence').EvidenceRecord[]>(`/evidence${qs ? `?${qs}` : ''}`);
  }

  async getEvidence(evidenceId: string): Promise<import('../types/intelligence').EvidenceRecord> {
    return this.request<import('../types/intelligence').EvidenceRecord>(`/evidence/${evidenceId}`);
  }

  async importConfiguration(req: import('../types/intelligence').ConfigImportRequest): Promise<import('../types/intelligence').ConfigImportResult> {
    return this.request<import('../types/intelligence').ConfigImportResult>('/imports', {
      method: 'POST',
      body: JSON.stringify(req),
    });
  }

  async listImports(): Promise<import('../types/intelligence').ConfigImportResult[]> {
    return this.request<import('../types/intelligence').ConfigImportResult[]>('/imports');
  }

  async getTopology(): Promise<import('../types/intelligence').TopologyGraph> {
    return this.request<import('../types/intelligence').TopologyGraph>('/topology');
  }

  async createSnapshot(req: { name: string; source_captures?: string[]; source_configs?: string[] }): Promise<import('../types/intelligence').TopologySnapshot> {
    return this.request<import('../types/intelligence').TopologySnapshot>('/snapshots', {
      method: 'POST',
      body: JSON.stringify(req),
    });
  }

  async listSnapshots(): Promise<import('../types/intelligence').TopologySnapshot[]> {
    return this.request<import('../types/intelligence').TopologySnapshot[]>('/snapshots');
  }

  async getSnapshot(snapshotId: string): Promise<import('../types/intelligence').TopologySnapshot> {
    return this.request<import('../types/intelligence').TopologySnapshot>(`/snapshots/${snapshotId}`);
  }

  async getSnapshotGraph(snapshotId: string): Promise<import('../types/intelligence').TopologyGraph> {
    return this.request<import('../types/intelligence').TopologyGraph>(`/snapshots/${snapshotId}/graph`);
  }

  async compareSnapshots(baseSnapshotId: string, targetSnapshotId: string): Promise<import('../types/intelligence').SnapshotComparisonDiff> {
    return this.request<import('../types/intelligence').SnapshotComparisonDiff>('/snapshots/compare', {
      method: 'POST',
      body: JSON.stringify({
        base_snapshot_id: baseSnapshotId,
        target_snapshot_id: targetSnapshotId,
      }),
    });
  }

  async listCaptures(): Promise<import('../types/intelligence').CaptureMetadata[]> {
    return this.request<import('../types/intelligence').CaptureMetadata[]>('/captures');
  }

  async getTopTalkers(jobId: string, limit = 10): Promise<import('../types/intelligence').TopTalker[]> {
    return this.request<import('../types/intelligence').TopTalker[]>(`/analytics/top-talkers?job_id=${encodeURIComponent(jobId)}&limit=${limit}`);
  }

  async getProtocolBreakdown(jobId: string): Promise<import('../types/intelligence').ProtocolBreakdown[]> {
    return this.request<import('../types/intelligence').ProtocolBreakdown[]>(`/analytics/protocol-breakdown?job_id=${encodeURIComponent(jobId)}`);
  }

  // --- Phase 03 Simulation, Reachability & Security Verification Endpoints ---

  async buildNetworkModel(req: import('../types/simulation').BuildModelRequest): Promise<import('../types/simulation').NetworkModel> {
    return this.request<import('../types/simulation').NetworkModel>('/models/build', {
      method: 'POST',
      body: JSON.stringify(req),
    });
  }

  async listModels(): Promise<import('../types/simulation').NetworkModel[]> {
    return this.request<import('../types/simulation').NetworkModel[]>('/models');
  }

  async getModel(modelId: string): Promise<import('../types/simulation').NetworkModel> {
    return this.request<import('../types/simulation').NetworkModel>(`/models/${modelId}`);
  }

  async getModelLimitations(modelId: string): Promise<import('../types/simulation').ModelLimitation[]> {
    return this.request<import('../types/simulation').ModelLimitation[]>(`/models/${modelId}/limitations`);
  }

  async evaluateReachability(query: import('../types/simulation').ReachabilityQuery): Promise<import('../types/simulation').ReachabilityResult> {
    return this.request<import('../types/simulation').ReachabilityResult>('/simulations/reachability', {
      method: 'POST',
      body: JSON.stringify(query),
    });
  }

  async createScenario(scenario: import('../types/simulation').SimulationScenario): Promise<import('../types/simulation').SimulationScenario> {
    return this.request<import('../types/simulation').SimulationScenario>('/simulations/scenarios', {
      method: 'POST',
      body: JSON.stringify(scenario),
    });
  }

  async listScenarios(baseModelId?: string): Promise<import('../types/simulation').SimulationScenario[]> {
    const query = baseModelId ? `?base_model_id=${encodeURIComponent(baseModelId)}` : '';
    return this.request<import('../types/simulation').SimulationScenario[]>(`/simulations/scenarios${query}`);
  }

  async getScenario(scenarioId: string): Promise<import('../types/simulation').SimulationScenario> {
    return this.request<import('../types/simulation').SimulationScenario>(`/simulations/scenarios/${scenarioId}`);
  }

  async runScenario(
    scenarioId: string,
    req?: import('../types/simulation').RunScenarioRequest
  ): Promise<import('../types/simulation').CounterfactualResult> {
    return this.request<import('../types/simulation').CounterfactualResult>(`/simulations/scenarios/${scenarioId}/run`, {
      method: 'POST',
      body: JSON.stringify(req || {}),
    });
  }

  async getCounterfactualResult(scenarioId: string): Promise<import('../types/simulation').CounterfactualResult> {
    return this.request<import('../types/simulation').CounterfactualResult>(`/simulations/scenarios/${scenarioId}/result`);
  }

  async listInvariants(): Promise<import('../types/simulation').SecurityInvariant[]> {
    return this.request<import('../types/simulation').SecurityInvariant[]>('/verification/invariants');
  }

  async createInvariant(invariant: import('../types/simulation').SecurityInvariant): Promise<import('../types/simulation').SecurityInvariant> {
    return this.request<import('../types/simulation').SecurityInvariant>('/verification/invariants', {
      method: 'POST',
      body: JSON.stringify(invariant),
    });
  }

  async runVerification(req: import('../types/simulation').RunVerificationRequest): Promise<import('../types/simulation').VerificationResult[]> {
    return this.request<import('../types/simulation').VerificationResult[]>('/verification/run', {
      method: 'POST',
      body: JSON.stringify(req),
    });
  }

  async getVerificationResults(runId: string): Promise<import('../types/simulation').VerificationResult[]> {
    return this.request<import('../types/simulation').VerificationResult[]>(`/verification/runs/${runId}`);
  }
}

export const apiClient = new NetworkTwinApiClient();


