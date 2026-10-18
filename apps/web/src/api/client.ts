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

  // --- Phase 04: Security Testing & Fuzzing ---

  async createTestingCampaign(req: import('../types/testing').CampaignCreateRequest): Promise<import('../types/testing').TestCampaign> {
    return this.request<import('../types/testing').TestCampaign>('/testing/campaigns', {
      method: 'POST',
      body: JSON.stringify(req),
    });
  }

  async listTestingCampaigns(): Promise<import('../types/testing').TestCampaign[]> {
    return this.request<import('../types/testing').TestCampaign[]>('/testing/campaigns');
  }

  async getTestingCampaign(campaignId: string): Promise<import('../types/testing').TestCampaign> {
    return this.request<import('../types/testing').TestCampaign>(`/testing/campaigns/${campaignId}`);
  }

  async runTestingCampaign(campaignId: string): Promise<import('../types/testing').TestCampaign> {
    return this.request<import('../types/testing').TestCampaign>(`/testing/campaigns/${campaignId}/run`, {
      method: 'POST',
    });
  }

  async listTestingCases(campaignId: string, params?: { target?: string; status?: string }): Promise<import('../types/testing').TestCase[]> {
    const q = new URLSearchParams();
    if (params?.target) q.set('target', params.target);
    if (params?.status) q.set('status', params.status);
    const qs = q.toString() ? `?${q.toString()}` : '';
    return this.request<import('../types/testing').TestCase[]>(`/testing/campaigns/${campaignId}/cases${qs}`);
  }

  async getTestCaseDetails(caseId: string): Promise<{ test_case: import('../types/testing').TestCase; execution_result: import('../types/testing').ExecutionResult | null }> {
    return this.request<{ test_case: import('../types/testing').TestCase; execution_result: import('../types/testing').ExecutionResult | null }>(`/testing/cases/${caseId}`);
  }

  async rerunTestCase(caseId: string): Promise<import('../types/testing').ExecutionResult> {
    return this.request<import('../types/testing').ExecutionResult>(`/testing/cases/${caseId}/rerun`, {
      method: 'POST',
    });
  }

  async listTestingFindings(filters?: { campaign_id?: string; severity?: string; protocol?: string; status?: string }): Promise<import('../types/testing').Finding[]> {
    const q = new URLSearchParams();
    if (filters?.campaign_id) q.set('campaign_id', filters.campaign_id);
    if (filters?.severity) q.set('severity', filters.severity);
    if (filters?.protocol) q.set('protocol', filters.protocol);
    if (filters?.status) q.set('status', filters.status);
    const qs = q.toString() ? `?${q.toString()}` : '';
    return this.request<import('../types/testing').Finding[]>(`/testing/findings${qs}`);
  }

  async getTestingFinding(findingId: string): Promise<import('../types/testing').Finding> {
    return this.request<import('../types/testing').Finding>(`/testing/findings/${findingId}`);
  }

  async minimizeFinding(findingId: string): Promise<import('../types/testing').ReproductionArtifact> {
    return this.request<import('../types/testing').ReproductionArtifact>(`/testing/findings/${findingId}/minimize`, {
      method: 'POST',
    });
  }

  async promoteFinding(findingId: string, name: string): Promise<import('../types/testing').RegressionFixture> {
    return this.request<import('../types/testing').RegressionFixture>(`/testing/findings/${findingId}/promote`, {
      method: 'POST',
      body: JSON.stringify({ name }),
    });
  }

  async exportFindingBundle(findingId: string): Promise<Blob> {
    const res = await fetch(`${this.baseUrl}/testing/findings/${findingId}/export`);
    if (!res.ok) throw new Error(`Export failed: ${res.statusText}`);
    return res.blob();
  }

  async listRegressionFixtures(): Promise<import('../types/testing').RegressionFixture[]> {
    return this.request<import('../types/testing').RegressionFixture[]>('/testing/regressions');
  }

  async runRegressionFixture(fixtureId: string): Promise<import('../types/testing').RegressionRunResult> {
    return this.request<import('../types/testing').RegressionRunResult>(`/testing/regressions/${fixtureId}/run`, {
      method: 'POST',
    });
  }

  async runQuickDifferential(): Promise<import('../types/testing').DifferentialResult> {
    return this.request<import('../types/testing').DifferentialResult>('/testing/differential/quick-check', {
      method: 'POST',
    });
  }

  // --- Phase 05: Stateful Protocol Sequence Testing ---

  async listProtocolSequences(sequenceType?: string): Promise<import('../types/sequences').ProtocolSequence[]> {
    const qs = sequenceType ? `?sequence_type=${encodeURIComponent(sequenceType)}` : '';
    return this.request<import('../types/sequences').ProtocolSequence[]>(`/sequences${qs}`);
  }

  async getProtocolSequence(sequenceId: string): Promise<import('../types/sequences').ProtocolSequence> {
    return this.request<import('../types/sequences').ProtocolSequence>(`/sequences/${sequenceId}`);
  }

  async generateSequenceSuite(seed: number = 42): Promise<import('../types/sequences').ProtocolSequence[]> {
    return this.request<import('../types/sequences').ProtocolSequence[]>('/sequences/generate-suite', {
      method: 'POST',
      body: JSON.stringify({ seed }),
    });
  }

  async runProtocolSequence(sequenceId: string): Promise<{ execution: import('../types/sequences').SequenceExecutionResult; findings: import('../types/sequences').SequenceFinding[] }> {
    return this.request<{ execution: import('../types/sequences').SequenceExecutionResult; findings: import('../types/sequences').SequenceFinding[] }>(`/sequences/${sequenceId}/run`, {
      method: 'POST',
    });
  }

  async mutateProtocolSequence(sequenceId: string, mutations: import('../types/sequences').SequenceMutation[]): Promise<import('../types/sequences').ProtocolSequence> {
    return this.request<import('../types/sequences').ProtocolSequence>(`/sequences/${sequenceId}/mutate`, {
      method: 'POST',
      body: JSON.stringify({ mutations }),
    });
  }

  async runSequenceDifferential(req: { sequence_id?: string; mode?: string } = {}): Promise<import('../types/sequences').SequenceDifferentialResult> {
    return this.request<import('../types/sequences').SequenceDifferentialResult>('/sequences/differential', {
      method: 'POST',
      body: JSON.stringify(req),
    });
  }

  async listSequenceFindings(sequenceId?: string): Promise<import('../types/sequences').SequenceFinding[]> {
    const qs = sequenceId ? `?sequence_id=${encodeURIComponent(sequenceId)}` : '';
    return this.request<import('../types/sequences').SequenceFinding[]>(`/sequences/findings${qs}`);
  }

  async minimizeSequenceFinding(findingId: string): Promise<import('../types/sequences').SequenceReproductionMetadata> {
    return this.request<import('../types/sequences').SequenceReproductionMetadata>(`/sequences/findings/${findingId}/minimize`, {
      method: 'POST',
    });
  }

  async promoteSequenceRegression(findingId: string, name: string): Promise<import('../types/sequences').SequenceRegressionFixture> {
    return this.request<import('../types/sequences').SequenceRegressionFixture>(`/sequences/findings/${findingId}/promote-regression`, {
      method: 'POST',
      body: JSON.stringify({ name }),
    });
  }

  async listSequenceRegressions(): Promise<import('../types/sequences').SequenceRegressionFixture[]> {
    return this.request<import('../types/sequences').SequenceRegressionFixture[]>('/sequences/regressions');
  }

  async getCoverageGaps(): Promise<import('../types/sequences').CoverageGapsResponse> {
    return this.request<import('../types/sequences').CoverageGapsResponse>('/sequences/coverage-gaps');
  }

  async exportSequenceBundle(findingId: string): Promise<Blob> {
    const res = await fetch(`${this.baseUrl}/sequences/findings/${findingId}/bundle`);
    if (!res.ok) throw new Error(`Sequence bundle download failed: ${res.statusText}`);
    return res.blob();
  }

  // --- Phase 06: Predictive Network World Model ---

  async listPredictiveDatasets(): Promise<import('../types/predictive').DatasetManifest[]> {
    return this.request<import('../types/predictive').DatasetManifest[]>('/predictive/datasets');
  }

  async extractPredictiveDataset(req: import('../types/predictive').DatasetExtractRequest): Promise<import('../types/predictive').DatasetManifest> {
    return this.request<import('../types/predictive').DatasetManifest>('/predictive/datasets/extract', {
      method: 'POST',
      body: JSON.stringify(req),
    });
  }

  async getPredictiveDataset(datasetId: string): Promise<import('../types/predictive').DatasetManifest> {
    return this.request<import('../types/predictive').DatasetManifest>(`/predictive/datasets/${datasetId}`);
  }

  async trainPredictiveModel(req: import('../types/predictive').ModelTrainRequest): Promise<import('../types/predictive').ModelTrainingRun> {
    return this.request<import('../types/predictive').ModelTrainingRun>('/predictive/train', {
      method: 'POST',
      body: JSON.stringify(req),
    });
  }

  async listPredictiveModels(): Promise<import('../types/predictive').ModelArtifact[]> {
    return this.request<import('../types/predictive').ModelArtifact[]>('/predictive/models');
  }

  async getPredictiveModel(modelId: string): Promise<import('../types/predictive').ModelArtifact> {
    return this.request<import('../types/predictive').ModelArtifact>(`/predictive/models/${modelId}`);
  }

  async predictBehavior(req: import('../types/predictive').PredictionRequest): Promise<import('../types/predictive').PredictionResult> {
    return this.request<import('../types/predictive').PredictionResult>('/predictive/predict', {
      method: 'POST',
      body: JSON.stringify(req),
    });
  }

  async listPredictiveRecords(modelId?: string): Promise<import('../types/predictive').PredictionResult[]> {
    const qs = modelId ? `?model_id=${encodeURIComponent(modelId)}` : '';
    return this.request<import('../types/predictive').PredictionResult[]>(`/predictive/predictions${qs}`);
  }

  async evaluateScenarioConsensus(
    scenarioId: string,
    modelId?: string,
    testProbePacket?: Record<string, unknown>
  ): Promise<import('../types/predictive').ScenarioPredictionComparison> {
    return this.request<import('../types/predictive').ScenarioPredictionComparison>(
      `/predictive/scenarios/${scenarioId}/evaluate`,
      {
        method: 'POST',
        body: JSON.stringify({ model_id: modelId, test_probe_packet: testProbePacket }),
      }
    );
  }

  async getPredictiveLimitations(): Promise<import('../types/predictive').PredictiveLimitationsResponse> {
    return this.request<import('../types/predictive').PredictiveLimitationsResponse>('/predictive/limitations');
  }

  // --- Phase 07 Benchmarking & Auditing ---

  async listBenchmarkFixtures(): Promise<import('../types/benchmark').BenchmarkFixtureMeta[]> {
    return this.request<import('../types/benchmark').BenchmarkFixtureMeta[]>('/benchmarks/fixtures');
  }

  async runBenchmark(req: { fixture_id?: string; category?: string; provenance?: string; random_seed?: number }): Promise<import('../types/benchmark').BenchmarkRunRecord[]> {
    return this.request<import('../types/benchmark').BenchmarkRunRecord[]>('/benchmarks/run', {
      method: 'POST',
      body: JSON.stringify(req),
    });
  }

  async listBenchmarkRuns(limit?: number): Promise<import('../types/benchmark').BenchmarkRunRecord[]> {
    const qs = limit ? `?limit=${limit}` : '';
    return this.request<import('../types/benchmark').BenchmarkRunRecord[]>(`/benchmarks/runs${qs}`);
  }

  async getBenchmarkRun(runId: string): Promise<import('../types/benchmark').BenchmarkRunRecord> {
    return this.request<import('../types/benchmark').BenchmarkRunRecord>(`/benchmarks/runs/${runId}`);
  }

  async getBenchmarkSummary(): Promise<import('../types/benchmark').BenchmarkSummaryResponse> {
    return this.request<import('../types/benchmark').BenchmarkSummaryResponse>('/benchmarks/summary');
  }

  // --- Phase 08 Adversarial Verification & Hardening ---

  async getHardeningCases(): Promise<import('../types/hardening').AdversarialTestCase[]> {
    return this.request<import('../types/hardening').AdversarialTestCase[]>('/twin/hardening/cases');
  }

  async runHardeningSuite(): Promise<import('../types/hardening').AdversarialRunSummary> {
    return this.request<import('../types/hardening').AdversarialRunSummary>('/twin/hardening/run', {
      method: 'POST',
      body: JSON.stringify({}),
    });
  }

  async getLatestHardeningRun(): Promise<import('../types/hardening').AdversarialRunSummary | null> {
    return this.request<import('../types/hardening').AdversarialRunSummary | null>('/twin/hardening/latest');
  }

  async getHardeningRun(runId: string): Promise<import('../types/hardening').AdversarialRunSummary> {
    return this.request<import('../types/hardening').AdversarialRunSummary>(`/twin/hardening/runs/${runId}`);
  }

  // --- Phase 09: Real-Capture Validation & Differential Testing ---

  async listCorpusCaptures(): Promise<import('../types/captures').CaptureManifestItem[]> {
    return this.request<import('../types/captures').CaptureManifestItem[]>('/twin/captures');
  }

  async getCorpusSummary(): Promise<import('../types/captures').CorpusSummaryResponse> {
    return this.request<import('../types/captures').CorpusSummaryResponse>('/twin/captures/summary');
  }

  async getCorpusCapture(captureId: string): Promise<import('../types/captures').CaptureManifestItem> {
    return this.request<import('../types/captures').CaptureManifestItem>(`/twin/captures/${captureId}`);
  }

  async validateCapture(captureId: string): Promise<import('../types/captures').CaptureValidationReport> {
    return this.request<import('../types/captures').CaptureValidationReport>(`/twin/captures/${captureId}/validate`, {
      method: 'POST',
    });
  }

  async runDifferentialTest(req: {
    relation_type: import('../types/captures').MetamorphicRelationType;
    base_capture_id: string;
    transformed_capture_id?: string | null;
    shift_seconds?: number;
  }): Promise<import('../types/captures').DifferentialTestResult> {
    return this.request<import('../types/captures').DifferentialTestResult>('/twin/captures/differential', {
      method: 'POST',
      body: JSON.stringify(req),
    });
  }

  async runE2EValidation(captureId: string): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(`/twin/captures/${captureId}/e2e`, {
      method: 'POST',
    });
  }

  // --- Phase 10: Evidence-Backed Incident Investigation & Root-Cause Analysis ---

  async listInvestigations(): Promise<import('../types/investigations').InvestigationCase[]> {
    return this.request<import('../types/investigations').InvestigationCase[]>('/twin/investigations');
  }

  async createInvestigation(req: import('../types/investigations').CreateInvestigationRequest): Promise<import('../types/investigations').InvestigationCase> {
    return this.request<import('../types/investigations').InvestigationCase>('/twin/investigations', {
      method: 'POST',
      body: JSON.stringify(req),
    });
  }

  async getInvestigation(investigationId: string): Promise<import('../types/investigations').InvestigationCase> {
    return this.request<import('../types/investigations').InvestigationCase>(`/twin/investigations/${investigationId}`);
  }

  async executeInvestigation(investigationId: string): Promise<import('../types/investigations').InvestigationCase> {
    return this.request<import('../types/investigations').InvestigationCase>(`/twin/investigations/${investigationId}/execute`, {
      method: 'POST',
    });
  }

  async runInvestigationCounterfactual(
    investigationId: string,
    req: import('../types/investigations').RunCounterfactualRequest
  ): Promise<import('../types/investigations').InvestigationCase> {
    return this.request<import('../types/investigations').InvestigationCase>(`/twin/investigations/${investigationId}/counterfactual`, {
      method: 'POST',
      body: JSON.stringify(req),
    });
  }

  async exportInvestigation(investigationId: string): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(`/twin/investigations/${investigationId}/export`);
  }

  async deleteInvestigation(investigationId: string): Promise<{ status: string; investigation_id: string }> {
    return this.request<{ status: string; investigation_id: string }>(`/twin/investigations/${investigationId}`, {
      method: 'DELETE',
    });
  }

  // --- Phase 11: Reproducible Replay & Evidence Integrity ---

  async listInvestigationExecutions(
    investigationId: string
  ): Promise<import('../types/investigations').InvestigationExecutionRecord[]> {
    return this.request<import('../types/investigations').InvestigationExecutionRecord[]>(
      `/twin/investigations/${investigationId}/executions`
    );
  }

  async getInvestigationExecution(
    investigationId: string,
    executionId: string
  ): Promise<import('../types/investigations').InvestigationExecutionRecord> {
    return this.request<import('../types/investigations').InvestigationExecutionRecord>(
      `/twin/investigations/${investigationId}/executions/${executionId}`
    );
  }

  async verifyExecutionIntegrity(
    investigationId: string,
    executionId: string
  ): Promise<import('../types/investigations').ExecutionIntegrityReport> {
    return this.request<import('../types/investigations').ExecutionIntegrityReport>(
      `/twin/investigations/${investigationId}/executions/${executionId}/verify-integrity`,
      { method: 'POST' }
    );
  }

  async replayInvestigationExecution(
    investigationId: string,
    executionId: string
  ): Promise<import('../types/investigations').ReplayExecutionResponse> {
    return this.request<import('../types/investigations').ReplayExecutionResponse>(
      `/twin/investigations/${investigationId}/executions/${executionId}/replay`,
      { method: 'POST' }
    );
  }

  async compareInvestigationExecutions(
    investigationId: string,
    executionId: string,
    otherExecutionId: string
  ): Promise<import('../types/investigations').ReplayComparison> {
    return this.request<import('../types/investigations').ReplayComparison>(
      `/twin/investigations/${investigationId}/executions/${executionId}/compare/${otherExecutionId}`
    );
  }

  async exportExecutionAuditPack(
    investigationId: string,
    executionId: string
  ): Promise<import('../types/investigations').AuditPackExport> {
    return this.request<import('../types/investigations').AuditPackExport>(
      `/twin/investigations/${investigationId}/executions/${executionId}/audit-pack`
    );
  }
}

export const apiClient = new NetworkTwinApiClient();



