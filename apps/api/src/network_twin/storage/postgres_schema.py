"""PostgreSQL DDL schema definitions and migrations for Protocol Digital Twin."""

POSTGRES_SCHEMA_V9_DDL = """
-- Schema Migrations Tracking
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    description TEXT NOT NULL
);

-- 1. Captures
CREATE TABLE IF NOT EXISTS captures (
    capture_id VARCHAR(256) PRIMARY KEY,
    filename TEXT NOT NULL,
    content_sha256 VARCHAR(256) NOT NULL,
    file_size_bytes BIGINT NOT NULL,
    format VARCHAR(32) NOT NULL,
    storage_path TEXT NOT NULL,
    uploaded_at TEXT NOT NULL,
    lifecycle_status VARCHAR(32) NOT NULL DEFAULT 'COMPLETE',
    error_message TEXT,
    active_analysis_run_id VARCHAR(256),
    engine_version VARCHAR(32) DEFAULT '1.0.0',
    pipeline_version VARCHAR(32) DEFAULT '1.0.0',
    schema_version VARCHAR(32) DEFAULT '1.0.0',
    packet_count BIGINT DEFAULT 0,
    event_count BIGINT DEFAULT 0,
    accepted_count BIGINT DEFAULT 0,
    rejected_count BIGINT DEFAULT 0,
    unsupported_count BIGINT DEFAULT 0,
    provenance_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_captures_content_sha256 ON captures(content_sha256);

-- 2. Analysis Jobs
CREATE TABLE IF NOT EXISTS analysis_jobs (
    job_id VARCHAR(256) PRIMARY KEY,
    capture_id VARCHAR(256) REFERENCES captures(capture_id) ON DELETE SET NULL,
    filename TEXT NOT NULL,
    file_size_bytes BIGINT NOT NULL,
    status VARCHAR(32) NOT NULL,
    created_at TEXT NOT NULL,
    completed_at TEXT,
    error_message TEXT,
    summary_json TEXT,
    engine_version VARCHAR(32) DEFAULT '1.0.0',
    pipeline_version VARCHAR(32) DEFAULT '1.0.0',
    schema_version VARCHAR(32) DEFAULT '1.0.0',
    reconciliation_json TEXT,
    events_path TEXT,
    quarantine_path TEXT,
    report_path TEXT
);
CREATE INDEX IF NOT EXISTS idx_analysis_jobs_capture_id ON analysis_jobs(capture_id);

-- 3. Assets
CREATE TABLE IF NOT EXISTS assets (
    asset_id VARCHAR(256) PRIMARY KEY,
    primary_ip VARCHAR(256) NOT NULL,
    ip_addresses_json TEXT NOT NULL,
    mac_addresses_json TEXT NOT NULL,
    hostnames_json TEXT NOT NULL,
    observed_protocols_json TEXT NOT NULL,
    observed_services_json TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    identity_status VARCHAR(32) NOT NULL,
    confidence DOUBLE PRECISION NOT NULL,
    conflicts_json TEXT NOT NULL,
    observation_sources_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_assets_primary_ip ON assets(primary_ip);

-- 4. Network Segments
CREATE TABLE IF NOT EXISTS network_segments (
    segment_id VARCHAR(256) PRIMARY KEY,
    cidr_prefix VARCHAR(256) NOT NULL UNIQUE,
    address_family VARCHAR(16) NOT NULL,
    gateway_ip VARCHAR(256),
    observed_host_count INTEGER NOT NULL,
    configuration_source TEXT,
    confidence DOUBLE PRECISION NOT NULL,
    provenance TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
);

-- 5. Services
CREATE TABLE IF NOT EXISTS services (
    service_id VARCHAR(256) PRIMARY KEY,
    asset_id VARCHAR(256) NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
    server_ip VARCHAR(256) NOT NULL,
    transport_protocol VARCHAR(16) NOT NULL,
    port INTEGER NOT NULL,
    app_protocol VARCHAR(32) NOT NULL,
    classification_confidence DOUBLE PRECISION NOT NULL,
    tls_sni TEXT,
    tls_alpn_json TEXT,
    http_server TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_services_server_port ON services(server_ip, port, transport_protocol);

-- 6. Evidence Records
CREATE TABLE IF NOT EXISTS evidence_records (
    evidence_id VARCHAR(256) PRIMARY KEY,
    evidence_type VARCHAR(256) NOT NULL,
    source_type VARCHAR(256) NOT NULL,
    source_artifact_id VARCHAR(256) NOT NULL,
    observation_timestamp TEXT,
    ingestion_timestamp TEXT NOT NULL,
    src_ref TEXT,
    dst_ref TEXT,
    parser_status VARCHAR(256) NOT NULL,
    confidence DOUBLE PRECISION NOT NULL,
    provenance TEXT NOT NULL,
    details_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_evidence_artifact ON evidence_records(source_artifact_id);

-- 7. Communication Relationships
CREATE TABLE IF NOT EXISTS communication_relationships (
    relationship_id VARCHAR(256) PRIMARY KEY,
    src_asset_id VARCHAR(256) NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
    dst_asset_id VARCHAR(256) NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
    transport_protocol VARCHAR(16) NOT NULL,
    src_port INTEGER,
    dst_port INTEGER,
    app_protocol VARCHAR(32) NOT NULL,
    packet_count BIGINT NOT NULL,
    byte_count BIGINT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    flow_ids_json TEXT NOT NULL,
    dns_transaction_ids_json TEXT NOT NULL,
    evidence_type VARCHAR(256) NOT NULL,
    directionality VARCHAR(32) NOT NULL,
    confidence DOUBLE PRECISION NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_comm_src_dst ON communication_relationships(src_asset_id, dst_asset_id);

-- 8. Topology Snapshots
CREATE TABLE IF NOT EXISTS topology_snapshots (
    snapshot_id VARCHAR(256) PRIMARY KEY,
    name TEXT NOT NULL,
    created_at TEXT NOT NULL,
    source_captures_json TEXT NOT NULL,
    source_configs_json TEXT NOT NULL,
    identity_policy_version VARCHAR(32) NOT NULL,
    graph_algorithm_version VARCHAR(32) NOT NULL,
    node_count INTEGER NOT NULL,
    edge_count INTEGER NOT NULL,
    unresolved_conflicts_json TEXT NOT NULL,
    schema_version VARCHAR(32) NOT NULL,
    metadata_json TEXT NOT NULL
);

-- 9. Snapshot Nodes
CREATE TABLE IF NOT EXISTS snapshot_nodes (
    snapshot_id VARCHAR(256) NOT NULL REFERENCES topology_snapshots(snapshot_id) ON DELETE CASCADE,
    node_id VARCHAR(256) NOT NULL,
    node_type VARCHAR(32) NOT NULL,
    label TEXT NOT NULL,
    asset_id VARCHAR(256),
    segment_id VARCHAR(256),
    properties_json TEXT NOT NULL,
    PRIMARY KEY (snapshot_id, node_id)
);

-- 10. Snapshot Edges
CREATE TABLE IF NOT EXISTS snapshot_edges (
    snapshot_id VARCHAR(256) NOT NULL REFERENCES topology_snapshots(snapshot_id) ON DELETE CASCADE,
    edge_id VARCHAR(128) NOT NULL,
    source_node_id VARCHAR(256) NOT NULL,
    target_node_id VARCHAR(256) NOT NULL,
    edge_type VARCHAR(256) NOT NULL,
    evidence_class VARCHAR(256) NOT NULL,
    primary_protocol VARCHAR(32) NOT NULL,
    packet_count BIGINT NOT NULL,
    byte_count BIGINT NOT NULL,
    confidence DOUBLE PRECISION NOT NULL,
    evidence_ids_json TEXT NOT NULL,
    properties_json TEXT NOT NULL,
    PRIMARY KEY (snapshot_id, edge_id)
);

-- 11. Configuration Imports
CREATE TABLE IF NOT EXISTS imported_configurations (
    import_id VARCHAR(256) PRIMARY KEY,
    format VARCHAR(32) NOT NULL,
    source_name TEXT NOT NULL,
    status VARCHAR(32) NOT NULL,
    items_imported INTEGER NOT NULL,
    errors_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    evidence_ids_json TEXT NOT NULL
);

-- 12. Network Models
CREATE TABLE IF NOT EXISTS network_models (
    model_id VARCHAR(256) PRIMARY KEY,
    name TEXT NOT NULL,
    source_snapshot_id VARCHAR(256) NOT NULL REFERENCES topology_snapshots(snapshot_id) ON DELETE CASCADE,
    source_snapshot_fingerprint VARCHAR(256) NOT NULL,
    schema_version VARCHAR(32) NOT NULL,
    model_version INTEGER NOT NULL,
    fingerprint VARCHAR(256) NOT NULL,
    created_at TEXT NOT NULL,
    is_counterfactual INTEGER NOT NULL DEFAULT 0,
    parent_model_id VARCHAR(256),
    model_json TEXT NOT NULL
);

-- 13. Simulation Scenarios
CREATE TABLE IF NOT EXISTS simulation_scenarios (
    scenario_id VARCHAR(256) PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    base_model_id VARCHAR(256) NOT NULL REFERENCES network_models(model_id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    scenario_json TEXT NOT NULL
);

-- 14. Counterfactual Results
CREATE TABLE IF NOT EXISTS counterfactual_results (
    run_id VARCHAR(256) PRIMARY KEY,
    scenario_id VARCHAR(256) NOT NULL,
    base_model_id VARCHAR(256) NOT NULL,
    baseline_fingerprint VARCHAR(256) NOT NULL,
    counterfactual_model_id VARCHAR(256) NOT NULL,
    counterfactual_fingerprint VARCHAR(256) NOT NULL,
    applied_actions_count INTEGER NOT NULL,
    newly_reachable_count INTEGER NOT NULL,
    newly_blocked_count INTEGER NOT NULL,
    invariant_regressions_count INTEGER NOT NULL,
    executed_at TEXT NOT NULL,
    result_json TEXT NOT NULL
);

-- 15. Security Invariants
CREATE TABLE IF NOT EXISTS security_invariants (
    invariant_id VARCHAR(256) PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    invariant_type VARCHAR(256) NOT NULL,
    severity VARCHAR(32) NOT NULL,
    scope VARCHAR(256) NOT NULL,
    version VARCHAR(32) NOT NULL,
    created_at TEXT NOT NULL,
    definition_json TEXT NOT NULL
);

-- 16. Verification Runs
CREATE TABLE IF NOT EXISTS verification_runs (
    run_id VARCHAR(256) PRIMARY KEY,
    model_id VARCHAR(256) NOT NULL,
    scenario_id VARCHAR(256),
    evaluated_at TEXT NOT NULL,
    pass_count INTEGER NOT NULL,
    fail_count INTEGER NOT NULL,
    indeterminate_count INTEGER NOT NULL,
    summary_json TEXT NOT NULL,
    results_json TEXT NOT NULL
);

-- 17. Test Campaigns
CREATE TABLE IF NOT EXISTS test_campaigns (
    campaign_id VARCHAR(256) PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    protocol_targets_json TEXT NOT NULL,
    strategies_json TEXT NOT NULL,
    seed BIGINT NOT NULL,
    max_cases_per_target INTEGER NOT NULL,
    total_cases INTEGER NOT NULL,
    status VARCHAR(32) NOT NULL,
    created_at TEXT NOT NULL,
    completed_at TEXT,
    cases_generated INTEGER NOT NULL DEFAULT 0,
    cases_executed INTEGER NOT NULL DEFAULT 0,
    passed_count INTEGER NOT NULL DEFAULT 0,
    rejected_count INTEGER NOT NULL DEFAULT 0,
    failed_count INTEGER NOT NULL DEFAULT 0,
    findings_count INTEGER NOT NULL DEFAULT 0,
    duration_ms DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    engine_version VARCHAR(32) NOT NULL
);

-- 18. Test Cases
CREATE TABLE IF NOT EXISTS test_cases (
    case_id VARCHAR(256) PRIMARY KEY,
    campaign_id VARCHAR(256) NOT NULL REFERENCES test_campaigns(campaign_id) ON DELETE CASCADE,
    test_index INTEGER NOT NULL,
    protocol_target VARCHAR(32) NOT NULL,
    generation_strategy VARCHAR(256) NOT NULL,
    mutation_sequence_json TEXT NOT NULL,
    seed BIGINT NOT NULL,
    generator_version VARCHAR(32) NOT NULL,
    fixture_format VARCHAR(32) NOT NULL,
    fixture_path TEXT NOT NULL,
    fixture_hash VARCHAR(256) NOT NULL,
    expected_behavior TEXT NOT NULL,
    status VARCHAR(32) NOT NULL,
    created_at TEXT NOT NULL
);

-- 19. Execution Results
CREATE TABLE IF NOT EXISTS execution_results (
    result_id VARCHAR(256) PRIMARY KEY,
    case_id VARCHAR(256) NOT NULL REFERENCES test_cases(case_id) ON DELETE CASCADE,
    exit_code INTEGER NOT NULL,
    stdout TEXT NOT NULL,
    stderr TEXT NOT NULL,
    execution_time_ms DOUBLE PRECISION NOT NULL,
    parser_status VARCHAR(256) NOT NULL,
    parsed_event_count INTEGER NOT NULL,
    schema_valid INTEGER NOT NULL,
    schema_errors_json TEXT NOT NULL,
    anomalies_json TEXT NOT NULL,
    sanitizer_triggered INTEGER NOT NULL,
    crash_detected INTEGER NOT NULL,
    passed INTEGER NOT NULL,
    diagnostic TEXT,
    executed_at TEXT NOT NULL
);

-- 20. Test Findings
CREATE TABLE IF NOT EXISTS test_findings (
    finding_id VARCHAR(256) PRIMARY KEY,
    campaign_id VARCHAR(256) NOT NULL REFERENCES test_campaigns(campaign_id) ON DELETE CASCADE,
    case_id VARCHAR(256) NOT NULL REFERENCES test_cases(case_id) ON DELETE CASCADE,
    protocol_target VARCHAR(32) NOT NULL,
    parser_component VARCHAR(256) NOT NULL,
    severity VARCHAR(32) NOT NULL,
    confidence VARCHAR(32) NOT NULL,
    failure_category VARCHAR(256) NOT NULL,
    input_hash VARCHAR(256) NOT NULL,
    engine_version VARCHAR(32) NOT NULL,
    reproduction_command TEXT NOT NULL,
    seed BIGINT NOT NULL,
    mutation_sequence_json TEXT NOT NULL,
    expected_behavior TEXT NOT NULL,
    actual_behavior TEXT NOT NULL,
    diagnostic TEXT NOT NULL,
    status VARCHAR(32) NOT NULL,
    regression_fixture_id VARCHAR(256),
    created_at TEXT NOT NULL
);

-- 21. Regression Fixtures
CREATE TABLE IF NOT EXISTS regression_fixtures (
    fixture_id VARCHAR(256) PRIMARY KEY,
    finding_id VARCHAR(256) NOT NULL,
    name TEXT NOT NULL,
    protocol_target VARCHAR(32) NOT NULL,
    failure_category VARCHAR(256) NOT NULL,
    fixture_path TEXT NOT NULL,
    fixture_hash VARCHAR(256) NOT NULL,
    engine_baseline_version VARCHAR(32) NOT NULL,
    expected_behavior TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_run_at TEXT,
    last_run_passed INTEGER,
    last_run_exit_code INTEGER,
    last_run_diagnostic TEXT
);

-- 22. Protocol Sequences
CREATE TABLE IF NOT EXISTS protocol_sequences (
    sequence_id VARCHAR(256) PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    sequence_type VARCHAR(256) NOT NULL,
    seed BIGINT NOT NULL,
    generator_version VARCHAR(32) NOT NULL,
    steps_json TEXT NOT NULL,
    expected_transitions_json TEXT NOT NULL,
    expected_flow_count INTEGER NOT NULL,
    expected_properties_json TEXT NOT NULL,
    mutations_json TEXT NOT NULL,
    format VARCHAR(32) NOT NULL,
    fixture_path TEXT,
    fixture_hash VARCHAR(256),
    is_supported INTEGER NOT NULL,
    coverage_gap_notes TEXT,
    created_at TEXT NOT NULL
);

-- 23. Sequence Findings
CREATE TABLE IF NOT EXISTS sequence_findings (
    finding_id VARCHAR(256) PRIMARY KEY,
    sequence_id VARCHAR(256) NOT NULL REFERENCES protocol_sequences(sequence_id) ON DELETE CASCADE,
    severity VARCHAR(32) NOT NULL,
    category VARCHAR(256) NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    root_cause_summary TEXT NOT NULL,
    reproduction_command TEXT NOT NULL,
    fixture_path TEXT NOT NULL,
    fixture_hash VARCHAR(256) NOT NULL,
    minimized INTEGER NOT NULL,
    minimized_sequence_id VARCHAR(256),
    is_regression INTEGER NOT NULL,
    created_at TEXT NOT NULL
);

-- 24. Sequence Regressions
CREATE TABLE IF NOT EXISTS sequence_regressions (
    regression_id VARCHAR(256) PRIMARY KEY,
    finding_id VARCHAR(256) NOT NULL,
    name TEXT NOT NULL,
    sequence_type VARCHAR(256) NOT NULL,
    fixture_path TEXT NOT NULL,
    fixture_hash VARCHAR(256) NOT NULL,
    expected_exit_code INTEGER NOT NULL,
    expected_to_pass INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    last_run_at TEXT,
    last_run_passed INTEGER
);

-- 25. Predictive Datasets
CREATE TABLE IF NOT EXISTS predictive_datasets (
    dataset_id VARCHAR(256) PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    pipeline_version VARCHAR(32) NOT NULL,
    time_window_sec DOUBLE PRECISION NOT NULL,
    total_samples INTEGER NOT NULL,
    feature_count INTEGER NOT NULL,
    target_type VARCHAR(256) NOT NULL,
    hash_sha256 VARCHAR(256) NOT NULL,
    created_at TEXT NOT NULL,
    manifest_json TEXT NOT NULL
);

-- 26. Model Artifacts
CREATE TABLE IF NOT EXISTS model_artifacts (
    model_id VARCHAR(256) PRIMARY KEY,
    name TEXT NOT NULL,
    version VARCHAR(32) NOT NULL,
    target VARCHAR(256) NOT NULL,
    algorithm VARCHAR(256) NOT NULL,
    dataset_id VARCHAR(256) NOT NULL REFERENCES predictive_datasets(dataset_id) ON DELETE CASCADE,
    artifact_path TEXT NOT NULL,
    artifact_hash_sha256 VARCHAR(256) NOT NULL,
    created_at TEXT NOT NULL,
    artifact_json TEXT NOT NULL
);

-- 27. Prediction Records
CREATE TABLE IF NOT EXISTS prediction_records (
    prediction_id VARCHAR(256) PRIMARY KEY,
    model_id VARCHAR(256) NOT NULL REFERENCES model_artifacts(model_id) ON DELETE CASCADE,
    target VARCHAR(256) NOT NULL,
    predicted_value DOUBLE PRECISION NOT NULL,
    predicted_at TEXT NOT NULL,
    result_json TEXT NOT NULL
);

-- 28. Benchmark Runs
CREATE TABLE IF NOT EXISTS benchmark_runs (
    run_id VARCHAR(256) PRIMARY KEY,
    fixture_id VARCHAR(256) NOT NULL,
    fixture_name TEXT NOT NULL,
    provenance VARCHAR(256) NOT NULL,
    category VARCHAR(256) NOT NULL,
    fixture_sha256 VARCHAR(256) NOT NULL,
    git_commit VARCHAR(256) NOT NULL,
    software_version VARCHAR(32) NOT NULL,
    executed_at TEXT NOT NULL,
    status VARCHAR(32) NOT NULL,
    decoding_metrics_json TEXT NOT NULL,
    deterministic_metrics_json TEXT NOT NULL,
    predictive_metrics_json TEXT,
    consensus_metrics_json TEXT,
    operational_profile_json TEXT NOT NULL,
    limitations_json TEXT NOT NULL
);

-- 29. Benchmark Metrics
CREATE TABLE IF NOT EXISTS benchmark_metrics (
    metric_id VARCHAR(256) PRIMARY KEY,
    run_id VARCHAR(256) NOT NULL REFERENCES benchmark_runs(run_id) ON DELETE CASCADE,
    metric_name VARCHAR(256) NOT NULL,
    metric_value DOUBLE PRECISION NOT NULL,
    sample_count INTEGER,
    created_at TEXT NOT NULL
);

-- 30. Investigation Cases
CREATE TABLE IF NOT EXISTS investigation_cases (
    investigation_id VARCHAR(256) PRIMARY KEY,
    title TEXT NOT NULL,
    investigation_type VARCHAR(256) NOT NULL,
    scope_json TEXT NOT NULL,
    status VARCHAR(32) NOT NULL,
    sufficiency VARCHAR(32) NOT NULL,
    created_at_iso TEXT NOT NULL,
    updated_at_iso TEXT NOT NULL,
    evidence_graph_json TEXT NOT NULL,
    candidate_explanations_json TEXT NOT NULL,
    primary_root_cause_id VARCHAR(256),
    counterfactual_comparisons_json TEXT NOT NULL,
    unresolved_questions_json TEXT NOT NULL,
    explicit_limitations_json TEXT NOT NULL,
    reproduction_steps_json TEXT NOT NULL
);

-- 31. Investigation Executions
CREATE TABLE IF NOT EXISTS investigation_executions (
    execution_id VARCHAR(256) PRIMARY KEY,
    investigation_id VARCHAR(256) NOT NULL,
    execution_index INTEGER NOT NULL,
    investigation_type VARCHAR(256) NOT NULL,
    engine_version VARCHAR(32) NOT NULL,
    rule_version VARCHAR(32) NOT NULL,
    started_at_iso TEXT NOT NULL,
    completed_at_iso TEXT NOT NULL,
    execution_duration_ms DOUBLE PRECISION NOT NULL,
    status VARCHAR(32) NOT NULL,
    replay_of_execution_id VARCHAR(256),
    model_id VARCHAR(256),
    model_fingerprint VARCHAR(256),
    overall_evidence_digest VARCHAR(256) NOT NULL,
    sufficiency VARCHAR(32) NOT NULL,
    primary_root_cause_id VARCHAR(256),
    execution_record_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_inv_exec_investigation_id ON investigation_executions(investigation_id);
CREATE INDEX IF NOT EXISTS idx_inv_exec_replay_of ON investigation_executions(replay_of_execution_id);
"""
