/**
 * TypeScript contracts for Phase 03 Executable Network Digital Twin,
 * Deterministic Reachability, Security Verification, and Counterfactual Simulation.
 */

export type ModelNodeType = 'HOST' | 'ROUTER' | 'SWITCH' | 'FIREWALL' | 'SUBNET' | 'SERVICE';
export type AdministrativeState = 'UP' | 'DOWN' | 'TESTING' | 'UNKNOWN';
export type RouteType = 'CONNECTED' | 'STATIC' | 'OSPF' | 'BGP' | 'CONFIGURED' | 'INFERRED';
export type RouteStatus = 'ACTIVE' | 'INACTIVE' | 'WITHDRAWN' | 'STALE';
export type RuleAction = 'PERMIT' | 'DENY' | 'LOG' | 'REJECT';
export type RuleDirection = 'INGRESS' | 'EGRESS' | 'BOTH';
export type DefaultPolicy = 'DEFAULT_DENY' | 'DEFAULT_ALLOW';
export type TransportProtocolConstraint = 'ANY' | 'TCP' | 'UDP' | 'ICMP' | 'ICMPV6';
export type ReachabilityStatus = 'REACHABLE' | 'BLOCKED' | 'INDETERMINATE';

export type InvariantType =
  | 'ISOLATION'
  | 'REQUIRED_REACHABILITY'
  | 'PORT_RESTRICTION'
  | 'MANAGEMENT_PLANE_ISOLATION'
  | 'PATH_CONSTRAINTS'
  | 'FORBIDDEN_EXPOSURE'
  | 'CONFIGURATION_CONSISTENCY';

export type InvariantSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';
export type InvariantStatus = 'PASS' | 'FAIL' | 'INDETERMINATE' | 'NOT_APPLICABLE';

export type SimulationActionType =
  | 'ADD_ROUTE'
  | 'REMOVE_ROUTE'
  | 'MODIFY_ROUTE'
  | 'ADD_FIREWALL_RULE'
  | 'REMOVE_FIREWALL_RULE'
  | 'MODIFY_FIREWALL_RULE'
  | 'TOGGLE_INTERFACE_STATE'
  | 'CREATE_ZONE'
  | 'ASSIGN_NODE_TO_ZONE';

export interface IPAddressAssignment {
  ip_address: string;
  prefix_length: number;
  is_primary?: boolean;
  is_inferred?: boolean;
}

export interface ModelInterface {
  interface_id: string;
  node_id: string;
  name: string;
  mac_address?: string | null;
  ip_assignments: IPAddressAssignment[];
  state: AdministrativeState;
  is_inferred?: boolean;
}

export interface RouteEntry {
  route_id: string;
  node_id: string;
  destination_prefix: string;
  prefix_length: number;
  next_hop_ip?: string | null;
  output_interface_id?: string | null;
  metric: number;
  admin_distance: number;
  route_type: RouteType;
  status: RouteStatus;
  source_evidence_ids?: string[];
  is_inferred?: boolean;
}

export interface FirewallRule {
  rule_id: string;
  node_id: string;
  rule_number: number;
  name?: string;
  action: RuleAction;
  direction: RuleDirection;
  source_zone?: string | null;
  source_prefix?: string | null;
  destination_zone?: string | null;
  destination_prefix?: string | null;
  protocol: TransportProtocolConstraint;
  source_port?: number | null;
  destination_port?: number | null;
  statefulness?: string;
  description?: string;
  is_inferred?: boolean;
}

export interface AccessControlList {
  acl_id: string;
  node_id: string;
  name: string;
  rules: FirewallRule[];
  default_policy: DefaultPolicy;
}

export interface ModelNode {
  node_id: string;
  label: string;
  node_type: ModelNodeType;
  interfaces: ModelInterface[];
  routing_table: RouteEntry[];
  acls: AccessControlList[];
  default_gateway_ip?: string | null;
  zone_id?: string | null;
  is_inferred?: boolean;
  metadata?: Record<string, any>;
}

export interface NetworkZone {
  zone_id: string;
  name: string;
  description?: string;
  assigned_node_ids: string[];
  assigned_interface_ids: string[];
  assigned_subnets: string[];
  security_level: number;
}

export interface ModelLimitation {
  limitation_code: string;
  description: string;
  affected_entities: string[];
  impact: string;
}

export interface NetworkModel {
  model_id: string;
  name: string;
  source_snapshot_id: string;
  source_snapshot_fingerprint: string;
  schema_version: string;
  model_version: number;
  created_at_iso: string;
  fingerprint: string;
  nodes: Record<string, ModelNode>;
  zones: Record<string, NetworkZone>;
  source_evidence_refs: string[];
  imported_config_refs: string[];
  known_limitations: ModelLimitation[];
  is_counterfactual: boolean;
  parent_model_id?: string | null;
}

export interface PathHop {
  hop_index: number;
  node_id: string;
  node_label: string;
  ingress_interface?: string | null;
  egress_interface?: string | null;
  routed_destination_prefix?: string | null;
  next_hop_ip?: string | null;
  matched_firewall_rule?: string | null;
  notes?: string;
}

export interface BlockingRule {
  node_id: string;
  node_label: string;
  rule_id?: string | null;
  rule_number?: number | null;
  rule_action: RuleAction;
  direction: RuleDirection;
  reason_code: string;
  explanation: string;
}

export interface ReachabilityQuery {
  model_id?: string;
  source_ip: string;
  destination_ip: string;
  protocol?: TransportProtocolConstraint;
  destination_port?: number | null;
  source_port?: number | null;
  flags?: string[];
}

export interface ReachabilityResult {
  query_id: string;
  model_id: string;
  model_fingerprint: string;
  source_ip: string;
  destination_ip: string;
  protocol: TransportProtocolConstraint;
  destination_port?: number | null;
  status: ReachabilityStatus;
  reason_code: string;
  path: PathHop[];
  blocking_rule?: BlockingRule | null;
  evaluated_policy_count: number;
  route_decisions_count: number;
  limitations?: string[];
  explanation: string;
  evidence_ids: string[];
}

export interface InvariantDefinition {
  source_zone_or_cidr?: string | null;
  destination_zone_or_cidr?: string | null;
  service_ip?: string | null;
  service_port?: number | null;
  allowed_ports?: number[];
  protected_zone?: string | null;
  management_interface_id?: string | null;
  authorized_source_cidrs?: string[];
  required_traversal_nodes?: string[];
  forbidden_target_zones?: string[];
}

export interface SecurityInvariant {
  invariant_id: string;
  name: string;
  description?: string;
  invariant_type: InvariantType;
  severity: InvariantSeverity;
  definition: InvariantDefinition;
  created_at_iso?: string;
}

export interface VerificationResult {
  result_id: string;
  invariant_id: string;
  invariant_name: string;
  invariant_type: InvariantType;
  severity: InvariantSeverity;
  status: InvariantStatus;
  reason_code: string;
  explanation: string;
  witness_path?: PathHop[] | null;
  blocking_rule?: BlockingRule | null;
  evaluated_at_iso?: string;
  model_id: string;
  model_fingerprint: string;
  limitations?: string[];
  evidence_ids?: string[];
}

export interface SimulationAction {
  action_type: SimulationActionType;
  target_node_id: string;
  parameters: Record<string, any>;
  comment?: string;
}

export interface SimulationScenario {
  scenario_id: string;
  name: string;
  description?: string;
  base_model_id: string;
  actions: SimulationAction[];
  created_at_iso?: string;
}

export interface PathDifference {
  source_ip: string;
  destination_ip: string;
  protocol: TransportProtocolConstraint;
  destination_port?: number | null;
  baseline_status: ReachabilityStatus;
  counterfactual_status: ReachabilityStatus;
  change_type: string;
  explanation: string;
}

export interface InvariantDifference {
  invariant_id: string;
  invariant_name: string;
  severity: InvariantSeverity;
  baseline_status: InvariantStatus;
  counterfactual_status: InvariantStatus;
  explanation: string;
}

export interface CounterfactualResult {
  result_id: string;
  run_id?: string;
  scenario_id: string;
  scenario_name?: string;
  base_model_id: string;
  baseline_fingerprint: string;
  counterfactual_model_id: string;
  counterfactual_fingerprint: string;
  applied_actions_count: number;
  path_differences: PathDifference[];
  reachability_diffs?: PathDifference[];
  invariant_differences: InvariantDifference[];
  invariant_diffs?: InvariantDifference[];
  newly_reachable_paths_count: number;
  newly_reachable_count?: number;
  newly_blocked_paths_count: number;
  newly_blocked_count?: number;
  security_regressions_count: number;
  invariant_regressions_count?: number;
  summary_explanation: string;
  created_at_iso: string;
  executed_at_iso?: string;
}

export interface BuildModelRequest {
  snapshot_id: string;
  name?: string;
  custom_routes?: Array<Record<string, any>>;
  custom_acls?: Array<Record<string, any>>;
  custom_zones?: Array<Record<string, any>>;
}

export interface RunScenarioRequest {
  test_queries?: ReachabilityQuery[];
}

export interface RunVerificationRequest {
  model_id: string;
  invariant_ids?: string[];
}
