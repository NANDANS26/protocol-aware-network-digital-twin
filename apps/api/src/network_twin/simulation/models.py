"""Strongly typed formal network state, forwarding, simulation, and verification models."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field


class AdministrativeState(StrEnum):
    UP = "UP"
    DOWN = "DOWN"


class RouteType(StrEnum):
    CONNECTED = "CONNECTED"
    STATIC = "STATIC"
    CONFIGURED = "CONFIGURED"
    INFERRED = "INFERRED"


class RouteStatus(StrEnum):
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"


class RuleAction(StrEnum):
    PERMIT = "PERMIT"
    DENY = "DENY"


class RuleDirection(StrEnum):
    INGRESS = "INGRESS"
    EGRESS = "EGRESS"
    BOTH = "BOTH"


class TransportProtocolConstraint(StrEnum):
    ANY = "ANY"
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"


class FilterStatefulness(StrEnum):
    STATELESS = "STATELESS"
    STATEFUL = "STATEFUL"


class DefaultPolicy(StrEnum):
    DEFAULT_DENY = "DEFAULT_DENY"
    DEFAULT_ALLOW = "DEFAULT_ALLOW"


class ReachabilityStatus(StrEnum):
    REACHABLE = "REACHABLE"
    BLOCKED = "BLOCKED"
    INDETERMINATE = "INDETERMINATE"
    INSUFFICIENT_MODEL = "INSUFFICIENT_MODEL"


class InvariantType(StrEnum):
    ISOLATION = "ISOLATION"
    REQUIRED_REACHABILITY = "REQUIRED_REACHABILITY"
    PORT_RESTRICTION = "PORT_RESTRICTION"
    MANAGEMENT_PLANE_ISOLATION = "MANAGEMENT_PLANE_ISOLATION"
    PATH_CONSTRAINTS = "PATH_CONSTRAINTS"
    FORBIDDEN_EXPOSURE = "FORBIDDEN_EXPOSURE"
    CONFIGURATION_CONSISTENCY = "CONFIGURATION_CONSISTENCY"


class InvariantSeverity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class InvariantStatus(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    INDETERMINATE = "INDETERMINATE"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class SimulationActionType(StrEnum):
    ADD_ROUTE = "ADD_ROUTE"
    REMOVE_ROUTE = "REMOVE_ROUTE"
    MODIFY_ROUTE = "MODIFY_ROUTE"
    ADD_FIREWALL_RULE = "ADD_FIREWALL_RULE"
    REMOVE_FIREWALL_RULE = "REMOVE_FIREWALL_RULE"
    MODIFY_FIREWALL_RULE = "MODIFY_FIREWALL_RULE"
    REORDER_FIREWALL_RULES = "REORDER_FIREWALL_RULES"
    MODIFY_INTERFACE_IP = "MODIFY_INTERFACE_IP"
    SET_INTERFACE_STATE = "SET_INTERFACE_STATE"
    SET_ZONE_ASSIGNMENT = "SET_ZONE_ASSIGNMENT"


class ReasonCode(StrEnum):
    REACHABLE = "REACHABLE"
    NO_ROUTE_TO_HOST = "NO_ROUTE_TO_HOST"
    UNRESOLVED_NEXT_HOP = "UNRESOLVED_NEXT_HOP"
    DROPPED_BY_FIREWALL = "DROPPED_BY_FIREWALL"
    DROPPED_BY_DEFAULT_POLICY = "DROPPED_BY_DEFAULT_POLICY"
    FORWARDING_LOOP_DETECTED = "FORWARDING_LOOP_DETECTED"
    HOP_LIMIT_EXCEEDED = "HOP_LIMIT_EXCEEDED"
    INTERFACE_DOWN = "INTERFACE_DOWN"
    DESTINATION_UNKNOWN = "DESTINATION_UNKNOWN"
    SOURCE_UNKNOWN = "SOURCE_UNKNOWN"
    INSUFFICIENT_FORWARDING_STATE = "INSUFFICIENT_FORWARDING_STATE"
    CONTRADICTORY_ROUTING = "CONTRADICTORY_ROUTING"
    UNRESOLVED_POLICY_TARGET = "UNRESOLVED_POLICY_TARGET"


# --- Interface & IP Assignment ---


class IPAddressAssignment(BaseModel):
    ip_address: str
    prefix_length: int = Field(ge=0, le=128)
    is_primary: bool = True
    is_inferred: bool = False


class ModelInterface(BaseModel):
    interface_id: str
    node_id: str
    name: str
    mac_address: str | None = None
    ip_assignments: list[IPAddressAssignment] = Field(default_factory=list)
    zone_id: str | None = None
    state: AdministrativeState = AdministrativeState.UP
    mtu: int = 1500
    is_inferred: bool = False


# --- Routing & Policies ---


class RouteEntry(BaseModel):
    route_id: str
    node_id: str
    destination_prefix: str  # CIDR e.g. "10.0.1.0/24"
    prefix_length: int = Field(ge=0, le=128)
    next_hop_ip: str | None = None
    output_interface_id: str | None = None
    metric: int = Field(default=1, ge=0)
    admin_distance: int = Field(default=1, ge=0)
    route_type: RouteType = RouteType.STATIC
    status: RouteStatus = RouteStatus.ACTIVE
    source_evidence_ids: list[str] = Field(default_factory=list)
    is_inferred: bool = False


class FirewallRule(BaseModel):
    rule_id: str
    node_id: str
    rule_number: int = Field(ge=1)
    name: str = ""
    action: RuleAction = RuleAction.DENY
    direction: RuleDirection = RuleDirection.INGRESS
    source_zone: str | None = None
    source_prefix: str | None = None  # None means ANY
    destination_zone: str | None = None
    destination_prefix: str | None = None  # None means ANY
    protocol: TransportProtocolConstraint = TransportProtocolConstraint.ANY
    source_port: int | None = None  # None means ANY
    destination_port: int | None = None  # None means ANY
    statefulness: FilterStatefulness = FilterStatefulness.STATELESS
    description: str = ""
    source_evidence_ids: list[str] = Field(default_factory=list)
    is_inferred: bool = False


class AccessControlList(BaseModel):
    acl_id: str
    node_id: str
    name: str
    rules: list[FirewallRule] = Field(default_factory=list)
    default_policy: DefaultPolicy = DefaultPolicy.DEFAULT_DENY


class NetworkZone(BaseModel):
    zone_id: str
    name: str
    description: str = ""
    assigned_node_ids: list[str] = Field(default_factory=list)
    assigned_interface_ids: list[str] = Field(default_factory=list)
    assigned_subnets: list[str] = Field(default_factory=list)
    security_level: int = Field(default=50, ge=0, le=100)


# --- Node in Model ---


class ModelNodeType(StrEnum):
    HOST = "HOST"
    ROUTER = "ROUTER"
    SWITCH = "SWITCH"
    FIREWALL = "FIREWALL"
    SUBNET = "SUBNET"
    SERVICE = "SERVICE"


class ModelNode(BaseModel):
    node_id: str
    label: str
    node_type: ModelNodeType
    interfaces: list[ModelInterface] = Field(default_factory=list)
    routing_table: list[RouteEntry] = Field(default_factory=list)
    acls: list[AccessControlList] = Field(default_factory=list)
    default_gateway_ip: str | None = None
    zone_id: str | None = None
    is_inferred: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


# --- Model Limitations & Traceability ---


class ModelLimitation(BaseModel):
    limitation_code: str
    description: str
    affected_entities: list[str] = Field(default_factory=list)
    impact: str = "May result in INDETERMINATE reachability evaluation"


class NetworkModel(BaseModel):
    model_id: str
    name: str
    source_snapshot_id: str
    source_snapshot_fingerprint: str
    schema_version: str = "1.0.0"
    model_version: int = 1
    created_at_iso: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    fingerprint: str = ""  # SHA-256 of canonical state
    nodes: dict[str, ModelNode] = Field(default_factory=dict)
    zones: dict[str, NetworkZone] = Field(default_factory=dict)
    source_evidence_refs: list[str] = Field(default_factory=list)
    imported_config_refs: list[str] = Field(default_factory=list)
    known_limitations: list[ModelLimitation] = Field(default_factory=list)
    is_counterfactual: bool = False
    parent_model_id: str | None = None


# --- Path & Query Representation ---


class PathHop(BaseModel):
    hop_index: int
    node_id: str
    node_label: str
    ingress_interface: str | None = None
    egress_interface: str | None = None
    routed_destination_prefix: str | None = None
    next_hop_ip: str | None = None
    matched_rule_id: str | None = None
    rule_action_applied: RuleAction | None = None
    notes: str = ""


class BlockingRule(BaseModel):
    node_id: str
    node_label: str
    rule_id: str | None = None
    rule_number: int | None = None
    rule_action: RuleAction = RuleAction.DENY
    direction: RuleDirection = RuleDirection.INGRESS
    reason_code: ReasonCode = ReasonCode.DROPPED_BY_FIREWALL
    explanation: str = ""


class ReachabilityQuery(BaseModel):
    source_ip: str
    destination_ip: str
    protocol: TransportProtocolConstraint = TransportProtocolConstraint.TCP
    source_port: int | None = None
    destination_port: int | None = None
    model_id: str | None = None
    scenario_id: str | None = None


class ReachabilityResult(BaseModel):
    query_id: str
    model_id: str
    model_fingerprint: str
    source_ip: str
    destination_ip: str
    protocol: TransportProtocolConstraint
    destination_port: int | None = None
    status: ReachabilityStatus
    reason_code: ReasonCode
    path: list[PathHop] = Field(default_factory=list)
    blocking_rule: BlockingRule | None = None
    evaluated_policy_count: int = 0
    route_decisions_count: int = 0
    explanation: str
    evidence_ids: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    executed_at_iso: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())


# --- Security Invariants ---


class InvariantDefinition(BaseModel):
    # Depending on invariant_type:
    source_zone_or_cidr: str | None = None
    destination_zone_or_cidr: str | None = None
    protected_zone: str | None = None
    untrusted_zone: str | None = None
    allowed_protocols: list[TransportProtocolConstraint] = Field(default_factory=list)
    allowed_ports: list[int] = Field(default_factory=list)
    service_ip: str | None = None
    service_port: int | None = None
    management_interface_id: str | None = None
    authorized_source_cidrs: list[str] = Field(default_factory=list)
    required_intermediate_nodes: list[str] = Field(default_factory=list)
    prohibited_intermediate_nodes: list[str] = Field(default_factory=list)
    description: str = ""


class SecurityInvariant(BaseModel):
    invariant_id: str
    name: str
    description: str
    invariant_type: InvariantType
    severity: InvariantSeverity
    scope: str = "GLOBAL"
    definition: InvariantDefinition
    version: str = "1.0.0"
    created_at_iso: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())


class VerificationResult(BaseModel):
    result_id: str
    invariant_id: str
    invariant_name: str
    invariant_type: InvariantType
    severity: InvariantSeverity
    status: InvariantStatus
    reason_code: str
    explanation: str
    witness_path: list[PathHop] | None = None
    blocking_rule: BlockingRule | None = None
    model_id: str
    model_fingerprint: str
    evaluated_at_iso: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    evidence_ids: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


# --- Counterfactual Scenarios ---


class SimulationAction(BaseModel):
    action_type: SimulationActionType
    target_node_id: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    comment: str = ""


class SimulationScenario(BaseModel):
    scenario_id: str
    name: str
    description: str
    base_model_id: str
    actions: list[SimulationAction] = Field(default_factory=list)
    created_at_iso: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())


class PathDifference(BaseModel):
    source_ip: str
    destination_ip: str
    protocol: TransportProtocolConstraint
    destination_port: int | None = None
    baseline_status: ReachabilityStatus
    counterfactual_status: ReachabilityStatus
    change_type: Literal["NEWLY_REACHABLE", "NEWLY_BLOCKED", "PATH_CHANGED", "UNCHANGED"]
    explanation: str


class InvariantDifference(BaseModel):
    invariant_id: str
    invariant_name: str
    baseline_status: InvariantStatus
    counterfactual_status: InvariantStatus
    explanation: str


class CounterfactualResult(BaseModel):
    run_id: str
    scenario_id: str
    base_model_id: str
    baseline_fingerprint: str
    counterfactual_model_id: str
    counterfactual_fingerprint: str
    applied_actions_count: int
    reachability_diffs: list[PathDifference] = Field(default_factory=list)
    invariant_diffs: list[InvariantDifference] = Field(default_factory=list)
    newly_reachable_count: int = 0
    newly_blocked_count: int = 0
    invariant_regressions_count: int = 0
    summary_explanation: str
    executed_at_iso: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
