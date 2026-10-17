/**
 * Strongly Typed Contracts for Phase 08: Adversarial Verification & Trustworthy Network Twin Hardening.
 */

export type AdversarialCategory =
  | 'ROUTING_FORWARDING'
  | 'SECURITY_ISOLATION'
  | 'CONFIG_CONSISTENCY'
  | 'PARSER_RESILIENCE'
  | 'PREDICTIVE_INTEGRITY'
  | 'METAMORPHIC_INVARIANCE';

export interface AdversarialTestCase {
  test_id: string;
  name: string;
  category: AdversarialCategory;
  description: string;
  hand_verifiable_oracle: string;
  expected_status: string;
  expected_reason_code: string;
}

export interface AdversarialTestResult {
  test_id: string;
  name: string;
  category: AdversarialCategory;
  hand_verifiable_oracle: string;
  expected_status: string;
  actual_status: string;
  expected_reason_code: string;
  actual_reason_code: string;
  passed: boolean;
  details: string;
  execution_time_ms: number;
}

export interface AdversarialRunSummary {
  run_id: string;
  timestamp: string;
  total_cases: number;
  passed_cases: number;
  failed_cases: number;
  all_passed: boolean;
  duration_ms: number;
  results: AdversarialTestResult[];
}
