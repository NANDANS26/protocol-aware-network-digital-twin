/**
 * TypeScript contract interfaces for Health and Readiness status.
 */

export type OverallHealthStatus = 'healthy' | 'degraded' | 'unhealthy' | 'not_ready';

export type SubsystemState = 'ok' | 'degraded' | 'down' | 'disabled' | 'planned';

export type OperationalState = 'operational' | 'unavailable' | 'planned';

export interface SubsystemReport {
  status: SubsystemState;
  operational_state: OperationalState;
  details?: string | null;
  last_checked?: string | null;
}

export interface HealthStatusResponse {
  status: OverallHealthStatus;
  timestamp: string;
  version: string;
  schema_version: string;
  environment: string;
  subsystems: Record<string, SubsystemReport>;
}
