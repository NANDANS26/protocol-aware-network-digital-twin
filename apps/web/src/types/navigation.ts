export type NavigationTab =
  | 'overview'
  | 'observatory'
  | 'twin'
  | 'laboratory'
  | 'research'
  | 'investigation';

export interface TabDefinition {
  id: NavigationTab;
  label: string;
  statusLabel: string;
  phase?: string;
  isImplemented: boolean;
  description: string;
}

export const NAVIGATION_TABS: TabDefinition[] = [
  {
    id: 'overview',
    label: 'System Overview',
    statusLabel: 'Ready',
    phase: 'Ready',
    isImplemented: true,
    description: 'Engineering baseline, system lifecycle, subsystem operational status, and real platform metrics.',
  },
  {
    id: 'observatory',
    label: 'Network Observatory',
    statusLabel: 'Live',
    phase: 'Live',
    isImplemented: true,
    description: 'High-throughput packet capture, C++ decoder pipeline, and protocol-aware flow stream.',
  },
  {
    id: 'twin',
    label: 'Network Digital Twin',
    statusLabel: 'Active',
    phase: 'Active',
    isImplemented: true,
    description: 'Evidence-based topology reconstruction, asset discovery, DNS/flow correlation, and versioned snapshots.',
  },
  {
    id: 'laboratory',
    label: 'Scenario Laboratory',
    statusLabel: 'Verified',
    phase: 'Verified',
    isImplemented: true,
    description: 'Deterministic security-property verification, counterexample generation, and what-if simulation.',
  },
  {
    id: 'research',
    label: 'Protocol Research Lab',
    statusLabel: 'Active',
    phase: 'Active',
    isImplemented: true,
    description: 'Protocol-aware security test generation, mutation fuzzing, differential testing, and regression suite.',
  },
  {
    id: 'investigation',
    label: 'Investigation Workspace',
    statusLabel: 'Audited',
    phase: 'Audited',
    isImplemented: true,
    description: 'Evidence-grounded security investigation replay, integrity auditing, and counterfactual remediation.',
  },
];
