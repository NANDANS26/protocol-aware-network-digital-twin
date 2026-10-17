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
  phase: string;
  isImplemented: boolean;
  description: string;
}

export const NAVIGATION_TABS: TabDefinition[] = [
  {
    id: 'overview',
    label: 'Overview & Foundation',
    phase: 'Phase 00',
    isImplemented: true,
    description: 'Engineering baseline, system lifecycle, subsystem operational status, and contract verification.',
  },
  {
    id: 'observatory',
    label: 'Network Observatory',
    phase: 'Phase 01',
    isImplemented: false,
    description: 'High-throughput packet capture, C++ decoder pipeline, and protocol-aware flow stream.',
  },
  {
    id: 'twin',
    label: 'Network Twin',
    phase: 'Phase 03',
    isImplemented: false,
    description: 'Evidence-based topology reconstruction, versioned device graph, and active interface state.',
  },
  {
    id: 'laboratory',
    label: 'Scenario Laboratory',
    phase: 'Phase 06',
    isImplemented: false,
    description: 'Deterministic security-property verification, counterexample generation, and what-if simulation.',
  },
  {
    id: 'research',
    label: 'Protocol Research Lab',
    phase: 'Phase 07',
    isImplemented: false,
    description: 'Isolated protocol fuzzing, state machine differential testing, and grammar synthesis.',
  },
  {
    id: 'investigation',
    label: 'Investigation Workspace',
    phase: 'Phase 08',
    isImplemented: false,
    description: 'Evidence-grounded security investigation agents and learned network world model.',
  },
];
