import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { TopologyModal } from '../views/twin/topology/TopologyModal';
import type { TopologyGraph } from '../types/intelligence';

describe('TopologyModal Component', () => {
  const createMockTopology = (): TopologyGraph => ({
    nodes: [
      {
        id: 'node-sub-corp',
        node_id: 'node-sub-corp',
        label: 'Corporate LAN',
        node_type: 'SUBNET',
        subnet_cidr: '10.0.1.0/24',
        evidence_class: 'CONFIGURED',
        metadata: {},
      },
      {
        id: 'node-router-gw',
        node_id: 'node-router-gw',
        label: 'Gateway Router',
        node_type: 'ROUTER',
        ip_addresses: ['10.0.1.1'],
        evidence_class: 'DIRECTLY_OBSERVED',
        metadata: {},
      },
      {
        id: 'node-host-1',
        node_id: 'node-host-1',
        label: 'Host 1',
        node_type: 'ASSET',
        ip_addresses: ['10.0.1.50'],
        evidence_class: 'DIRECTLY_OBSERVED',
        metadata: {},
      },
    ],
    edges: [
      {
        id: 'edge-sub-1',
        edge_id: 'edge-sub-1',
        source_node_id: 'node-host-1',
        target_node_id: 'node-sub-corp',
        edge_type: 'SUBNET_ATTACHMENT',
        evidence_class: 'DIRECTLY_OBSERVED',
        packet_count: 10,
        byte_count: 500,
      },
      {
        id: 'edge-gw-1',
        edge_id: 'edge-gw-1',
        source_node_id: 'node-router-gw',
        target_node_id: 'node-sub-corp',
        edge_type: 'SUBNET_ATTACHMENT',
        evidence_class: 'CONFIGURED',
        packet_count: 20,
        byte_count: 1200,
      },
    ],
    node_count: 3,
    edge_count: 2,
    generated_at_iso: '2026-10-18T12:00:00Z',
  });

  const defaultProps = {
    isOpen: true,
    onClose: vi.fn(),
    topology: createMockTopology(),
    selectedNode: null,
    selectedEdge: null,
    onSelectNode: vi.fn(),
    onSelectEdge: vi.fn(),
    evidenceClassFilter: 'ALL',
    onChangeEvidenceFilter: vi.fn(),
  };

  it('does not render modal when isOpen is false', () => {
    const { container } = render(
      <TopologyModal {...defaultProps} isOpen={false} />
    );
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(container.firstChild).toBeNull();
  });

  it('renders modal with proper accessibility attributes when isOpen is true', () => {
    render(<TopologyModal {...defaultProps} />);

    const dialog = screen.getByRole('dialog');
    expect(dialog).toBeInTheDocument();
    expect(dialog).toHaveAttribute('aria-modal', 'true');
    expect(dialog).toHaveAttribute('aria-labelledby', 'topology-modal-title');
    expect(screen.getByText('Interactive Network Topology')).toBeInTheDocument();
    expect(screen.getByText('Full-Screen Workspace')).toBeInTheDocument();
  });

  it('renders dynamic network metrics in header', () => {
    render(<TopologyModal {...defaultProps} />);

    // Total nodes = 3, subnets = 1, routers = 1, relationships = 2
    expect(screen.getByText('3')).toBeInTheDocument();
    expect(screen.getByText(/nodes/)).toBeInTheDocument();
    expect(screen.getByText(/subnets/)).toBeInTheDocument();
    expect(screen.getByText(/transit routers/)).toBeInTheDocument();
    expect(screen.getByText(/relationships/)).toBeInTheDocument();
  });

  it('calls onClose when close button is clicked', () => {
    const onClose = vi.fn();
    render(<TopologyModal {...defaultProps} onClose={onClose} />);

    const closeButton = screen.getByRole('button', { name: /Close Interactive Topology/i });
    expect(closeButton).toBeInTheDocument();
    fireEvent.click(closeButton);

    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('calls onClose when Escape key is pressed', () => {
    const onClose = vi.fn();
    render(<TopologyModal {...defaultProps} onClose={onClose} />);

    fireEvent.keyDown(window, { key: 'Escape', code: 'Escape' });
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('closes when clicking the backdrop outside modal window', () => {
    const onClose = vi.fn();
    render(<TopologyModal {...defaultProps} onClose={onClose} />);

    const backdrop = screen.getByTestId('topology-modal-backdrop');
    fireEvent.click(backdrop);
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('does not close when clicking inside the modal content window', () => {
    const onClose = vi.fn();
    render(<TopologyModal {...defaultProps} onClose={onClose} />);

    const content = screen.getByTestId('topology-modal-content');
    fireEvent.click(content);
    expect(onClose).not.toHaveBeenCalled();
  });

  it('restores focus to previously active element upon closing', () => {
    const button = document.createElement('button');
    button.textContent = 'Trigger Button';
    document.body.appendChild(button);
    button.focus();
    expect(document.activeElement).toBe(button);

    const { unmount } = render(<TopologyModal {...defaultProps} />);

    unmount();
    expect(document.activeElement).toBe(button);
    document.body.removeChild(button);
  });
});
