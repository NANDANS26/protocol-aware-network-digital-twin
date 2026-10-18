import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { TopologyGraphView } from '../views/twin/topology/TopologyGraphView';
import {
  computeHierarchicalLayout,
  computeSmoothBezierPath,
  getBoxIntersection,
} from '../views/twin/topology/layoutEngine';
import type { TopologyGraph } from '../types/intelligence';

describe('Hierarchical Clustered Topology Layout Engine', () => {
  const createMockTopology = (): TopologyGraph => ({
    nodes: [
      // Subnets
      {
        id: 'node-sub-corp',
        node_id: 'node-sub-corp',
        label: 'Corporate LAN',
        node_type: 'SUBNET',
        type: 'SUBNET',
        subnet_cidr: '10.0.1.0/24',
        evidence_class: 'CONFIGURED',
        metadata: {},
      },
      {
        id: 'node-sub-dmz',
        node_id: 'node-sub-dmz',
        label: 'DMZ Segment',
        node_type: 'SUBNET',
        type: 'SUBNET',
        subnet_cidr: '172.16.0.0/24',
        evidence_class: 'CONFIGURED',
        metadata: {},
      },
      // Router in Transit Tier
      {
        id: 'node-core-router',
        node_id: 'node-core-router',
        label: 'Core-GW-01',
        node_type: 'ROUTER',
        type: 'ROUTER',
        ip_addresses: ['10.0.1.1', '172.16.0.1'],
        mac_addresses: ['00:00:5e:00:01:01'],
        evidence_class: 'DIRECTLY_OBSERVED',
        metadata: {},
      },
      // Assets in Corporate Subnet
      {
        id: 'node-workstation-01',
        node_id: 'node-workstation-01',
        label: 'Workstation 1',
        node_type: 'ASSET',
        type: 'ASSET',
        ip_addresses: ['10.0.1.50'],
        mac_addresses: ['aa:bb:cc:dd:ee:01'],
        hostnames: ['ws-01.corp.local'],
        evidence_class: 'DIRECTLY_OBSERVED',
        metadata: {},
      },
      {
        id: 'node-workstation-02',
        node_id: 'node-workstation-02',
        label: 'Workstation 2',
        node_type: 'ASSET',
        type: 'ASSET',
        ip_addresses: ['10.0.1.51'],
        mac_addresses: ['aa:bb:cc:dd:ee:02'],
        hostnames: ['ws-02.corp.local'],
        evidence_class: 'DIRECTLY_OBSERVED',
        metadata: {},
      },
      // Asset with Service in DMZ
      {
        id: 'node-web-server',
        node_id: 'node-web-server',
        label: 'Web Server',
        node_type: 'ASSET',
        type: 'ASSET',
        ip_addresses: ['172.16.0.10'],
        mac_addresses: ['aa:bb:cc:dd:ee:10'],
        hostnames: ['web.dmz.local'],
        evidence_class: 'DIRECTLY_OBSERVED',
        metadata: {},
      },
      {
        id: 'node-srv-https',
        node_id: 'node-srv-https',
        label: 'HTTPS (443)',
        node_type: 'SERVICE',
        type: 'SERVICE',
        ip_addresses: ['172.16.0.10'],
        properties: { port: 443, protocol: 'TCP' },
        evidence_class: 'DIRECTLY_OBSERVED',
        metadata: {},
      },
      // External Unresolved Node
      {
        id: 'node-ext-attacker',
        node_id: 'node-ext-attacker',
        label: '203.0.113.88',
        node_type: 'ASSET',
        type: 'ASSET',
        ip_addresses: ['203.0.113.88'],
        evidence_class: 'INFERRED',
        metadata: {},
      },
    ],
    edges: [
      // Subnet membership
      {
        id: 'edge-sub-ws01',
        source_node_id: 'node-workstation-01',
        target_node_id: 'node-sub-corp',
        edge_type: 'SUBNET_ATTACHMENT',
        evidence_class: 'CONFIGURED',
        packet_count: 0,
        byte_count: 0,
      },
      {
        id: 'edge-sub-ws02',
        source_node_id: 'node-workstation-02',
        target_node_id: 'node-sub-corp',
        edge_type: 'SUBNET_ATTACHMENT',
        evidence_class: 'CONFIGURED',
        packet_count: 0,
        byte_count: 0,
      },
      {
        id: 'edge-sub-web',
        source_node_id: 'node-web-server',
        target_node_id: 'node-sub-dmz',
        edge_type: 'SUBNET_ATTACHMENT',
        evidence_class: 'CONFIGURED',
        packet_count: 0,
        byte_count: 0,
      },
      // Host-Service edge
      {
        id: 'edge-host-srv',
        source_node_id: 'node-web-server',
        target_node_id: 'node-srv-https',
        edge_type: 'HOST_SERVICE',
        evidence_class: 'DIRECTLY_OBSERVED',
        packet_count: 0,
        byte_count: 0,
      },
      // Router connections
      {
        id: 'edge-rtr-corp',
        source_node_id: 'node-core-router',
        target_node_id: 'node-sub-corp',
        edge_type: 'ROUTED_TRANSIT',
        evidence_class: 'CONFIGURED',
        packet_count: 120,
        byte_count: 14000,
      },
      {
        id: 'edge-rtr-dmz',
        source_node_id: 'node-core-router',
        target_node_id: 'node-sub-dmz',
        edge_type: 'ROUTED_TRANSIT',
        evidence_class: 'CONFIGURED',
        packet_count: 350,
        byte_count: 42000,
      },
      // Cross-subnet communication
      {
        id: 'edge-comm-client-srv',
        source_node_id: 'node-workstation-01',
        target_node_id: 'node-web-server',
        edge_type: 'OBSERVED_COMMUNICATION',
        primary_protocol: 'HTTPS',
        evidence_class: 'DIRECTLY_OBSERVED',
        packet_count: 240,
        byte_count: 58000,
      },
      // External traffic
      {
        id: 'edge-comm-ext',
        source_node_id: 'node-ext-attacker',
        target_node_id: 'node-web-server',
        edge_type: 'OBSERVED_COMMUNICATION',
        primary_protocol: 'HTTPS',
        evidence_class: 'DIRECTLY_OBSERVED',
        packet_count: 99,
        byte_count: 12000,
      },
    ],
    node_count: 8,
    edge_count: 8,
  });

  it('computes layout deterministically with identical outputs across repeated calls', () => {
    const topology = createMockTopology();
    const layout1 = computeHierarchicalLayout(topology, new Set());
    const layout2 = computeHierarchicalLayout(topology, new Set());

    expect(layout1.bounds).toEqual(layout2.bounds);
    expect(layout1.subnetContainers.length).toBe(layout2.subnetContainers.length);

    for (let i = 0; i < layout1.subnetContainers.length; i++) {
      expect(layout1.subnetContainers[i]).toEqual(layout2.subnetContainers[i]);
    }

    for (const [nodeId, placed1] of layout1.placedNodes.entries()) {
      const placed2 = layout2.placedNodes.get(nodeId);
      expect(placed2).toBeDefined();
      expect(placed1.x).toBe(placed2!.x);
      expect(placed1.y).toBe(placed2!.y);
      expect(placed1.width).toBe(placed2!.width);
      expect(placed1.height).toBe(placed2!.height);
    }
  });

  it('guarantees subnet container boxes and transit tier do not collide', () => {
    const topology = createMockTopology();
    const layout = computeHierarchicalLayout(topology, new Set());

    // Check subnet containers have positive dimensions
    expect(layout.subnetContainers.length).toBe(2);
    for (const box of layout.subnetContainers) {
      expect(box.width).toBeGreaterThan(150);
      expect(box.height).toBeGreaterThan(100);
    }

    // Check separation between the two subnet boxes
    const box1 = layout.subnetContainers[0];
    const box2 = layout.subnetContainers[1];
    expect(box2.x).toBeGreaterThanOrEqual(box1.x + box1.width + 30);

    // Check transit tier is placed in a distinct vertical tier
    if (layout.transitTier) {
      expect(layout.transitTier.width).toBeGreaterThan(100);
      // Transit tier sits above the subnet containers
      expect(layout.transitTier.y + layout.transitTier.height).toBeLessThanOrEqual(box1.y + 20);
    }
  });

  it('places member assets strictly inside their parent subnet container boundaries', () => {
    const topology = createMockTopology();
    const layout = computeHierarchicalLayout(topology, new Set());

    for (const box of layout.subnetContainers) {
      for (const memberId of box.memberNodeIds) {
        const placed = layout.placedNodes.get(memberId);
        if (placed && !placed.isCollapsed) {
          expect(placed.box.x).toBeGreaterThanOrEqual(box.x);
          expect(placed.box.x + placed.box.width).toBeLessThanOrEqual(box.x + box.width + 1);
          expect(placed.box.y).toBeGreaterThanOrEqual(box.y);
          expect(placed.box.y + placed.box.height).toBeLessThanOrEqual(box.y + box.height + 1);
        }
      }
    }
  });

  it('docks services directly into host asset cards', () => {
    const topology = createMockTopology();
    const layout = computeHierarchicalLayout(topology, new Set());

    const webServer = layout.placedNodes.get('node-web-server');
    expect(webServer).toBeDefined();

    // The service is associated to the host asset
    const serviceNode = layout.placedNodes.get('node-srv-https');
    expect(serviceNode?.hostAssetId).toBe('node-web-server');
  });

  it('places external and unresolved nodes in a dedicated container', () => {
    const topology = createMockTopology();
    const layout = computeHierarchicalLayout(topology, new Set());

    expect(layout.unresolvedContainer).toBeDefined();
    const attackerNode = layout.placedNodes.get('node-ext-attacker');
    expect(attackerNode).toBeDefined();
    expect(attackerNode!.box.x).toBeGreaterThanOrEqual(layout.unresolvedContainer!.x);
  });

  it('computes edge boundary intersections and smooth Bezier curves accurately', () => {
    const box = {
      x: 100,
      y: 100,
      width: 200,
      height: 100,
    };
    const outsideTarget = { x: 500, y: 150 }; // directly to the right of center (200, 150)

    const intersection = getBoxIntersection(box, outsideTarget);
    // Should intersect the right border at x = 300, y = 150
    expect(intersection.x).toBe(300);
    expect(intersection.y).toBe(150);

    // Compute Bezier path
    const path = computeSmoothBezierPath({ x: 100, y: 100 }, { x: 400, y: 300 });
    expect(path).toMatch(/^M 100 100 C /);
    expect(path).toContain('400 300');
  });

  it('supports subnet collapse: shrinks container and routes edges to container boundary', () => {
    const topology = createMockTopology();
    const collapsed = new Set(['node-sub-corp']);
    const layout = computeHierarchicalLayout(topology, collapsed);

    const corpBox = layout.subnetContainers.find((b) => b.subnetId === 'node-sub-corp');
    expect(corpBox).toBeDefined();
    expect(corpBox!.isCollapsed).toBe(true);
    // Collapsed header height is compact (around 48px)
    expect(corpBox!.height).toBeLessThan(60);

    // Member nodes inside collapsed subnet are marked isCollapsed
    const ws01 = layout.placedNodes.get('node-workstation-01');
    expect(ws01?.isCollapsed).toBe(true);
  });
});

describe('TopologyGraphView Component', () => {
  const mockTopology: TopologyGraph = {
    nodes: [
      {
        id: 'sub-internal',
        node_id: 'sub-internal',
        label: 'Internal Subnet',
        node_type: 'SUBNET',
        subnet_cidr: '192.168.1.0/24',
        evidence_class: 'CONFIGURED',
        metadata: {},
      },
      {
        id: 'host-db',
        node_id: 'host-db',
        label: 'Database Server',
        node_type: 'ASSET',
        ip_addresses: ['192.168.1.50'],
        mac_addresses: ['11:22:33:44:55:66'],
        evidence_class: 'DIRECTLY_OBSERVED',
        metadata: {},
      },
    ],
    edges: [
      {
        id: 'edge-sub',
        source_node_id: 'host-db',
        target_node_id: 'sub-internal',
        edge_type: 'SUBNET_ATTACHMENT',
        evidence_class: 'CONFIGURED',
        packet_count: 0,
        byte_count: 0,
      },
    ],
    node_count: 2,
    edge_count: 1,
  };

  it('renders search input, filter controls, zoom buttons, and canvas container', () => {
    const onSelectNode = vi.fn();
    const onSelectEdge = vi.fn();
    const onChangeEvidenceFilter = vi.fn();

    render(
      <TopologyGraphView
        topology={mockTopology}
        selectedNode={null}
        selectedEdge={null}
        onSelectNode={onSelectNode}
        onSelectEdge={onSelectEdge}
        evidenceClassFilter="ALL"
        onChangeEvidenceFilter={onChangeEvidenceFilter}
      />
    );

    // Controls
    expect(screen.getByPlaceholderText(/Search IP, Host, MAC, ID/i)).toBeInTheDocument();
    expect(screen.getByText('Expand All')).toBeInTheDocument();
    expect(screen.getByText('Collapse All')).toBeInTheDocument();
    expect(screen.getByTitle(/Zoom In/i)).toBeInTheDocument();
    expect(screen.getByTitle(/Zoom Out/i)).toBeInTheDocument();
    expect(screen.getByTitle(/Fit Entire Topology to View/i)).toBeInTheDocument();

    // Canvas contents
    expect(screen.getByText(/Subnet Hub/i)).toBeInTheDocument();
    expect(screen.getByText(/Asset Node/i)).toBeInTheDocument();
    expect(screen.getByText(/Internal Subnet/i)).toBeInTheDocument();
    expect(screen.getAllByText(/Database Server/i).length).toBeGreaterThanOrEqual(1);
  });

  it('filters and highlights nodes when search term is entered', () => {
    render(
      <TopologyGraphView
        topology={mockTopology}
        selectedNode={null}
        selectedEdge={null}
        onSelectNode={vi.fn()}
        onSelectEdge={vi.fn()}
        evidenceClassFilter="ALL"
        onChangeEvidenceFilter={vi.fn()}
      />
    );

    const searchInput = screen.getByPlaceholderText(/Search IP, Host, MAC, ID/i);
    fireEvent.change(searchInput, { target: { value: '192.168.1.50' } });

    expect(screen.getByText(/Found 1 matching node/i)).toBeInTheDocument();
  });

  it('opens and closes the Inspector Details drawer with Return to Full Graph button', () => {
    const onSelectNode = vi.fn();
    const selected = mockTopology.nodes[1];

    const { rerender } = render(
      <TopologyGraphView
        topology={mockTopology}
        selectedNode={null}
        selectedEdge={null}
        onSelectNode={onSelectNode}
        onSelectEdge={vi.fn()}
        evidenceClassFilter="ALL"
        onChangeEvidenceFilter={vi.fn()}
      />
    );

    // Initially unselected
    expect(screen.getByText(/Topology Inspector/i)).toBeInTheDocument();

    // Rerender with node selected
    rerender(
      <TopologyGraphView
        topology={mockTopology}
        selectedNode={selected}
        selectedEdge={null}
        onSelectNode={onSelectNode}
        onSelectEdge={vi.fn()}
        evidenceClassFilter="ALL"
        onChangeEvidenceFilter={vi.fn()}
      />
    );

    // Inspector is open
    expect(screen.getByText('Return to Full Graph')).toBeInTheDocument();
    expect(screen.getAllByText('192.168.1.50').length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText('11:22:33:44:55:66').length).toBeGreaterThanOrEqual(1);

    // Click Return to Full Graph
    fireEvent.click(screen.getByText('Return to Full Graph'));
    expect(onSelectNode).toHaveBeenCalledWith(null);
  });
});
