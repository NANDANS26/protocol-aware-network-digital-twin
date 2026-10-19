/**
 * Production-Quality Hierarchical Clustered Topology Layout Engine.
 * 
 * Provides deterministic, collision-free node placement and boundary-to-boundary
 * edge routing with hierarchical subnet containment, docked host services,
 * transit routing tiers, and external traffic separation.
 */

import type {
  TopologyGraph,
  TopologyNode,
  TopologyEdge,
} from '../../../types/intelligence';

export interface BoundingBox {
  x: number;
  y: number;
  width: number;
  height: number;
}

export interface PlacedNode {
  nodeId: string;
  node: TopologyNode;
  x: number; // center x
  y: number; // center y
  width: number;
  height: number;
  box: BoundingBox;
  subnetId?: string;
  hostAssetId?: string;
  isCollapsed?: boolean;
}

export interface SubnetContainerBox {
  subnetId: string;
  cidr: string;
  label: string;
  gatewayIp?: string;
  hostCount: number;
  serviceCount?: number;
  x: number;
  y: number;
  width: number;
  height: number;
  isCollapsed: boolean;
  memberNodeIds: string[];
}

export interface TransitTierBox {
  x: number;
  y: number;
  width: number;
  height: number;
  routerNodeIds: string[];
}

export interface UnresolvedContainerBox {
  x: number;
  y: number;
  width: number;
  height: number;
  memberNodeIds: string[];
}

export interface RoutedEdge {
  edgeId: string;
  edge: TopologyEdge;
  sourceNodeId: string;
  targetNodeId: string;
  sourcePoint: { x: number; y: number };
  targetPoint: { x: number; y: number };
  pathData: string;
  strokeColor: string;
  strokeWidth: number;
  isDashed: boolean;
  protocol: string;
  label?: string;
}

export interface LayoutBounds {
  minX: number;
  minY: number;
  maxX: number;
  maxY: number;
  width: number;
  height: number;
  centerX: number;
  centerY: number;
}

export interface TopologyLayoutResult {
  placedNodes: Map<string, PlacedNode>;
  subnetContainers: SubnetContainerBox[];
  transitTier?: TransitTierBox;
  unresolvedContainer?: UnresolvedContainerBox;
  routedEdges: RoutedEdge[];
  bounds: LayoutBounds;
}

// Geometric helpers
export function getBoxIntersection(
  box: BoundingBox,
  targetPoint: { x: number; y: number }
): { x: number; y: number } {
  const cx = box.x + box.width / 2;
  const cy = box.y + box.height / 2;
  const dx = targetPoint.x - cx;
  const dy = targetPoint.y - cy;

  if (Math.abs(dx) < 1e-6 && Math.abs(dy) < 1e-6) {
    return { x: cx, y: cy };
  }

  const halfW = box.width / 2;
  const halfH = box.height / 2;

  // Slope-based boundary ray casting
  const scaleX = halfW / Math.max(Math.abs(dx), 1e-6);
  const scaleY = halfH / Math.max(Math.abs(dy), 1e-6);
  const scale = Math.min(scaleX, scaleY);

  return {
    x: Math.round(cx + dx * scale),
    y: Math.round(cy + dy * scale),
  };
}

export function computeSmoothBezierPath(
  p1: { x: number; y: number },
  p2: { x: number; y: number }
): string {
  const dx = p2.x - p1.x;
  const dy = p2.y - p1.y;

  // Determine primary direction
  if (Math.abs(dx) >= Math.abs(dy)) {
    const curvature = Math.max(30, Math.min(120, Math.abs(dx) * 0.4));
    const cx1 = p1.x + (dx > 0 ? curvature : -curvature);
    const cy1 = p1.y;
    const cx2 = p2.x - (dx > 0 ? curvature : -curvature);
    const cy2 = p2.y;
    return `M ${p1.x} ${p1.y} C ${cx1} ${cy1}, ${cx2} ${cy2}, ${p2.x} ${p2.y}`;
  } else {
    const curvature = Math.max(30, Math.min(120, Math.abs(dy) * 0.4));
    const cx1 = p1.x;
    const cy1 = p1.y + (dy > 0 ? curvature : -curvature);
    const cx2 = p2.x;
    const cy2 = p2.y - (dy > 0 ? curvature : -curvature);
    return `M ${p1.x} ${p1.y} C ${cx1} ${cy1}, ${cx2} ${cy2}, ${p2.x} ${p2.y}`;
  }
}

/**
 * Checks whether an IP address belongs to a CIDR prefix (simple IPv4/IPv6 prefix check).
 */
export function isIpInCidr(ip: string, cidr: string): boolean {
  if (!ip || !cidr || !cidr.includes('/')) return false;
  try {
    const [networkStr, prefixLenStr] = cidr.split('/');
    if (!networkStr || !prefixLenStr) return false;
    const prefixLen = parseInt(prefixLenStr, 10);
    if (isNaN(prefixLen)) return false;

    // IPv4 check
    if (ip.includes('.') && networkStr.includes('.')) {
      const ipParts = ip.split('.').map((p) => parseInt(p, 10));
      const netParts = networkStr.split('.').map((p) => parseInt(p, 10));
      if (ipParts.length !== 4 || netParts.length !== 4) return false;

      let ipNum = 0;
      let netNum = 0;
      for (let i = 0; i < 4; i++) {
        ipNum = ((ipNum << 8) | (ipParts[i] || 0)) >>> 0;
        netNum = ((netNum << 8) | (netParts[i] || 0)) >>> 0;
      }
      const mask = prefixLen === 0 ? 0 : (~0 << (32 - prefixLen)) >>> 0;
      return (ipNum & mask) === (netNum & mask);
    }

    // Fallback simple prefix check for IPv6
    return ip.toLowerCase().startsWith(networkStr.split('::')[0]!.toLowerCase());
  } catch {
    return false;
  }
}

export function computeHierarchicalLayout(
  topology: TopologyGraph | null,
  collapsedSubnets: Set<string> = new Set()
): TopologyLayoutResult {
  const placedNodes = new Map<string, PlacedNode>();
  const subnetContainers: SubnetContainerBox[] = [];
  const routedEdges: RoutedEdge[] = [];

  const defaultBounds: LayoutBounds = {
    minX: -300,
    minY: -200,
    maxX: 300,
    maxY: 200,
    width: 600,
    height: 400,
    centerX: 0,
    centerY: 0,
  };

  if (!topology || !topology.nodes || topology.nodes.length === 0) {
    return {
      placedNodes,
      subnetContainers,
      routedEdges,
      bounds: defaultBounds,
    };
  }

  const nodes = topology.nodes;
  const edges = topology.edges || [];

  // Group nodes by type
  const subnetNodes = nodes.filter((n) => n.node_type === 'SUBNET');
  const routerNodes = nodes.filter((n) => n.node_type === 'ROUTER');
  const serviceNodes = nodes.filter((n) => n.node_type === 'SERVICE');
  const assetNodes = nodes.filter(
    (n) => n.node_type === 'ASSET' || n.node_type === 'INTERFACE' || n.node_type === 'DNS_RESOLVER'
  );

  // 1. Build Subnet Definitions
  const subnetMap = new Map<
    string,
    {
      node: TopologyNode;
      cidr: string;
      gatewayIp?: string;
      assets: TopologyNode[];
    }
  >();

  subnetNodes.forEach((sNode) => {
    const sId = sNode.node_id || sNode.id;
    const cidr =
      (sNode.properties?.cidr_prefix as string) ||
      sNode.subnet_cidr ||
      (sNode.label.includes('/') ? sNode.label.replace(/^Subnet\s*/i, '').trim() : '192.168.1.0/24');
    const gatewayIp = sNode.properties?.gateway_ip as string | undefined;

    subnetMap.set(sId, {
      node: sNode,
      cidr,
      gatewayIp,
      assets: [],
    });
  });

  // Also discover implicit subnets if none exist but assets have subnet_cidr
  if (subnetMap.size === 0) {
    const inferredCidrs = new Set<string>();
    assetNodes.forEach((a) => {
      const cidr = a.subnet_cidr || (a.properties?.cidr_prefix as string);
      if (cidr) inferredCidrs.add(cidr);
    });

    inferredCidrs.forEach((cidr, idx) => {
      const sId = `subnet-inferred-${idx + 1}`;
      const virtualNode: TopologyNode = {
        id: sId,
        node_id: sId,
        label: `Subnet ${cidr}`,
        node_type: 'SUBNET',
        subnet_cidr: cidr,
        evidence_class: 'INFERRED',
      };
      subnetMap.set(sId, {
        node: virtualNode,
        cidr,
        assets: [],
      });
    });
  }

  // 2. Assign Assets to Subnets
  const unattachedAssets: TopologyNode[] = [];

  assetNodes.forEach((asset) => {
    const aId = asset.node_id || asset.id;
    let assignedSubnetId: string | null = null;

    // Check direct SUBNET_ATTACHMENT edge
    const attachEdge = edges.find(
      (e) =>
        e.edge_type === 'SUBNET_ATTACHMENT' &&
        (e.source_node_id === aId || e.target_node_id === aId)
    );
    if (attachEdge) {
      const targetSubId =
        attachEdge.source_node_id === aId ? attachEdge.target_node_id : attachEdge.source_node_id;
      if (subnetMap.has(targetSubId)) {
        assignedSubnetId = targetSubId;
      }
    }

    // Check segment_id property
    if (!assignedSubnetId && asset.segment_id) {
      for (const [sId, sData] of subnetMap.entries()) {
        if (sId.includes(asset.segment_id) || sData.node.segment_id === asset.segment_id) {
          assignedSubnetId = sId;
          break;
        }
      }
    }

    // Check IP in CIDR
    if (!assignedSubnetId) {
      const assetIps: string[] = [
        ...(asset.ip_addresses || []),
        ...((asset.properties?.ip_addresses as string[]) || []),
        asset.label,
      ].filter((ip) => ip && ip.includes('.'));

      for (const [sId, sData] of subnetMap.entries()) {
        if (assetIps.some((ip) => isIpInCidr(ip, sData.cidr))) {
          assignedSubnetId = sId;
          break;
        }
      }
    }

    if (assignedSubnetId && subnetMap.has(assignedSubnetId)) {
      subnetMap.get(assignedSubnetId)!.assets.push(asset);
    } else {
      unattachedAssets.push(asset);
    }
  });

  // 3. Map Services to Host Assets
  const hostServiceMap = new Map<string, TopologyNode[]>();
  const unassignedServices: TopologyNode[] = [];

  serviceNodes.forEach((svc) => {
    const svcId = svc.node_id || svc.id;
    let parentAssetId = svc.asset_id;

    if (!parentAssetId) {
      const hostEdge = edges.find(
        (e) =>
          e.edge_type === 'SERVICE_DEPENDENCY' &&
          (e.source_node_id === svcId || e.target_node_id === svcId)
      );
      if (hostEdge) {
        parentAssetId =
          hostEdge.source_node_id === svcId ? hostEdge.target_node_id : hostEdge.source_node_id;
      }
    }

    if (!parentAssetId && svc.ip_addresses && svc.ip_addresses.length > 0) {
      const matchByIp = assetNodes.find((a) =>
        (a.ip_addresses || []).some((ip) => svc.ip_addresses!.includes(ip))
      );
      if (matchByIp) {
        parentAssetId = matchByIp.node_id || matchByIp.id;
      }
    }

    if (parentAssetId) {
      // Normalize asset ID matching
      const targetNode = nodes.find(
        (n) =>
          (n.node_id || n.id) === parentAssetId ||
          (n.node_id || n.id) === `node-${parentAssetId}` ||
          n.asset_id === parentAssetId
      );
      const targetKey = targetNode ? (targetNode.node_id || targetNode.id) : parentAssetId;

      if (!hostServiceMap.has(targetKey)) {
        hostServiceMap.set(targetKey, []);
      }
      hostServiceMap.get(targetKey)!.push(svc);
    } else {
      unassignedServices.push(svc);
    }
  });

  // 4. Calculate Subnet Container Dimensions & Internal Node Coordinates
  const ASSET_CARD_WIDTH = 190;
  const ASSET_CARD_BASE_HEIGHT = 68;
  const SERVICE_CHIP_HEIGHT = 24;
  const GRID_COL_GAP = 20;
  const GRID_ROW_GAP = 18;
  const CONTAINER_PADDING_X = 22;
  const CONTAINER_HEADER_HEIGHT = 50;
  const CONTAINER_BOTTOM_PADDING = 20;
  const SUBNET_COL_GAP = 80;
  const SUBNET_ROW_GAP = 70;

  const subnetEntries = Array.from(subnetMap.entries());

  // Pre-calculate subnet box dimensions and column configurations
  interface SubnetPreCalc {
    sId: string;
    sData: {
      node: TopologyNode;
      cidr: string;
      gatewayIp?: string;
      assets: TopologyNode[];
    };
    isCollapsed: boolean;
    hosts: TopologyNode[];
    totalServices: number;
    boxWidth: number;
    boxHeight: number;
    numCols: number;
    assetHeights: number[];
  }

  const precomputedSubnets: SubnetPreCalc[] = subnetEntries.map(([sId, sData]) => {
    const isCollapsed = collapsedSubnets.has(sId);
    const hosts = sData.assets;
    const totalServices = hosts.reduce((acc, h) => {
      const hId = h.node_id || h.id;
      return acc + (hostServiceMap.get(hId)?.length || 0);
    }, 0);

    if (isCollapsed) {
      return {
        sId,
        sData,
        isCollapsed: true,
        hosts,
        totalServices,
        boxWidth: 240,
        boxHeight: 52,
        numCols: 1,
        assetHeights: [],
      };
    }

    const numCols = Math.min(3, Math.max(1, Math.ceil(Math.sqrt(Math.max(1, hosts.length)))));
    const boxWidth =
      CONTAINER_PADDING_X * 2 +
      numCols * ASSET_CARD_WIDTH +
      (numCols - 1) * GRID_COL_GAP;

    const colY = new Array(numCols).fill(CONTAINER_HEADER_HEIGHT + 14);
    const assetHeights: number[] = [];

    hosts.forEach((asset, idx) => {
      const aId = asset.node_id || asset.id;
      const col = idx % numCols;
      const attachedServices = hostServiceMap.get(aId) || [];
      const serviceHeight = attachedServices.length * (SERVICE_CHIP_HEIGHT + 4);
      const totalCardHeight =
        ASSET_CARD_BASE_HEIGHT + (attachedServices.length > 0 ? serviceHeight + 8 : 0);

      assetHeights.push(totalCardHeight);
      colY[col] += totalCardHeight + GRID_ROW_GAP;
    });

    const maxColY = Math.max(...colY, CONTAINER_HEADER_HEIGHT + 80);
    const boxHeight = maxColY + CONTAINER_BOTTOM_PADDING;

    return {
      sId,
      sData,
      isCollapsed: false,
      hosts,
      totalServices,
      boxWidth,
      boxHeight,
      numCols,
      assetHeights,
    };
  });

  // Calculate balanced multi-row columns
  // <= 2 subnets -> 1 row (side-by-side)
  // 3-4 subnets -> 2 columns per row
  // 5+ subnets -> 3 columns per row
  const colsPerRow =
    precomputedSubnets.length <= 2
      ? precomputedSubnets.length
      : precomputedSubnets.length <= 4
      ? 2
      : 3;

  let currentY = 0;
  let maxGridRight = 0;
  const numRows = colsPerRow > 0 ? Math.ceil(precomputedSubnets.length / colsPerRow) : 0;

  for (let r = 0; r < numRows; r++) {
    const rowSubnets = precomputedSubnets.slice(r * colsPerRow, (r + 1) * colsPerRow);
    const rowHeight = Math.max(...rowSubnets.map((s) => s.boxHeight));
    let currentX = 0;

    rowSubnets.forEach((sub) => {
      const {
        sId,
        sData,
        isCollapsed,
        hosts,
        totalServices,
        boxWidth,
        boxHeight,
        numCols,
        assetHeights,
      } = sub;
      const containerX = currentX;
      const containerY = currentY;
      const memberNodeIds: string[] = [sId];

      if (isCollapsed) {
        const containerBox: SubnetContainerBox = {
          subnetId: sId,
          cidr: sData.cidr,
          label: sData.node.label,
          gatewayIp: sData.gatewayIp,
          hostCount: hosts.length,
          serviceCount: totalServices,
          x: containerX,
          y: containerY,
          width: boxWidth,
          height: boxHeight,
          isCollapsed: true,
          memberNodeIds,
        };
        subnetContainers.push(containerBox);

        // Register subnet node at container center
        placedNodes.set(sId, {
          nodeId: sId,
          node: sData.node,
          x: containerX + boxWidth / 2,
          y: containerY + boxHeight / 2,
          width: boxWidth,
          height: boxHeight,
          box: { x: containerX, y: containerY, width: boxWidth, height: boxHeight },
          isCollapsed: true,
        });

        // Mark member nodes as placed inside collapsed container
        hosts.forEach((h) => {
          const hId = h.node_id || h.id;
          memberNodeIds.push(hId);
          placedNodes.set(hId, {
            nodeId: hId,
            node: h,
            x: containerX + boxWidth / 2,
            y: containerY + boxHeight / 2,
            width: 0,
            height: 0,
            box: { x: containerX, y: containerY, width: boxWidth, height: boxHeight },
            subnetId: sId,
            isCollapsed: true,
          });

          const svcs = hostServiceMap.get(hId) || [];
          svcs.forEach((svc) => {
            const svcId = svc.node_id || svc.id;
            memberNodeIds.push(svcId);
            placedNodes.set(svcId, {
              nodeId: svcId,
              node: svc,
              x: containerX + boxWidth / 2,
              y: containerY + boxHeight / 2,
              width: 0,
              height: 0,
              box: { x: containerX, y: containerY, width: boxWidth, height: boxHeight },
              subnetId: sId,
              hostAssetId: hId,
              isCollapsed: true,
            });
          });
        });
      } else {
        // Expanded Layout
        const colY = new Array(numCols).fill(containerY + CONTAINER_HEADER_HEIGHT + 14);

        hosts.forEach((asset, idx) => {
          const aId = asset.node_id || asset.id;
          memberNodeIds.push(aId);

          const col = idx % numCols;
          const posX =
            containerX + CONTAINER_PADDING_X + col * (ASSET_CARD_WIDTH + GRID_COL_GAP);
          const posY = colY[col]!;
          const totalCardHeight = assetHeights[idx] || ASSET_CARD_BASE_HEIGHT;

          // Register placed Asset Card
          placedNodes.set(aId, {
            nodeId: aId,
            node: asset,
            x: posX + ASSET_CARD_WIDTH / 2,
            y: posY + totalCardHeight / 2,
            width: ASSET_CARD_WIDTH,
            height: totalCardHeight,
            box: {
              x: posX,
              y: posY,
              width: ASSET_CARD_WIDTH,
              height: totalCardHeight,
            },
            subnetId: sId,
            isCollapsed: false,
          });

          // Place attached services docked inside the asset's card footprint
          let svcTop = posY + ASSET_CARD_BASE_HEIGHT + 4;
          const attachedServices = hostServiceMap.get(aId) || [];
          attachedServices.forEach((svc) => {
            const svcId = svc.node_id || svc.id;
            memberNodeIds.push(svcId);
            const svcW = ASSET_CARD_WIDTH - 16;
            const svcH = SERVICE_CHIP_HEIGHT;

            placedNodes.set(svcId, {
              nodeId: svcId,
              node: svc,
              x: posX + ASSET_CARD_WIDTH / 2,
              y: svcTop + svcH / 2,
              width: svcW,
              height: svcH,
              box: {
                x: posX + 8,
                y: svcTop,
                width: svcW,
                height: svcH,
              },
              subnetId: sId,
              hostAssetId: aId,
              isCollapsed: false,
            });

            svcTop += svcH + 4;
          });

          colY[col] = posY + totalCardHeight + GRID_ROW_GAP;
        });

        const containerBox: SubnetContainerBox = {
          subnetId: sId,
          cidr: sData.cidr,
          label: sData.node.label,
          gatewayIp: sData.gatewayIp,
          hostCount: hosts.length,
          serviceCount: totalServices,
          x: containerX,
          y: containerY,
          width: boxWidth,
          height: boxHeight,
          isCollapsed: false,
          memberNodeIds,
        };
        subnetContainers.push(containerBox);

        // Register Subnet Node itself at top-center of container
        placedNodes.set(sId, {
          nodeId: sId,
          node: sData.node,
          x: containerX + boxWidth / 2,
          y: containerY + CONTAINER_HEADER_HEIGHT / 2,
          width: boxWidth,
          height: CONTAINER_HEADER_HEIGHT,
          box: {
            x: containerX,
            y: containerY,
            width: boxWidth,
            height: CONTAINER_HEADER_HEIGHT,
          },
          subnetId: sId,
          isCollapsed: false,
        });
      }

      currentX += boxWidth + SUBNET_COL_GAP;
      maxGridRight = Math.max(maxGridRight, currentX);
    });

    currentY += rowHeight + SUBNET_ROW_GAP;
  }

  // 5. Place Routers in Transit / Routing Tier
  let transitTier: TransitTierBox | undefined;
  if (routerNodes.length > 0) {
    const ROUTER_WIDTH = 180;
    const ROUTER_HEIGHT = 65;
    const ROUTER_GAP = 24;

    const tierWidth =
      CONTAINER_PADDING_X * 2 +
      routerNodes.length * ROUTER_WIDTH +
      (routerNodes.length - 1) * ROUTER_GAP;
    const tierHeight = CONTAINER_HEADER_HEIGHT + ROUTER_HEIGHT + 24;

    // Center transit tier horizontally above the top row of subnets
    let tierCenterX = 200;
    let minSubnetTopY = 0;
    if (subnetContainers.length > 0) {
      const minX = Math.min(...subnetContainers.map((s) => s.x));
      const maxX = Math.max(...subnetContainers.map((s) => s.x + s.width));
      tierCenterX = (minX + maxX) / 2;
      minSubnetTopY = Math.min(...subnetContainers.map((s) => s.y));
    }

    const tierX = Math.round(tierCenterX - tierWidth / 2);
    const tierY = minSubnetTopY - (tierHeight + 60);

    transitTier = {
      x: tierX,
      y: tierY,
      width: tierWidth,
      height: tierHeight,
      routerNodeIds: routerNodes.map((r) => r.node_id || r.id),
    };

    routerNodes.forEach((rNode, idx) => {
      const rId = rNode.node_id || rNode.id;
      const rx = tierX + CONTAINER_PADDING_X + idx * (ROUTER_WIDTH + ROUTER_GAP);
      const ry = tierY + CONTAINER_HEADER_HEIGHT + 8;

      placedNodes.set(rId, {
        nodeId: rId,
        node: rNode,
        x: rx + ROUTER_WIDTH / 2,
        y: ry + ROUTER_HEIGHT / 2,
        width: ROUTER_WIDTH,
        height: ROUTER_HEIGHT,
        box: {
          x: rx,
          y: ry,
          width: ROUTER_WIDTH,
          height: ROUTER_HEIGHT,
        },
        isCollapsed: false,
      });
    });
  }

  // 6. Place External / Unresolved Nodes
  let unresolvedContainer: UnresolvedContainerBox | undefined;
  const unresolvedNodes = [...unattachedAssets, ...unassignedServices];
  if (unresolvedNodes.length > 0) {
    const UNRESOLVED_CARD_WIDTH = 180;
    const UNRESOLVED_CARD_HEIGHT = 58;
    const uWidth = CONTAINER_PADDING_X * 2 + UNRESOLVED_CARD_WIDTH;
    const uHeight =
      CONTAINER_HEADER_HEIGHT +
      unresolvedNodes.length * (UNRESOLVED_CARD_HEIGHT + 12) +
      CONTAINER_BOTTOM_PADDING;

    const uX = maxGridRight > 0 ? maxGridRight : 0;
    const uY = 0;

    unresolvedContainer = {
      x: uX,
      y: uY,
      width: uWidth,
      height: uHeight,
      memberNodeIds: unresolvedNodes.map((n) => n.node_id || n.id),
    };

    let itemY = uY + CONTAINER_HEADER_HEIGHT + 10;
    unresolvedNodes.forEach((uNode) => {
      const uId = uNode.node_id || uNode.id;
      const rx = uX + CONTAINER_PADDING_X;

      placedNodes.set(uId, {
        nodeId: uId,
        node: uNode,
        x: rx + UNRESOLVED_CARD_WIDTH / 2,
        y: itemY + UNRESOLVED_CARD_HEIGHT / 2,
        width: UNRESOLVED_CARD_WIDTH,
        height: UNRESOLVED_CARD_HEIGHT,
        box: {
          x: rx,
          y: itemY,
          width: UNRESOLVED_CARD_WIDTH,
          height: UNRESOLVED_CARD_HEIGHT,
        },
        isCollapsed: false,
      });

      itemY += UNRESOLVED_CARD_HEIGHT + 12;
    });
  }

  // 7. Route Edges (Boundary-to-Boundary Curves)
  edges.forEach((edge) => {
    const edgeId = edge.edge_id || edge.id;
    const sId = edge.source_node_id;
    const tId = edge.target_node_id;

    // Do not draw internal subnet attachment lines if subnet container is expanded (it is already visually contained)
    if (edge.edge_type === 'SUBNET_ATTACHMENT') {
      const sPlaced = placedNodes.get(sId);
      const tPlaced = placedNodes.get(tId);
      if (sPlaced && tPlaced && sPlaced.subnetId === tPlaced.subnetId && !sPlaced.isCollapsed) {
        // Redundant internal spoke - skip rendering to avoid cluttering subnet group
        return;
      }
    }

    // Do not draw duplicate lines for docked services inside the host card
    if (edge.edge_type === 'SERVICE_DEPENDENCY') {
      const sPlaced = placedNodes.get(sId);
      const tPlaced = placedNodes.get(tId);
      if (
        (sPlaced && tPlaced && sPlaced.hostAssetId === tId && !sPlaced.isCollapsed) ||
        (sPlaced && tPlaced && tPlaced.hostAssetId === sId && !tPlaced.isCollapsed)
      ) {
        // Docked service indicator is visually attached to host card - skip extra edge line
        return;
      }
    }

    const sNodePlaced = placedNodes.get(sId);
    const tNodePlaced = placedNodes.get(tId);

    if (!sNodePlaced || !tNodePlaced) return;

    // If source or target is collapsed, anchor to the Subnet Container box instead
    let sBox = sNodePlaced.box;
    if (sNodePlaced.isCollapsed && sNodePlaced.subnetId) {
      const sub = subnetContainers.find((sc) => sc.subnetId === sNodePlaced.subnetId);
      if (sub) sBox = { x: sub.x, y: sub.y, width: sub.width, height: sub.height };
    }

    let tBox = tNodePlaced.box;
    if (tNodePlaced.isCollapsed && tNodePlaced.subnetId) {
      const sub = subnetContainers.find((sc) => sc.subnetId === tNodePlaced.subnetId);
      if (sub) tBox = { x: sub.x, y: sub.y, width: sub.width, height: sub.height };
    }

    const tCenter = { x: tBox.x + tBox.width / 2, y: tBox.y + tBox.height / 2 };
    const sCenter = { x: sBox.x + sBox.width / 2, y: sBox.y + sBox.height / 2 };

    const p1 = getBoxIntersection(sBox, tCenter);
    const p2 = getBoxIntersection(tBox, sCenter);

    const pathData = computeSmoothBezierPath(p1, p2);

    const proto = (edge.primary_protocol || edge.protocol || 'IP').toUpperCase();
    const strokeColor =
      proto.includes('TCP') || proto.includes('HTTP')
        ? '#06b6d4' // Cyan
        : proto.includes('UDP') || proto.includes('DNS')
        ? '#f59e0b' // Amber
        : proto.includes('TLS')
        ? '#a855f7' // Purple
        : proto.includes('ROUT') || edge.edge_type === 'CONFIGURED_ROUTE'
        ? '#3b82f6' // Blue
        : '#10b981'; // Emerald

    const isDashed = edge.evidence_class === 'INFERRED' || edge.evidence_class === 'CONFIGURED';
    const strokeWidth = Math.min(3.5, Math.max(1.5, Math.log10(Math.max(1, edge.packet_count + 1))));

    routedEdges.push({
      edgeId,
      edge,
      sourceNodeId: sId,
      targetNodeId: tId,
      sourcePoint: p1,
      targetPoint: p2,
      pathData,
      strokeColor,
      strokeWidth,
      isDashed,
      protocol: proto,
      label: edge.packet_count > 0 ? `${edge.packet_count} pkts` : undefined,
    });
  });

  // 8. Compute Total Layout Bounds
  let minX = 0;
  let minY = 0;
  let maxX = 500;
  let maxY = 400;

  const allBoxes: BoundingBox[] = [
    ...subnetContainers.map((s) => ({ x: s.x, y: s.y, width: s.width, height: s.height })),
  ];
  if (transitTier) {
    allBoxes.push({ x: transitTier.x, y: transitTier.y, width: transitTier.width, height: transitTier.height });
  }
  if (unresolvedContainer) {
    allBoxes.push({
      x: unresolvedContainer.x,
      y: unresolvedContainer.y,
      width: unresolvedContainer.width,
      height: unresolvedContainer.height,
    });
  }

  // Include non-collapsed placed nodes to guarantee node labels and badges are enclosed
  placedNodes.forEach((pn) => {
    if (!pn.isCollapsed && pn.width > 0 && pn.height > 0) {
      allBoxes.push(pn.box);
    }
  });

  // Include routed edge endpoints
  routedEdges.forEach((e) => {
    allBoxes.push({ x: e.sourcePoint.x - 12, y: e.sourcePoint.y - 12, width: 24, height: 24 });
    allBoxes.push({ x: e.targetPoint.x - 12, y: e.targetPoint.y - 12, width: 24, height: 24 });
  });

  if (allBoxes.length > 0) {
    minX = Math.min(...allBoxes.map((b) => b.x));
    minY = Math.min(...allBoxes.map((b) => b.y));
    maxX = Math.max(...allBoxes.map((b) => b.x + b.width));
    maxY = Math.max(...allBoxes.map((b) => b.y + b.height));
  } else {
    const nodeCoords = Array.from(placedNodes.values());
    if (nodeCoords.length > 0) {
      minX = Math.min(...nodeCoords.map((n) => n.box.x));
      minY = Math.min(...nodeCoords.map((n) => n.box.y));
      maxX = Math.max(...nodeCoords.map((n) => n.box.x + n.box.width));
      maxY = Math.max(...nodeCoords.map((n) => n.box.y + n.box.height));
    }
  }

  // Generous safety margin to protect shadows, badges, ports, and edge arcs
  const PADDING = 64;
  minX -= PADDING;
  minY -= PADDING;
  maxX += PADDING;
  maxY += PADDING;

  const width = Math.max(600, maxX - minX);
  const height = Math.max(400, maxY - minY);

  const bounds: LayoutBounds = {
    minX,
    minY,
    maxX,
    maxY,
    width,
    height,
    centerX: Math.round(minX + width / 2),
    centerY: Math.round(minY + height / 2),
  };

  return {
    placedNodes,
    subnetContainers,
    transitTier,
    unresolvedContainer,
    routedEdges,
    bounds,
  };
}
