// Wire contracts shared with the Rust daemon and the Go control plane.
// Field names are snake_case in all three languages; the shapes are
// pinned by the fixtures under contracts/ at the repo root.

export interface PeerNode {
  node_id: string;
  node_name: string;
  public_key: string;
  fingerprint: string;
  virtual_ip: string;
  endpoint: string;
  role: string;
  online: boolean;
  nat_type: string;
  ebpf_probe_passed: boolean;
  last_seen: string;
  tx_bytes: number;
  rx_bytes: number;
  avg_latency_ms: number;
}

export interface TopologyLink {
  a: string;
  b: string;
  latency_ms: number;
  encrypted: boolean;
}

export interface MeshTopology {
  nodes: PeerNode[];
  links: TopologyLink[];
  generated_at: string;
}

export interface AclRule {
  id: string;
  source_role: string;
  dest_service: string;
  port: number;
  action: string; // "ALLOW" | "DENY"
  priority: number;
}

export interface AclPolicyResponse {
  version: number;
  rules: AclRule[];
}

export interface DashboardData {
  topology: MeshTopology;
  policy: AclPolicyResponse;
  demo: boolean;
}
