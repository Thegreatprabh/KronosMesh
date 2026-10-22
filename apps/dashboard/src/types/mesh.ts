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

/// How a dashboard load failed. The console treats these differently:
/// a network failure usually means the plane is down or unreachable,
/// an HTTP failure means it answered but rejected the request, and a
/// parse failure means it answered with something unintelligible.
export type LoadErrorKind = 'network' | 'http' | 'parse';

export interface LoadError {
  kind: LoadErrorKind;
  message: string;
  status?: number;
}

export interface DashboardData {
  topology: MeshTopology;
  policy: AclPolicyResponse;
  demo: boolean;
  /// True when this payload is the last successfully loaded live data,
  /// kept on screen because the latest refresh failed. Demo data is
  /// only ever shown when no live load has succeeded yet.
  stale?: boolean;
  /// Why the latest refresh failed (present in stale and demo states).
  error?: LoadError;
  /// Epoch milliseconds of the last successful live load.
  fetchedAt?: number;
}
