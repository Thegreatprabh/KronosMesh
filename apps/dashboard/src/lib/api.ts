import type {
  AclPolicyResponse,
  AclRule,
  DashboardData,
  LoadError,
  LoadErrorKind,
  MeshTopology,
  PeerNode,
} from '../types/mesh';

const CONTROL_URL: string =
  (import.meta.env.VITE_CONTROL_URL as string | undefined) ??
  'http://localhost:8080';

export function controlUrl(): string {
  return CONTROL_URL;
}

/// A control-plane load failure, classified so the console can explain
/// WHAT went wrong instead of silently swapping in demo values.
export class ApiError extends Error {
  readonly kind: LoadErrorKind;
  readonly status?: number;

  constructor(kind: LoadErrorKind, message: string, status?: number) {
    super(message);
    this.kind = kind;
    this.status = status;
  }
}

function toLoadError(e: unknown): LoadError {
  if (e instanceof ApiError) {
    return { kind: e.kind, message: e.message, status: e.status };
  }
  return {
    kind: 'network',
    message: e instanceof Error ? e.message : 'unknown error',
  };
}

async function getJson<T>(path: string): Promise<T> {
  let resp: Response;
  try {
    resp = await fetch(`${CONTROL_URL}${path}`);
  } catch (e) {
    throw new ApiError(
      'network',
      `cannot reach the control plane at ${CONTROL_URL} (${
        e instanceof Error ? e.message : 'network error'
      })`,
    );
  }
  if (!resp.ok) {
    throw new ApiError('http', `${path} returned HTTP ${resp.status}`, resp.status);
  }
  try {
    return (await resp.json()) as T;
  } catch {
    throw new ApiError('parse', `${path} returned a body that is not valid JSON`);
  }
}

export async function fetchTopology(): Promise<MeshTopology> {
  return getJson<MeshTopology>('/api/v1/topology');
}

export async function fetchAcls(): Promise<AclPolicyResponse> {
  return getJson<AclPolicyResponse>('/api/v1/acls');
}

// The control plane gates ACL changes behind KRONOS_ADMIN_TOKEN. The
// operator pastes it once per session in the ACL panel; it is kept in
// sessionStorage - deliberately NOT localStorage: this credential is
// a bearer secret, and a persistent copy would outlive the session
// and widen the blast radius of any script that ever runs in this
// origin. It is sent on mutations only.
const ADMIN_TOKEN_KEY = 'kronos-admin-token';

export function getAdminToken(): string {
  try {
    return sessionStorage.getItem(ADMIN_TOKEN_KEY) ?? '';
  } catch {
    return '';
  }
}

export function setAdminToken(token: string): void {
  try {
    if (token) {
      sessionStorage.setItem(ADMIN_TOKEN_KEY, token);
    } else {
      sessionStorage.removeItem(ADMIN_TOKEN_KEY);
    }
  } catch {
    // storage unavailable (private mode); mutations will surface the 401
  }
}

function authHeaders(): Record<string, string> {
  const t = getAdminToken();
  return t ? { Authorization: `Bearer ${t}` } : {};
}

export async function createAcl(rule: Omit<AclRule, 'id'>): Promise<AclRule> {
  const resp = await fetch(`${CONTROL_URL}/api/v1/acls`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: JSON.stringify({ ...rule, id: '' }),
  });
  if (!resp.ok) {
    throw new Error(
      resp.status === 401
        ? 'create ACL returned 401 - the control plane requires an admin token (set it in the ACL panel)'
        : `create ACL returned ${resp.status}`,
    );
  }
  return (await resp.json()) as AclRule;
}

export async function deleteAcl(id: string): Promise<void> {
  const resp = await fetch(`${CONTROL_URL}/api/v1/acls/${id}`, {
    method: 'DELETE',
    headers: { ...authHeaders() },
  });
  if (!resp.ok) {
    throw new Error(
      resp.status === 401
        ? 'delete ACL returned 401 - the control plane requires an admin token (set it in the ACL panel)'
        : `delete ACL returned ${resp.status}`,
    );
  }
}

// ---------------------------------------------------------------------------
// Demo dataset: rendered (clearly labelled) only when the control plane
// is unreachable, so the console never shows a blank or broken state.
// ---------------------------------------------------------------------------

const DEMO_NODES: PeerNode[] = [
  {
    node_id: 'demo-1', node_name: 'edge-blr-01',
    public_key: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
    fingerprint: '89eb0d6a8a691dae2cd15ed0369931ce0a949ecafa5c3f93f8121833646e15c3',
    virtual_ip: '100.64.0.10', endpoint: '203.0.113.10:51820', role: 'edge',
    online: true, nat_type: 'nat', ebpf_probe_passed: true,
    last_seen: '2026-10-22T00:00:00Z', tx_bytes: 912559104, rx_bytes: 1205866496,
    avg_latency_ms: 11.2,
  },
  {
    node_id: 'demo-2', node_name: 'db-mum-01',
    public_key: '2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e1fca7e58b2',
    fingerprint: 'cb2f5160fc1f7e05a55ef49d340b48da2e5a78099d53393351cd579dd42503d6',
    virtual_ip: '100.64.0.11', endpoint: '203.0.113.44:51820', role: 'database',
    online: true, nat_type: 'open', ebpf_probe_passed: true,
    last_seen: '2026-10-22T00:00:00Z', tx_bytes: 402653184, rx_bytes: 536870912,
    avg_latency_ms: 18.6,
  },
  {
    node_id: 'demo-3', node_name: 'cache-del-01',
    public_key: 'fcde2b2edba56bf408601fb721fe9b5c338d10ee429ea04fae5511b68fbf8fb9',
    fingerprint: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
    virtual_ip: '100.64.0.12', endpoint: '198.51.100.23:51820', role: 'cache',
    online: true, nat_type: 'nat', ebpf_probe_passed: false,
    last_seen: '2026-10-22T00:00:00Z', tx_bytes: 67108864, rx_bytes: 134217728,
    avg_latency_ms: 24.9,
  },
  {
    node_id: 'demo-4', node_name: 'gpu-hyd-01',
    public_key: 'a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3',
    fingerprint: '2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e1fca7e58b2',
    virtual_ip: '100.64.0.13', endpoint: '192.0.2.99:51820', role: 'compute',
    online: true, nat_type: 'nat', ebpf_probe_passed: true,
    last_seen: '2026-10-22T00:00:00Z', tx_bytes: 2147483648, rx_bytes: 1073741824,
    avg_latency_ms: 21.3,
  },
  {
    node_id: 'demo-5', node_name: 'iot-pnq-01',
    public_key: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    fingerprint: 'fcde2b2edba56bf408601fb721fe9b5c338d10ee429ea04fae5511b68fbf8fb9',
    virtual_ip: '100.64.0.14', endpoint: '198.51.100.77:51820', role: 'iot',
    online: false, nat_type: 'unknown', ebpf_probe_passed: false,
    last_seen: '2026-10-21T22:41:00Z', tx_bytes: 1048576, rx_bytes: 2097152,
    avg_latency_ms: 0,
  },
];

function demoData(): DashboardData {
  const online = DEMO_NODES.filter((n) => n.online);
  const links = [];
  for (let i = 0; i < online.length; i++) {
    for (let j = i + 1; j < online.length; j++) {
      links.push({
        a: online[i].virtual_ip,
        b: online[j].virtual_ip,
        latency_ms:
          (online[i].avg_latency_ms + online[j].avg_latency_ms) / 2,
        encrypted: true,
      });
    }
  }
  return {
    demo: true,
    topology: {
      nodes: DEMO_NODES,
      links,
      generated_at: new Date().toISOString(),
    },
    policy: {
      version: 3,
      rules: [
        { id: 'demo-r1', source_role: 'admin', dest_service: 'ssh', port: 22, action: 'ALLOW', priority: 10 },
        { id: 'demo-r2', source_role: 'edge', dest_service: 'postgres', port: 5432, action: 'ALLOW', priority: 20 },
        { id: 'demo-r3', source_role: 'iot', dest_service: 'postgres', port: 5432, action: 'DENY', priority: 30 },
      ],
    },
  };
}

/// The last payload that genuinely came from the control plane. A
/// failed refresh must never replace real data with demo values: the
/// operator keeps looking at the last truth, marked stale, with the
/// failure explained. Demo data appears only before the first
/// successful live load.
let lastGood: DashboardData | null = null;

/// Loads topology + policy from the control plane. On failure, returns
/// the last good live payload marked stale (with the classified error)
/// when one exists, and the labelled demo dataset only otherwise.
export async function loadDashboardData(): Promise<DashboardData> {
  try {
    const [topology, policy] = await Promise.all([
      fetchTopology(),
      fetchAcls(),
    ]);
    lastGood = { topology, policy, demo: false, fetchedAt: Date.now() };
    return lastGood;
  } catch (e) {
    const error = toLoadError(e);
    if (lastGood) {
      return { ...lastGood, stale: true, error };
    }
    return { ...demoData(), error };
  }
}

export function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.min(
    Math.floor(Math.log(bytes) / Math.log(1024)),
    units.length - 1,
  );
  return `${(bytes / Math.pow(1024, i)).toFixed(1)} ${units[i]}`;
}
