import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  Globe,
  Network,
  RefreshCw,
  Server,
  Shield,
  Terminal,
} from 'lucide-react';
import TopologyCanvas from './components/TopologyCanvas';
import NodeTable from './components/NodeTable';
import AclPolicyEditor from './components/AclPolicyEditor';
import CryptographicInspector from './components/CryptographicInspector';
import {
  controlUrl,
  createAcl,
  deleteAcl,
  formatBytes,
  loadDashboardData,
} from './lib/api';
import type { AclRule, DashboardData, PeerNode } from './types/mesh';

const REFRESH_MS = 3000;

function StatCard(props: {
  icon: React.ReactNode;
  label: string;
  value: string;
  sub: string;
}) {
  return (
    <div className="rounded-xl border border-edge bg-panel p-4">
      <div className="flex items-center gap-2 text-xs uppercase tracking-wider text-slate-500">
        {props.icon}
        {props.label}
      </div>
      <div className="mt-1.5 font-mono text-2xl text-slate-50">{props.value}</div>
      <div className="text-xs text-slate-500">{props.sub}</div>
    </div>
  );
}

export default function App() {
  const [data, setData] = useState<DashboardData | null>(null);
  const [selectedVip, setSelectedVip] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const refresh = useCallback(async () => {
    const next = await loadDashboardData();
    setData(next);
    setSelectedVip((prev) => {
      if (prev && next.topology.nodes.some((n) => n.virtual_ip === prev)) {
        return prev;
      }
      const firstOnline = next.topology.nodes.find((n) => n.online);
      return (firstOnline ?? next.topology.nodes[0])?.virtual_ip ?? null;
    });
  }, []);

  useEffect(() => {
    void refresh();
    const id = setInterval(() => void refresh(), REFRESH_MS);
    return () => clearInterval(id);
  }, [refresh]);

  const selected: PeerNode | null = useMemo(() => {
    if (!data || !selectedVip) return null;
    return (
      data.topology.nodes.find((n) => n.virtual_ip === selectedVip) ?? null
    );
  }, [data, selectedVip]);

  const roles = useMemo(() => {
    if (!data) return ['admin'];
    const set = new Set<string>(['admin']);
    for (const n of data.topology.nodes) set.add(n.role);
    return [...set].sort();
  }, [data]);

  const stats = useMemo(() => {
    if (!data) return { online: 0, total: 0, traffic: 0, latency: 0 };
    const nodes = data.topology.nodes;
    const onlineNodes = nodes.filter((n) => n.online);
    const lat = onlineNodes.filter((n) => n.avg_latency_ms > 0);
    return {
      online: onlineNodes.length,
      total: nodes.length,
      traffic: nodes.reduce((sum, n) => sum + n.tx_bytes + n.rx_bytes, 0),
      latency:
        lat.length === 0
          ? 0
          : lat.reduce((sum, n) => sum + n.avg_latency_ms, 0) / lat.length,
    };
  }, [data]);

  const topTalkers = useMemo(() => {
    if (!data) return [];
    const sorted = [...data.topology.nodes].sort(
      (a, b) => b.tx_bytes + b.rx_bytes - (a.tx_bytes + a.rx_bytes),
    );
    const max = Math.max(
      1,
      ...sorted.map((n) => n.tx_bytes + n.rx_bytes),
    );
    return sorted.slice(0, 4).map((n) => ({
      node: n,
      pct: ((n.tx_bytes + n.rx_bytes) / max) * 100,
    }));
  }, [data]);

  const handleCreateAcl = useCallback(
    async (rule: Omit<AclRule, 'id'>) => {
      await createAcl(rule);
      await refresh();
    },
    [refresh],
  );

  const handleDeleteAcl = useCallback(
    async (id: string) => {
      await deleteAcl(id);
      await refresh();
    },
    [refresh],
  );

  const cliConfig = useMemo(() => {
    if (!selected) return '';
    return [
      `# kronos.toml — provision ${selected.node_name}`,
      `node_name = "${selected.node_name}"`,
      `role = "${selected.role}"`,
      `control_url = "${controlUrl()}"`,
      `listen_port = 51820`,
      ``,
      `# join the mesh`,
      `$ kronos-daemon up --config kronos.toml`,
      `$ kronos-daemon status`,
      `$ kronos-daemon peers`,
    ].join('\n');
  }, [selected]);

  const copyConfig = async () => {
    try {
      await navigator.clipboard.writeText(cliConfig);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      setCopied(false);
    }
  };

  return (
    <div className="min-h-screen bg-abyss">
      <header className="border-b border-edge bg-panel/60">
        <div className="mx-auto flex max-w-7xl items-center gap-3 px-4 py-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-neon/10 text-neon">
            <Shield size={22} />
          </div>
          <div>
            <h1 className="text-lg font-bold tracking-wide text-slate-50">
              KRONOS<span className="text-neon">MESH</span>
            </h1>
            <p className="text-xs text-slate-500">
              Zero-Trust Mesh Console · Noise_IK · X25519 · ChaCha20-Poly1305
            </p>
          </div>
          <div className="ml-auto flex items-center gap-3">
            {data?.demo && (
              <span className="flex items-center gap-1.5 rounded bg-amber/10 px-2 py-1 text-xs font-semibold text-amber">
                <AlertTriangle size={13} /> DEMO DATA
              </span>
            )}
            {data?.stale && (
              <span className="flex items-center gap-1.5 rounded bg-amber/10 px-2 py-1 text-xs font-semibold text-amber">
                <AlertTriangle size={13} /> STALE
              </span>
            )}
            {data && !data.demo && !data.stale && (
              <span className="flex items-center gap-1.5 rounded bg-neon/10 px-2 py-1 text-xs font-semibold text-neon">
                <span className="h-1.5 w-1.5 rounded-full bg-neon" /> LIVE
              </span>
            )}
            <span className="hidden font-mono text-xs text-slate-500 md:block">
              {controlUrl()}
            </span>
            <button
              onClick={() => void refresh()}
              className="flex items-center gap-1.5 rounded-lg border border-edge px-3 py-1.5 text-xs text-slate-300 transition-colors hover:border-neon hover:text-neon"
            >
              <RefreshCw size={13} /> Refresh
            </button>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-7xl space-y-4 px-4 py-4">
        {data?.demo && (
          <div className="flex items-start gap-2 rounded-xl border border-amber/30 bg-amber/5 p-3 text-sm text-amber">
            <AlertTriangle size={16} className="mt-0.5 shrink-0" />
            <span>
              Live data unavailable
              {data.error && (
                <>
                  {' '}
                  — {data.error.kind} error: {data.error.message}
                </>
              )}{' '}
              — showing the built-in demo dataset; nothing on this page is
              real telemetry. Start the plane with{' '}
              <code className="font-mono">docker compose up</code> or{' '}
              <code className="font-mono">go run ./control-plane</code> for
              live data.
            </span>
          </div>
        )}

        {data?.stale && (
          <div className="flex items-start gap-2 rounded-xl border border-amber/30 bg-amber/5 p-3 text-sm text-amber">
            <AlertTriangle size={16} className="mt-0.5 shrink-0" />
            <span>
              Refresh failed
              {data.error && (
                <>
                  {' '}
                  ({data.error.kind}
                  {data.error.status ? ` ${data.error.status}` : ''}:{' '}
                  {data.error.message})
                </>
              )}{' '}
              — showing the last live data
              {data.fetchedAt && (
                <> from {new Date(data.fetchedAt).toLocaleTimeString()}</>
              )}
              . Retrying automatically.
            </span>
          </div>
        )}

        <section className="grid grid-cols-2 gap-4 lg:grid-cols-4">
          <StatCard
            icon={<Server size={13} />}
            label="Nodes online"
            value={`${stats.online}/${stats.total}`}
            sub="registered mesh members"
          />
          <StatCard
            icon={<Network size={13} />}
            label="Encrypted tunnels"
            value={String(data?.topology.links.length ?? 0)}
            sub="Noise_IK sessions (logical mesh)"
          />
          <StatCard
            icon={<Activity size={13} />}
            label="Mesh traffic"
            value={formatBytes(stats.traffic)}
            sub="cumulative TX + RX, all nodes"
          />
          <StatCard
            icon={<Globe size={13} />}
            label="Avg latency"
            value={stats.latency ? `${stats.latency.toFixed(1)} ms` : '—'}
            sub="across online nodes"
          />
        </section>

        {data ? (
          <>
            <section className="grid gap-4 lg:grid-cols-5">
              <div className="lg:col-span-3">
                <TopologyCanvas
                  topology={data.topology}
                  selectedVip={selectedVip}
                  onSelect={setSelectedVip}
                />
              </div>
              <div className="lg:col-span-2">
                <CryptographicInspector node={selected} />
              </div>
            </section>

            <section className="rounded-xl border border-edge bg-panel p-4">
              <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold uppercase tracking-wider text-slate-300">
                <Activity size={15} className="text-neon" /> Packet Throughput — Top Talkers
              </h2>
              <div className="space-y-2.5">
                {topTalkers.map(({ node, pct }) => (
                  <div key={node.node_id} className="flex items-center gap-3">
                    <span className="w-28 truncate text-sm text-slate-300">
                      {node.node_name}
                    </span>
                    <div className="h-2 flex-1 overflow-hidden rounded bg-edge">
                      <div
                        className="h-full rounded bg-gradient-to-r from-cyan-500 to-emerald-400 transition-all duration-500"
                        style={{ width: `${pct}%` }}
                      />
                    </div>
                    <span className="w-24 text-right font-mono text-xs text-slate-400">
                      {formatBytes(node.tx_bytes + node.rx_bytes)}
                    </span>
                  </div>
                ))}
                {topTalkers.length === 0 && (
                  <p className="text-sm text-slate-500">No traffic recorded yet.</p>
                )}
              </div>
            </section>

            <NodeTable
              nodes={data.topology.nodes}
              selectedVip={selectedVip}
              onSelect={setSelectedVip}
            />

            <AclPolicyEditor
              policy={data.policy}
              roles={roles}
              readOnly={data.demo}
              onCreate={handleCreateAcl}
              onDelete={handleDeleteAcl}
            />

            <section className="rounded-xl border border-edge bg-panel p-4">
              <div className="mb-2 flex items-center justify-between">
                <h2 className="flex items-center gap-2 text-sm font-semibold uppercase tracking-wider text-slate-300">
                  <Terminal size={15} className="text-neon" /> CLI Config Generator
                </h2>
                <button
                  onClick={() => void copyConfig()}
                  disabled={!selected}
                  className="rounded-lg border border-edge px-3 py-1.5 text-xs text-slate-300 transition-colors hover:border-neon hover:text-neon disabled:opacity-40"
                >
                  {copied ? 'Copied' : 'Copy'}
                </button>
              </div>
              <pre className="overflow-x-auto rounded-lg border border-edge bg-abyss p-3 font-mono text-xs leading-relaxed text-slate-300">
                {selected
                  ? cliConfig
                  : 'Select a node to generate its provisioning config.'}
              </pre>
            </section>
          </>
        ) : (
          <p className="py-16 text-center text-slate-500">
            Connecting to the control plane…
          </p>
        )}

        <footer className="pb-4 pt-2 text-center text-xs text-slate-600">
          KronosMesh — open-source zero-trust mesh networking. Every packet
          sealed with ChaCha20-Poly1305; every node verified by its
          BLAKE2b fingerprint.
        </footer>
      </main>
    </div>
  );
}
