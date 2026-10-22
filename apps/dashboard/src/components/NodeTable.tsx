import { Cpu, Server } from 'lucide-react';
import type { PeerNode } from '../types/mesh';
import { formatBytes } from '../lib/api';

interface Props {
  nodes: PeerNode[];
  selectedVip: string | null;
  onSelect: (vip: string) => void;
}

/// Real-time peer inventory: keys, virtual IPs, NAT type, eBPF status,
/// and traffic counters straight from control-plane heartbeats.
export default function NodeTable({ nodes, selectedVip, onSelect }: Props) {
  return (
    <div className="rounded-xl border border-edge bg-panel p-4">
      <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold uppercase tracking-wider text-slate-300">
        <Server size={15} className="text-neon" /> Node Inventory
      </h2>
      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm">
          <thead>
            <tr className="border-b border-edge text-xs uppercase tracking-wider text-slate-500">
              <th className="py-2 pr-3">Node</th>
              <th className="py-2 pr-3">Virtual IP</th>
              <th className="py-2 pr-3">Endpoint</th>
              <th className="py-2 pr-3">Role</th>
              <th className="py-2 pr-3">NAT</th>
              <th className="py-2 pr-3">eBPF</th>
              <th className="py-2 pr-3">TX / RX</th>
              <th className="py-2">Latency</th>
            </tr>
          </thead>
          <tbody>
            {nodes.map((node) => (
              <tr
                key={node.node_id}
                onClick={() => onSelect(node.virtual_ip)}
                className={`cursor-pointer border-b border-edge/50 transition-colors hover:bg-white/5 ${
                  node.virtual_ip === selectedVip ? 'bg-cyan-400/5' : ''
                }`}
              >
                <td className="py-2.5 pr-3">
                  <span
                    className={`mr-2 inline-block h-2 w-2 rounded-full ${
                      node.online ? 'bg-mint' : 'bg-danger'
                    }`}
                  />
                  <span className="font-medium text-slate-100">{node.node_name}</span>
                  <div className="font-mono text-[11px] text-slate-500">
                    {node.fingerprint.slice(0, 16)}…
                  </div>
                </td>
                <td className="py-2.5 pr-3 font-mono text-neon">{node.virtual_ip}</td>
                <td className="py-2.5 pr-3 font-mono text-xs text-slate-400">{node.endpoint}</td>
                <td className="py-2.5 pr-3 text-slate-300">{node.role}</td>
                <td className="py-2.5 pr-3 text-slate-400">{node.nat_type}</td>
                <td className="py-2.5 pr-3">
                  {node.ebpf_enabled ? (
                    <span className="inline-flex items-center gap-1 rounded bg-mint/10 px-1.5 py-0.5 text-xs text-mint">
                      <Cpu size={12} /> XDP
                    </span>
                  ) : (
                    <span className="rounded bg-slate-500/10 px-1.5 py-0.5 text-xs text-slate-400">
                      userspace
                    </span>
                  )}
                </td>
                <td className="py-2.5 pr-3 font-mono text-xs text-slate-300">
                  {formatBytes(node.tx_bytes)} / {formatBytes(node.rx_bytes)}
                </td>
                <td className="py-2.5 font-mono text-xs text-slate-300">
                  {node.online ? `${node.avg_latency_ms.toFixed(1)} ms` : '—'}
                </td>
              </tr>
            ))}
            {nodes.length === 0 && (
              <tr>
                <td colSpan={8} className="py-6 text-center text-slate-500">
                  No nodes yet — start a daemon with `kronos-daemon up`.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
