import { useEffect, useState } from 'react';
import { Key, Lock, Trash2 } from 'lucide-react';
import type { PeerNode } from '../types/mesh';
import { formatBytes } from '../lib/api';

interface Props {
  node: PeerNode | null;
  /// Revokes the node's membership via the control plane
  /// (admin-only). Absent in demo mode, where there is nothing
  /// real to revoke.
  onRevoke?: (node: PeerNode) => Promise<void>;
}

const SUITE: Array<[string, string]> = [
  ['Handshake', 'Noise_IK'],
  ['Key exchange', 'X25519 (Curve25519 ECDH)'],
  ['Cipher', 'ChaCha20-Poly1305 AEAD'],
  ['Hash / HKDF', 'BLAKE2s'],
  ['Identity fingerprint', 'BLAKE2b-256'],
  ['Replay protection', '2048-packet sliding window'],
];

/// Cryptographic inspector: the selected node's identity material and
/// the protocol suite its sessions run, with live traffic counters.
export default function CryptographicInspector({ node, onRevoke }: Props) {
  const [error, setError] = useState<string | null>(null);
  const [revoking, setRevoking] = useState(false);

  useEffect(() => {
    setError(null);
  }, [node?.node_id]);

  const handleRevoke = async () => {
    if (!node || !onRevoke) return;
    if (
      !window.confirm(
        `Revoke ${node.node_name} (${node.virtual_ip})? Its node token stops working immediately, and the node must be re-provisioned (admin or enrollment token) to rejoin the mesh.`,
      )
    ) {
      return;
    }
    setError(null);
    setRevoking(true);
    try {
      await onRevoke(node);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'revoke node failed');
    } finally {
      setRevoking(false);
    }
  };

  return (
    <div className="rounded-xl border border-edge bg-panel p-4">
      <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold uppercase tracking-wider text-slate-300">
        <Key size={15} className="text-neon" /> Cryptographic Inspector
      </h2>
      {node === null ? (
        <p className="py-8 text-center text-sm text-slate-500">
          Select a node in the topology or inventory to inspect its
          cryptographic identity.
        </p>
      ) : (
        <div className="space-y-4">
          <div>
            <div className="flex items-center justify-between">
              <span className="font-semibold text-slate-100">{node.node_name}</span>
              <span
                className={`rounded px-2 py-0.5 font-mono text-xs ${
                  node.online
                    ? 'bg-mint/10 text-mint'
                    : 'bg-danger/10 text-danger'
                }`}
              >
                {node.online ? 'SESSIONS ACTIVE' : 'OFFLINE'}
              </span>
            </div>
            <p className="mt-1 font-mono text-xs text-slate-500">
              {node.virtual_ip} · {node.endpoint} · NAT {node.nat_type} ·{' '}
              {node.ebpf_probe_passed ? 'XDP probe passed (capability only)' : 'XDP probe not passed'} · kernel fast path inactive — userspace relay
            </p>
          </div>

          <div>
            <label className="mb-1 block text-xs uppercase tracking-wider text-slate-500">
              Public key (X25519)
            </label>
            <p className="break-all rounded-lg border border-edge bg-abyss p-2.5 font-mono text-[11px] leading-relaxed text-slate-300">
              {node.public_key}
            </p>
          </div>
          <div>
            <label className="mb-1 block text-xs uppercase tracking-wider text-slate-500">
              Fingerprint (BLAKE2b-256)
            </label>
            <p className="break-all rounded-lg border border-edge bg-abyss p-2.5 font-mono text-[11px] leading-relaxed text-neon">
              {node.fingerprint}
            </p>
          </div>

          <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
            {SUITE.map(([k, v]) => (
              <div key={k} className="flex items-baseline justify-between gap-2 border-b border-edge/50 pb-1.5">
                <dt className="flex items-center gap-1.5 text-xs text-slate-500">
                  <Lock size={11} className="text-slate-600" /> {k}
                </dt>
                <dd className="text-right font-mono text-xs text-slate-200">{v}</dd>
              </div>
            ))}
          </dl>

          <div className="grid grid-cols-3 gap-3 text-center">
            <div className="rounded-lg border border-edge bg-abyss p-2.5">
              <div className="font-mono text-sm text-slate-100">{formatBytes(node.tx_bytes)}</div>
              <div className="text-[11px] uppercase tracking-wider text-slate-500">sent</div>
            </div>
            <div className="rounded-lg border border-edge bg-abyss p-2.5">
              <div className="font-mono text-sm text-slate-100">{formatBytes(node.rx_bytes)}</div>
              <div className="text-[11px] uppercase tracking-wider text-slate-500">received</div>
            </div>
            <div className="rounded-lg border border-edge bg-abyss p-2.5">
              <div className="font-mono text-sm text-slate-100">
                {node.online ? `${node.avg_latency_ms.toFixed(1)} ms` : '—'}
              </div>
              <div className="text-[11px] uppercase tracking-wider text-slate-500">avg latency</div>
            </div>
          </div>
          <p className="text-xs leading-relaxed text-slate-500">
            Session keys are derived per Noise_IK handshake and never
            leave the node. Rekeying happens on a fresh handshake; the
            daemon rotates its ephemeral keypair every session.
          </p>

          {onRevoke && (
            <div className="border-t border-edge/60 pt-3">
              <button
                onClick={() => void handleRevoke()}
                disabled={revoking}
                className="flex items-center gap-1.5 rounded-lg border border-danger/40 px-3 py-1.5 text-xs font-medium text-danger transition-colors hover:bg-danger/10 disabled:opacity-40"
              >
                <Trash2 size={13} /> {revoking ? 'Revoking…' : 'Revoke node'}
              </button>
              <p className="mt-1.5 text-[11px] leading-relaxed text-slate-500">
                Removes this node from the mesh: its token is
                invalidated at once and its virtual IP returns to the
                pool. Requires the operator admin token.
              </p>
              {error && <p className="mt-2 text-xs text-danger">{error}</p>}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
