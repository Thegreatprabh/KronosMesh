import { useMemo } from 'react';
import { Lock } from 'lucide-react';
import type { MeshTopology, PeerNode } from '../types/mesh';

interface Props {
  topology: MeshTopology;
  selectedVip: string | null;
  onSelect: (vip: string) => void;
}

const WIDTH = 820;
const HEIGHT = 480;
const CX = WIDTH / 2;
const CY = HEIGHT / 2;
const RADIUS = 168;

interface PlacedNode {
  node: PeerNode;
  x: number;
  y: number;
}

/// Interactive SVG mesh map: nodes on a ring, animated tunnel lines
/// with latency labels, click-to-inspect.
export default function TopologyCanvas({ topology, selectedVip, onSelect }: Props) {
  const placed = useMemo<PlacedNode[]>(() => {
    const n = Math.max(topology.nodes.length, 1);
    return topology.nodes.map((node, i) => {
      const angle = (2 * Math.PI * i) / n - Math.PI / 2;
      return {
        node,
        x: CX + RADIUS * Math.cos(angle),
        y: CY + RADIUS * Math.sin(angle),
      };
    });
  }, [topology.nodes]);

  const byVip = useMemo(() => {
    const map = new Map<string, PlacedNode>();
    for (const p of placed) map.set(p.node.virtual_ip, p);
    return map;
  }, [placed]);

  return (
    <div className="rounded-xl border border-edge bg-panel p-4">
      <div className="mb-2 flex items-center justify-between">
        <h2 className="flex items-center gap-2 text-sm font-semibold uppercase tracking-wider text-slate-300">
          <Lock size={15} className="text-neon" /> Mesh Topology
        </h2>
        <span className="font-mono text-xs text-slate-500">
          {topology.links.length} encrypted tunnels
        </span>
      </div>
      <svg viewBox={`0 0 ${WIDTH} ${HEIGHT}`} className="w-full">
        {topology.links.map((link, i) => {
          const a = byVip.get(link.a);
          const b = byVip.get(link.b);
          if (!a || !b) return null;
          const mx = (a.x + b.x) / 2;
          const my = (a.y + b.y) / 2;
          const touchesSelection =
            selectedVip !== null &&
            (link.a === selectedVip || link.b === selectedVip);
          return (
            <g key={`${link.a}-${link.b}-${i}`}>
              <line
                x1={a.x} y1={a.y} x2={b.x} y2={b.y}
                stroke={touchesSelection ? '#22d3ee' : '#2dd4bf'}
                strokeOpacity={touchesSelection ? 0.9 : 0.35}
                strokeWidth={touchesSelection ? 2 : 1.2}
                className="tunnel-line"
              />
              <text
                x={mx} y={my - 4}
                textAnchor="middle"
                className="fill-slate-500 font-mono"
                fontSize="10"
              >
                {link.latency_ms.toFixed(1)} ms
              </text>
            </g>
          );
        })}
        {placed.map(({ node, x, y }) => {
          const selected = node.virtual_ip === selectedVip;
          return (
            <g
              key={node.node_id}
              onClick={() => onSelect(node.virtual_ip)}
              className="cursor-pointer"
            >
              <circle
                cx={x} cy={y} r={selected ? 30 : 25}
                fill={node.online ? '#0e2233' : '#1a1f2e'}
                stroke={selected ? '#22d3ee' : node.online ? '#34d399' : '#475569'}
                strokeWidth={selected ? 2.5 : 1.5}
                className={node.online ? 'node-pulse' : undefined}
              />
              <text
                x={x} y={y + 1}
                textAnchor="middle"
                className="fill-slate-100 font-mono"
                fontSize="10"
              >
                {node.virtual_ip.split('.')[3]}
              </text>
              <text
                x={x} y={y + 44}
                textAnchor="middle"
                className="fill-slate-300"
                fontSize="12"
                fontWeight={600}
              >
                {node.node_name}
              </text>
              <text
                x={x} y={y + 58}
                textAnchor="middle"
                className="fill-slate-500 font-mono"
                fontSize="10"
              >
                {node.virtual_ip} · {node.role}
              </text>
            </g>
          );
        })}
        {placed.length === 0 && (
          <text x={CX} y={CY} textAnchor="middle" className="fill-slate-500" fontSize="14">
            No nodes registered yet
          </text>
        )}
      </svg>
    </div>
  );
}
