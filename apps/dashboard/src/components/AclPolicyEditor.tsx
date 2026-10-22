import { useMemo, useState } from 'react';
import { CheckCircle2, Plus, Shield, Trash2 } from 'lucide-react';
import type { AclPolicyResponse, AclRule } from '../types/mesh';
import { getAdminToken, setAdminToken } from '../lib/api';

interface Props {
  policy: AclPolicyResponse;
  roles: string[];
  readOnly: boolean;
  onCreate: (rule: Omit<AclRule, 'id'>) => Promise<void>;
  onDelete: (id: string) => Promise<void>;
}

/// Zero-trust policy builder: Source Role -> Destination Service : Port
/// with ALLOW/DENY, a live JSON preview of the draft rule, and the
/// current policy exactly as the control plane serves it.
export default function AclPolicyEditor({ policy, roles, readOnly, onCreate, onDelete }: Props) {
  const [sourceRole, setSourceRole] = useState(roles[0] ?? 'admin');
  const [destService, setDestService] = useState('ssh');
  const [port, setPort] = useState(22);
  const [action, setAction] = useState('ALLOW');
  const [priority, setPriority] = useState(50);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [token, setToken] = useState(() => getAdminToken());
  const [tokenSaved, setTokenSaved] = useState(false);

  const saveToken = () => {
    setAdminToken(token.trim());
    setTokenSaved(true);
    window.setTimeout(() => setTokenSaved(false), 2000);
  };

  const draft: Omit<AclRule, 'id'> = useMemo(
    () => ({
      source_role: sourceRole,
      dest_service: destService,
      port,
      action,
      priority,
    }),
    [sourceRole, destService, port, action, priority],
  );

  const sorted = useMemo(
    () => [...policy.rules].sort((a, b) => a.priority - b.priority),
    [policy.rules],
  );

  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      await onCreate(draft);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'create failed');
    } finally {
      setBusy(false);
    }
  };

  const inputCls =
    'w-full rounded-lg border border-edge bg-abyss px-3 py-2 text-sm text-slate-100 outline-none focus:border-neon';
  const labelCls = 'mb-1 block text-xs uppercase tracking-wider text-slate-500';

  return (
    <div className="rounded-xl border border-edge bg-panel p-4">
      <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold uppercase tracking-wider text-slate-300">
        <Shield size={15} className="text-neon" /> Zero-Trust ACL Matrix
        <span className="ml-auto font-mono text-xs normal-case text-slate-500">
          policy v{policy.version}
        </span>
      </h2>
      {!readOnly && (
        <div className="mb-3 flex items-end gap-2">
          <div className="flex-1">
            <label className={labelCls}>Admin token</label>
            <input
              type="password"
              value={token}
              onChange={(e) => setToken(e.target.value)}
              placeholder="Required when the control plane sets KRONOS_ADMIN_TOKEN"
              className={inputCls}
            />
          </div>
          <button
            onClick={saveToken}
            className="rounded-lg border border-edge bg-abyss px-3 py-2 text-sm text-slate-200 transition-colors hover:border-neon"
          >
            {tokenSaved ? 'Saved' : 'Save token'}
          </button>
        </div>
      )}

      <div className="grid gap-4 lg:grid-cols-2">
        <div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className={labelCls}>Source role</label>
              <input
                className={inputCls}
                value={sourceRole}
                onChange={(e) => setSourceRole(e.target.value)}
                list="kronos-roles"
                disabled={readOnly}
              />
              <datalist id="kronos-roles">
                {roles.map((r) => (
                  <option key={r} value={r} />
                ))}
              </datalist>
            </div>
            <div>
              <label className={labelCls}>Destination service</label>
              <input
                className={inputCls}
                value={destService}
                onChange={(e) => setDestService(e.target.value)}
                disabled={readOnly}
              />
            </div>
            <div>
              <label className={labelCls}>Port (0 = any)</label>
              <input
                className={inputCls}
                type="number"
                min={0}
                max={65535}
                value={port}
                onChange={(e) => setPort(Number(e.target.value))}
                disabled={readOnly}
              />
            </div>
            <div>
              <label className={labelCls}>Priority</label>
              <input
                className={inputCls}
                type="number"
                value={priority}
                onChange={(e) => setPriority(Number(e.target.value))}
                disabled={readOnly}
              />
            </div>
            <div className="col-span-2">
              <label className={labelCls}>Action</label>
              <div className="flex gap-2">
                {['ALLOW', 'DENY'].map((a) => (
                  <button
                    key={a}
                    onClick={() => setAction(a)}
                    disabled={readOnly}
                    className={`flex-1 rounded-lg border px-3 py-2 text-sm font-semibold ${
                      action === a
                        ? a === 'ALLOW'
                          ? 'border-mint bg-mint/10 text-mint'
                          : 'border-danger bg-danger/10 text-danger'
                        : 'border-edge bg-abyss text-slate-400'
                    }`}
                  >
                    {a}
                  </button>
                ))}
              </div>
            </div>
          </div>
          <button
            onClick={submit}
            disabled={readOnly || busy}
            className="mt-3 flex w-full items-center justify-center gap-2 rounded-lg bg-neon px-4 py-2 text-sm font-semibold text-abyss transition-opacity disabled:opacity-40"
          >
            <Plus size={15} /> {busy ? 'Adding…' : 'Add rule'}
          </button>
          {readOnly && (
            <p className="mt-2 text-xs text-amber">
              Demo mode — connect the control plane to edit policy.
            </p>
          )}
          {error && <p className="mt-2 text-xs text-danger">{error}</p>}
          <label className={`${labelCls} mt-4`}>Live JSON preview</label>
          <pre className="overflow-x-auto rounded-lg border border-edge bg-abyss p-3 font-mono text-xs text-mint">
            {JSON.stringify(draft, null, 2)}
          </pre>
        </div>

        <div className="space-y-2">
          {sorted.map((rule) => (
            <div
              key={rule.id}
              className="flex items-center gap-3 rounded-lg border border-edge bg-abyss px-3 py-2.5"
            >
              <CheckCircle2
                size={16}
                className={rule.action === 'ALLOW' ? 'text-mint' : 'text-danger'}
              />
              <div className="min-w-0 flex-1 font-mono text-xs text-slate-300">
                <span className="text-slate-100">{rule.source_role}</span>
                {' -> '}
                <span className="text-neon">{rule.dest_service}:{rule.port}</span>
                <span
                  className={`ml-2 rounded px-1.5 py-0.5 font-semibold ${
                    rule.action === 'ALLOW'
                      ? 'bg-mint/10 text-mint'
                      : 'bg-danger/10 text-danger'
                  }`}
                >
                  {rule.action}
                </span>
                <span className="ml-2 text-slate-500">prio {rule.priority}</span>
              </div>
              <button
                onClick={() => void onDelete(rule.id)}
                disabled={readOnly}
                className="text-slate-500 transition-colors hover:text-danger disabled:opacity-40"
                aria-label={`Delete rule ${rule.id}`}
              >
                <Trash2 size={15} />
              </button>
            </div>
          ))}
          {sorted.length === 0 && (
            <p className="py-6 text-center text-sm text-slate-500">
              No policy rules — default posture is deny-all.
            </p>
          )}
        </div>
      </div>
    </div>
  );
}
