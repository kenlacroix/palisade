import { useState } from "react";
import {
  addMember,
  fetchMembers,
  relativeTime,
  removeMember,
  updateMemberRole,
  useApi,
  type Role,
} from "../api.ts";
import { Card } from "../ui.tsx";

const ROLES: Role[] = ["owner", "admin", "member", "viewer"];

export default function Members() {
  const { data, error, loading, refetch } = useApi(fetchMembers, []);
  const rows = data?.members ?? [];

  const [email, setEmail] = useState("");
  const [role, setRole] = useState<Role>("member");
  const [busy, setBusy] = useState(false);
  const [addError, setAddError] = useState<string | null>(null);
  const [rowError, setRowError] = useState<string | null>(null);

  const onAdd = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setAddError(null);
    try {
      await addMember(email, role);
      setEmail("");
      refetch();
    } catch (err) {
      setAddError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const onRole = async (userId: string, next: Role) => {
    setRowError(null);
    try {
      await updateMemberRole(userId, next);
      refetch();
    } catch (err) {
      setRowError(err instanceof Error ? err.message : String(err));
    }
  };

  const onRemove = async (userId: string) => {
    setRowError(null);
    try {
      await removeMember(userId);
      refetch();
    } catch (err) {
      setRowError(err instanceof Error ? err.message : String(err));
    }
  };

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Members</h1>
        <p className="text-sm text-slate-500">Manage who belongs to this org and their role.</p>
      </div>

      <Card>
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-ink-700 text-left text-xs uppercase tracking-wide text-slate-500">
              <th className="px-4 py-3 font-medium">Email</th>
              <th className="px-4 py-3 font-medium">Name</th>
              <th className="px-4 py-3 font-medium">Role</th>
              <th className="px-4 py-3 font-medium">Joined</th>
              <th className="px-4 py-3 font-medium" />
            </tr>
          </thead>
          <tbody className="divide-y divide-ink-700">
            {rows.map((m) => (
              <tr key={m.user_id} className="hover:bg-ink-700/50">
                <td className="px-4 py-3 text-slate-200">{m.email}</td>
                <td className="px-4 py-3 text-slate-300">{m.name}</td>
                <td className="px-4 py-3">
                  <select
                    value={m.role}
                    onChange={(e) => onRole(m.user_id, e.target.value as Role)}
                    aria-label={`role for ${m.email}`}
                    className="rounded-lg border border-ink-600 bg-ink-800 px-3 py-1.5 text-sm outline-none focus:border-accent"
                  >
                    {ROLES.map((r) => (
                      <option key={r} value={r}>
                        {r}
                      </option>
                    ))}
                  </select>
                </td>
                <td className="px-4 py-3 text-slate-500" title={m.created_at ?? undefined}>
                  {relativeTime(m.created_at)}
                </td>
                <td className="px-4 py-3 text-right">
                  <button
                    onClick={() => onRemove(m.user_id)}
                    className="text-slate-500 hover:text-red-400"
                  >
                    remove
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {error ? (
          <div className="px-4 py-6 text-center text-sm text-red-400">Failed to load members: {error}</div>
        ) : rows.length === 0 ? (
          <div className="px-4 py-6 text-center text-sm text-slate-500">
            {loading ? "Loading members…" : "No members yet."}
          </div>
        ) : null}
        {rowError && <div className="px-4 pb-4 text-sm text-red-400">{rowError}</div>}
      </Card>

      <Card className="p-5">
        <div className="mb-3 text-xs font-semibold uppercase tracking-wide text-slate-400">Add member</div>
        <form onSubmit={onAdd} className="space-y-3">
          <div className="flex items-center gap-2">
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="email"
              required
              className="flex-1 rounded-lg border border-ink-600 bg-ink-800 px-3 py-1.5 text-sm outline-none placeholder:text-slate-600 focus:border-accent"
            />
            <select
              value={role}
              onChange={(e) => setRole(e.target.value as Role)}
              aria-label="role for new member"
              className="rounded-lg border border-ink-600 bg-ink-800 px-3 py-1.5 text-sm outline-none focus:border-accent"
            >
              {ROLES.map((r) => (
                <option key={r} value={r}>
                  {r}
                </option>
              ))}
            </select>
            <button
              type="submit"
              disabled={busy}
              className="rounded-lg bg-accent px-3 py-1.5 text-sm font-medium text-white hover:bg-accent/90 disabled:opacity-50"
            >
              {busy ? "Adding…" : "Add member"}
            </button>
          </div>
          {addError && <div className="text-sm text-red-400">{addError}</div>}
        </form>
      </Card>
    </div>
  );
}
