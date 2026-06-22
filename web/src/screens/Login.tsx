import { useState } from "react";
import { login, setToken, type Session } from "../api.ts";

export default function Login({ onAuthed }: { onAuthed: (session: Session) => void }) {
  const [email, setEmail] = useState("demo@palisade.local");
  const [password, setPassword] = useState("palisade");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const res = await login(email, password);
      setToken(res.token);
      onAuthed(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex h-full items-center justify-center bg-ink-900">
      <form onSubmit={onSubmit} className="w-80 rounded-xl border border-ink-600 bg-ink-800 p-6">
        <div className="mb-6 flex items-center gap-2">
          <span className="text-accent text-xl">⬡</span>
          <span className="text-lg font-semibold tracking-tight">Palisade</span>
        </div>
        <div className="space-y-3">
          <div>
            <label className="mb-1 block text-xs uppercase tracking-wide text-slate-500">
              Email
            </label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full rounded-lg border border-ink-600 bg-ink-900 px-3 py-1.5 text-sm outline-none placeholder:text-slate-600 focus:border-accent"
            />
          </div>
          <div>
            <label className="mb-1 block text-xs uppercase tracking-wide text-slate-500">
              Password
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full rounded-lg border border-ink-600 bg-ink-900 px-3 py-1.5 text-sm outline-none placeholder:text-slate-600 focus:border-accent"
            />
          </div>
        </div>
        {error && <div className="mt-3 text-sm text-red-400">{error}</div>}
        <button
          type="submit"
          disabled={busy}
          className="mt-5 w-full rounded-lg bg-accent px-3 py-1.5 text-sm font-medium text-white hover:bg-accent/90 disabled:opacity-50"
        >
          {busy ? "Signing in…" : "Sign in"}
        </button>
      </form>
    </div>
  );
}
