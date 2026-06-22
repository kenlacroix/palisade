import type { Severity } from "./data.ts";

const SEV_COLOR: Record<Severity, string> = {
  critical: "text-red-400",
  high: "text-amber-400",
  medium: "text-yellow-400",
  low: "text-sky-400",
  info: "text-slate-400",
};

const SEV_BG: Record<Severity, string> = {
  critical: "bg-red-500/15 text-red-300 ring-red-500/30",
  high: "bg-amber-500/15 text-amber-300 ring-amber-500/30",
  medium: "bg-yellow-500/15 text-yellow-300 ring-yellow-500/30",
  low: "bg-sky-500/15 text-sky-300 ring-sky-500/30",
  info: "bg-slate-500/15 text-slate-300 ring-slate-500/30",
};

export function Dot({ severity }: { severity: Severity }) {
  return <span className={`${SEV_COLOR[severity]} text-lg leading-none`}>●</span>;
}

export function SevBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={`inline-flex items-center rounded px-2 py-0.5 text-xs font-medium uppercase tracking-wide ring-1 ${SEV_BG[severity]}`}
    >
      {severity}
    </span>
  );
}

export function Card({
  children,
  className = "",
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={`rounded-xl border border-ink-600 bg-ink-800 ${className}`}>{children}</div>
  );
}
