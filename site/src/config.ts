export const SITE = {
  name: "Palisade",
  domain: "trypalisade.dev",
  url: "https://trypalisade.dev",
  appUrl: "https://app.trypalisade.dev",
  repoUrl: "https://github.com/kenlacroix/palisade",
  authorUrl: "https://kennethlacroix.me",
  authorName: "Kenneth Lacroix",
  tagline: "Attack-surface monitoring for self-hosted & AI infrastructure",
  description:
    "A pull-only agent enrolls once, discovers listening services on-host, and runs CVE detections locally — only normalized findings ever leave the host. Signed detection catalog, posture scoring, alerting, and AI triage.",
} as const;

export const NAV_LINKS = [
  { href: "/how-it-works", label: "How it works" },
  { href: "/features", label: "Features" },
  { href: SITE.repoUrl, label: "GitHub", external: true },
] as const;
