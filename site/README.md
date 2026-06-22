# Palisade marketing site

Static marketing site for [trypalisade.dev](https://trypalisade.dev), built with
[Astro](https://astro.build) + Tailwind. Themed to match the product dashboard
(`web/`): the `ink` dark scale and `#7c3aed` accent.

## Develop

```bash
cd site
npm install
npm run dev        # http://localhost:4321
```

## Build

```bash
npm run build      # → site/dist (static)
npm run preview    # serve the built output locally
```

## Deploy (Cloudflare Pages)

Static output, no adapter needed.

- **Framework preset:** Astro
- **Build command:** `npm run build`
- **Build output directory:** `dist`
- **Root directory:** `site`
- **Custom domain:** `trypalisade.dev`

`public/_headers` ships baseline security headers (HSTS, nosniff, frame-deny);
`@astrojs/sitemap` emits `sitemap-index.xml` referenced by `public/robots.txt`.

### Domain split

| Subdomain | Serves |
|-----------|--------|
| `trypalisade.dev` | this marketing site |
| `app.trypalisade.dev` | the `web/` dashboard |
| `api.trypalisade.dev` | the control plane |

App/repo/author URLs live in `src/config.ts` — update there, not inline.

## TODO

- `public/og.png` — 1200×630 social card (referenced by `Layout.astro`).
