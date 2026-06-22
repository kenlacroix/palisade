# Home / Proxmox deploy

Run the control plane on a home box and publish it at `api.trypalisade.dev`
through a **Cloudflare Tunnel** — no port forwarding, no exposed home IP, works
behind CGNAT. `docker-compose.override.yml` (one level up) adds the `cloudflared`
and `backup` services on top of the base stack, and hardens it (see below).

## Blast radius & isolation

The live demo is intentionally insecure — it boots with
`PALISADE_ALLOW_INSECURE_DEFAULTS=1` on default credentials and the public
signing key, on **synthetic, disposable** data (`PALISADE_SEED_DEMO=1`,
`PALISADE_DEMO_MODE=1` make it read-only for logged-in users). Treat the box as
compromisable and keep its blast radius small:

- **Dedicated, disposable host.** Run it in its own unprivileged LXC or a small
  VM (step 1) that holds nothing else. There is no real tenant data to protect;
  if anything looks off, `docker compose down -v && docker compose up -d --build`
  re-seeds from scratch.
- **No inbound, no LAN exposure.** The tunnel is an *outbound* connection to
  Cloudflare, so the host needs **no inbound ports** — block inbound at the
  firewall entirely. `docker-compose.override.yml` also unpublishes the API's
  host port (`ports: !reset []`), so `/v1` is reachable only through the tunnel
  and from inside the compose network, never from the home LAN.
- **No egress from the data tier.** Postgres and Redis run on an `internal`
  Docker network with no route off the box; only `api`, `worker`, and
  `cloudflared` join the `edge` network that can reach the internet. A
  compromised database container cannot exfiltrate or call home.
- **Reduced container privilege.** Every service runs with
  `no-new-privileges`, dropped Linux capabilities (where the image's entrypoint
  allows), and pid/memory caps, so a process escape has less to work with.
- **Don't bridge demo and real.** Never enroll a real host's agent against the
  demo, and never point a real tenant at `api.trypalisade.dev`. The demo signing
  key is public — bundles it serves are forgeable by design.

For a real (non-demo) tenant, follow the production hardening checklist in
[`SECURITY.md`](../../SECURITY.md): unset the insecure-defaults flag, rotate
every secret, and let the startup preflight enforce it.

## 1. Proxmox container

A Debian 12 **LXC** is the cheapest option. Docker in an unprivileged LXC needs
nesting + keyctl:

```bash
# on the Proxmox host
pct create 110 local:vztmpl/debian-12-standard_*.tar.zst \
  --hostname palisade \
  --cores 2 --memory 4096 --swap 1024 \
  --rootfs local-lvm:16 \
  --net0 name=eth0,bridge=vmbr0,ip=dhcp \
  --unprivileged 1 --features nesting=1,keyctl=1 \
  --onboot 1
pct start 110
pct exec 110 -- bash -c 'apt-get update && apt-get install -y openssh-server sudo'
```

> If Docker-in-LXC gives you overlayfs/cgroup grief, use a small VM instead
> (same everything else). 2 vCPU / 4 GB / 16 GB is plenty for a POC.

## 2. Docker

```bash
curl -fsSL https://get.docker.com | sh
```

## 3. Clone + configure

```bash
git clone https://github.com/kenlacroix/palisade.git
cd palisade/control-plane
cp .env.example .env
```

Edit `.env` for a real instance:

- `POSTGRES_PASSWORD` — strong value
- `PALISADE_ENROLL_TOKENS` — rotate off `PLS-DEMO`
- `PALISADE_DEMO_USER_PASSWORD` — change or remove the demo user
- `PALISADE_CORS_ORIGINS=https://app.trypalisade.dev,https://trypalisade.dev`
- `PALISADE_SIGNING_KEY` — set a real Ed25519 seed (see root README)
- `ANTHROPIC_API_KEY` — optional, enables triage/drafting

Agents use the **bearer `agent_secret`** path by default (mTLS terminates at
Cloudflare's edge, so client certs don't survive the tunnel). Leave
`PALISADE_REQUIRE_MTLS` unset. To keep mTLS later, front the API with a local
Caddy/nginx doing client-cert verification and reach it over Tailscale instead.

## 4. Cloudflare Tunnel (one-time)

```bash
docker run -it --rm -v "$PWD/deploy/cloudflared:/etc/cloudflared" \
  cloudflare/cloudflared:latest tunnel login            # writes cert.pem
docker run -it --rm -v "$PWD/deploy/cloudflared:/etc/cloudflared" \
  cloudflare/cloudflared:latest tunnel create palisade  # writes <UUID>.json
mv deploy/cloudflared/*.json deploy/cloudflared/palisade.json
docker run -it --rm -v "$PWD/deploy/cloudflared:/etc/cloudflared" \
  cloudflare/cloudflared:latest tunnel route dns palisade api.trypalisade.dev
```

`config.yml` already points the tunnel at `http://api:8000`. `cert.pem` and
`palisade.json` are gitignored.

> Prefer a dashboard (token) tunnel? Skip the above, create a tunnel in the CF
> dashboard, set its public hostname to `api.trypalisade.dev → http://api:8000`,
> and replace the `cloudflared` command with `tunnel run --token <TOKEN>`.

## 5. Bring it up

```bash
mkdir -p backups
docker compose up -d --build
docker compose ps
docker compose logs -f cloudflared    # should show 4 edge connections registered
curl -s https://api.trypalisade.dev/healthz   # from anywhere
```

## 6. Verify backups

```bash
docker compose logs backup    # first dump runs on boot
ls -lh backups/               # palisade-YYYYmmdd-HHMMSS.sql.gz
```

Off-box copies (recommended): `rclone` the `backups/` dir to an R2/B2 bucket on a
cron. Restore: `gunzip -c backups/<file>.sql.gz | docker compose exec -T postgres psql -U palisade palisade`.

## Updating

```bash
git pull && docker compose up -d --build
```
