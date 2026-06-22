# Contributing to Palisade

Thanks for your interest. This is a portfolio project, but issues and pull
requests are welcome.

## Repository layout

| Path             | What it is                                              |
| ---------------- | ------------------------------------------------------- |
| `agent/`         | Go agent that runs on each monitored host               |
| `control-plane/` | FastAPI control plane (SQLAlchemy + Alembic)            |
| `web/`           | React + TypeScript + Vite dashboard                     |
| `site/`          | Astro marketing site (trypalisade.dev)                  |
| `detections/`    | YAML detection specs validated against a JSON schema    |
| `docs/`          | Design decisions, release signing, screenshots          |

## Development setup

Requires Go 1.22+, Python 3.12+, and Node 20+.

```bash
make venv            # control-plane venv + deps
cd web && npm ci     # web deps
cd agent && go build ./...
```

Common workflows are in the `Makefile` (`make help`):

- `make smoke` — control-plane end-to-end loop (SQLite, in-process)
- `make integration` — real agent binary against a real control plane
- `make test` — agent Go tests + smoke + integration + detection validation
- `make demo` — full stack + live agent loop at <http://localhost:8080>

## Linting and formatting

Run before opening a PR — CI enforces these:

```bash
make lint            # ruff + golangci-lint + eslint/prettier
make fmt             # auto-fix and format everything
```

`golangci-lint` is installed with
`go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.59.1`.

## Tests

- **Agent:** `cd agent && go test ./...`
- **Control plane:** each `app/*_test.py` runs in its own process — several test
  modules rebind the module-global DB engine and config at import, so a single
  pooled `pytest app` run cross-contaminates. Run them per file (this is how CI
  does it).
- **Web:** `cd web && npm test`
- **Detections:** `cd detections && python validate.py`

The Postgres Row-Level Security leg (`app/rls_postgres_test.py`) needs a running
Postgres and `PALISADE_TEST_DATABASE_URL`; see `.github/workflows/ci.yml`.

## Pull requests

- Use [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`,
  `fix:`, `docs:`, `chore:`).
- Keep changes focused; update docs and `CHANGELOG.md` (Unreleased) when behavior
  changes.
- If you change SQLAlchemy models, generate a migration and confirm no drift:
  `make revision m="..."` then `make check`.
- Ensure `make lint` and the relevant tests pass.

## Security

Do not file public issues for vulnerabilities. See [SECURITY.md](SECURITY.md).
