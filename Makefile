# Palisade — one-command workflows. Apply-from-scratch is the whole pitch:
# `make venv && make up` brings the control plane online from nothing.
CP := control-plane
ALEMBIC := cd $(CP) && .venv/bin/alembic

.DEFAULT_GOAL := help

.PHONY: help venv up down logs migrate revision check smoke integration test agent-build web demo demo-down

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-13s\033[0m %s\n",$$1,$$2}'

venv: ## Create control-plane venv + install deps
	cd $(CP) && python3 -m venv .venv && .venv/bin/pip install -q -r requirements.txt

up: ## Full stack (api + postgres) via docker compose
	cd $(CP) && docker compose up --build

down: ## Stop the stack
	cd $(CP) && docker compose down

logs: ## Tail the api container
	cd $(CP) && docker compose logs -f api

migrate: ## Apply migrations to head (DATABASE_URL or sqlite default)
	$(ALEMBIC) upgrade head

revision: ## Autogenerate a migration: make revision m="add users table"
	$(ALEMBIC) revision --autogenerate -m "$(m)"

check: ## Fail if models drift from migrations (run before committing schema changes)
	$(ALEMBIC) check

smoke: ## Control-plane end-to-end smoke test
	cd $(CP) && .venv/bin/python -m app.smoke_test

integration: ## Live test: real agent binary <-> real control plane over HTTP
	cd $(CP) && .venv/bin/python -m app.live_integration_test

test: ## Agent Go tests + control-plane smoke + live integration + detection validation
	cd agent && go test ./...
	$(MAKE) smoke
	$(MAKE) integration
	cd detections && .venv/bin/python validate.py

agent-build: ## Build the Go agent binary (agent/palisade)
	cd agent && go build -o palisade ./cmd/palisade

web: ## Run the web prototype dev server
	cd web && npm run dev

demo: ## Self-contained demo: full stack + live agent loop (open http://localhost:8080)
	docker compose -f docker-compose.demo.yml up --build

demo-down: ## Stop the demo stack and remove its volumes
	docker compose -f docker-compose.demo.yml down -v
