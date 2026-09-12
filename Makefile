.PHONY: help up down logs migrate seed seed-full dev test test-unit test-int load lint fmt typecheck audit demo-carding exploit-bola reset psql redis-cli

COMPOSE ?= docker compose

# Tests run on the host against the datastores compose brings up. The runtime
# image deliberately ships without pytest or the tests directory — a production
# image should not carry its own test harness — so `docker compose exec api
# pytest` cannot work by design.
PYTEST ?= $(shell test -x .venv/bin/pytest && echo .venv/bin/pytest || echo pytest)

help:
	@grep -E '^[a-z-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

up: ## Start api + postgres + redis, run migrations
	$(COMPOSE) up -d --build
	@echo "Swagger:   http://localhost:8000/docs"
	@echo "Dashboard: http://localhost:8000/dash  (dash / dash-dev-password)"

down: ## Stop everything
	$(COMPOSE) down

reset: ## Stop and destroy the database volume
	$(COMPOSE) down -v

logs: ## Tail api logs
	$(COMPOSE) logs -f api

# `docker compose restart` reuses the built image, so it will NOT pick up source
# edits — use `make up` (which passes --build) after changing app code.
migrate: ## Apply migrations
	$(COMPOSE) exec api alembic upgrade head

seed: ## Load reference data + generate a small demo world (fast)
	$(COMPOSE) exec api python -m scripts.seed_reference
	$(COMPOSE) exec api python -m scripts.seed_flights --scale demo --days 7

seed-full: ## Bigger generated world (slower)
	$(COMPOSE) exec api python -m scripts.seed_reference
	$(COMPOSE) exec api python -m scripts.seed_flights --scale small --days 14

demo-carding: ## Drive a simulated card-testing attack against the running API
	$(COMPOSE) exec api python -m scripts.simulate_carding

exploit-bola: ## Attempt the OWASP API #1 attack; exits non-zero if it succeeds
	$(COMPOSE) exec api python -m scripts.exploit_bola

dev: ## Install the dev toolchain into .venv (uv)
	uv venv --python 3.12
	uv pip install -e ".[dev]"

test: ## Full suite — needs `make up` for postgres + redis
	$(PYTEST) -q

test-unit: ## Unit tests only; no datastores required
	$(PYTEST) -q tests/unit

test-int: ## Integration + concurrency + security only
	$(PYTEST) -q tests/integration tests/concurrency tests/security

load: ## Prove no oversell under concurrent load
	@echo "Note: restart the API with RATE_LIMIT_ENABLED=false first —"
	@echo "otherwise this measures the rate limiter, not the seat locking."
	$(PYTEST) -q tests/concurrency && python -m load.oversell_proof --seats 50 --racers 400

lint: ## ruff
	.venv/bin/ruff check . && .venv/bin/ruff format --check .

fmt: ## ruff format
	.venv/bin/ruff check --fix . && .venv/bin/ruff format .

typecheck: ## mypy
	.venv/bin/mypy app

audit: ## dependency + static security scan
	.venv/bin/pip-audit || true
	.venv/bin/bandit -q -r app scripts -ll

psql: ## psql as the owner role
	$(COMPOSE) exec db psql -U skylock_owner -d skylock

redis-cli: ## redis-cli
	$(COMPOSE) exec redis redis-cli
