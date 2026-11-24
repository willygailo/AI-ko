.PHONY: help test test-backend test-frontend lint lint-backend lint-frontend lint-shell build-ui dev dev-backend dev-frontend check-lab check

help:
	@echo "AegisPT Developer Targets:"
	@echo "  make check         Run all CI checks (lint, test, build-ui, check-lab)"
	@echo "  make lint          Run ruff, frontend typecheck/lint, and shellcheck"
	@echo "  make test          Run backend pytest and frontend unit tests"
	@echo "  make build-ui      Build production frontend bundle (aegispt/frontend/dist)"
	@echo "  make dev           Start backend API (127.0.0.1:8443) and Vite dev server (5173)"
	@echo "  make dev-backend   Start FastAPI backend server via ./aegispt serve"
	@echo "  make dev-frontend  Start Vite frontend dev server"
	@echo "  make check-lab     Validate aegispt/lab/docker-compose.lab.yml"

PYTEST := $(shell if [ -x aegispt/.venv/bin/pytest ]; then echo ".venv/bin/pytest"; else echo "pytest"; fi)
RUFF := $(shell if [ -x aegispt/.venv/bin/ruff ]; then echo ".venv/bin/ruff"; else echo "ruff"; fi)

test: test-backend test-frontend

test-backend:
	cd aegispt && $(PYTEST) -v

test-frontend:
	cd aegispt/frontend && pnpm test

lint: lint-backend lint-frontend lint-shell

lint-backend:
	cd aegispt && $(RUFF) check backend cli

lint-frontend:
	cd aegispt/frontend && pnpm typecheck && pnpm lint

lint-shell:
	shellcheck aegispt/aegispt aegispt/scripts/setup_ollama.sh

build-ui:
	cd aegispt/frontend && pnpm build

check-lab:
	docker compose -f aegispt/lab/docker-compose.lab.yml config -q

check: lint test build-ui check-lab

dev-backend:
	cd aegispt && ./aegispt serve

dev-frontend:
	cd aegispt/frontend && pnpm dev

dev:
	@trap 'kill 0' INT TERM EXIT; \
	(cd aegispt && ./aegispt serve) & \
	(cd aegispt/frontend && pnpm dev) & \
	wait
