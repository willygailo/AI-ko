# AegisPT — Private AI Web & API Penetration Testing Platform

See the root [README.md](../README.md) for the complete architecture diagram, 3-tier tool matrix, full environment variable reference, and API overview, or read [TOOLS_AND_SETUP.md](./TOOLS_AND_SETUP.md) for the Ollama Cloud / local / offline setup guide and 24-tool cheat sheet.

---

## Quick Start (from `aegispt/`)

### 1. Configure & Check Kali Toolchain

```bash
cp .env.example .env
./aegispt setup           # Guided .env wizard (Ollama Cloud, Local Ollama, or Offline mode)
./aegispt doctor          # Verify installed adapters, OWASP KB, and active LLM profile
./aegispt tools           # Interactive cheat sheet for all 24 tools & 12 http_probe modes

# Optional: install globally so `aegispt` and `python -m aegispt_cli.main` work anywhere
pip install --user --break-system-packages --no-build-isolation --no-deps -e .
aegispt --install-completion
```

Optional local Ollama setup:
- `--light` *(default)* pulls `qwen2.5:1.5b` + `qwen2.5:3b` (~2.5 GB, ideal for 7.5–8 GB RAM hosts).
- `--coder` pulls `qwen2.5:3b` + `qwen2.5-coder:7b` (~6.5 GB, best with 12+ GB RAM).

```bash
./scripts/setup_ollama.sh          # Default --light profile (1.5b + 3b)
./scripts/setup_ollama.sh --coder  # Larger coder profile (3b + 7b, 12+ GB RAM)
```

### 2. Start Backend Server & Built-In Web Dashboard

```bash
./aegispt serve
```

- Listens on `http://127.0.0.1:8443` by default (honoring `AEGISPT_HOST`/`AEGISPT_PORT` from `.env`).
- Startup logs keep the raw bearer token hidden by default (`AEGISPT_PRINT_TOKEN=0`); run `./aegispt token` anytime to retrieve it.
- REST routes require `Authorization: Bearer <token>` (or `X-API-Key: <token>`); query-parameter `?token=` auth is disabled on REST endpoints. WebSocket streams authenticate via `Authorization: Bearer` headers (CLI) or single-use tickets from `POST /api/v1/system/ws-ticket` (Web UI).

### 3. Build, Test, or Develop the Frontend

```bash
cd frontend
pnpm install --frozen-lockfile
pnpm typecheck && pnpm lint && pnpm test && pnpm build
pnpm dev     # Optional Vite dev server on http://127.0.0.1:5173
```

### 4. Local Practice Lab (OWASP Juice Shop — 127.0.0.1 only)

```bash
docker compose -f lab/docker-compose.lab.yml up -d

./aegispt engagement create \
  --name "Local Juice Shop" \
  --url http://127.0.0.1:3000 \
  --allow-private-ips \
  --mode tiered

./aegispt run
./aegispt steer "Focus on GraphQL, JWT, and BOLA checks"
./aegispt pause && ./aegispt resume
./aegispt attach
./aegispt stop
./aegispt run-tool http_probe http://127.0.0.1:3000 --args '{"mode":"passive_audit"}'
./aegispt approvals
./aegispt snapshots
./aegispt llm-profiles
./aegispt runs
./aegispt checklist
./aegispt chains
./aegispt findings
./aegispt report --format html --out report.html
./aegispt report --format poc_sh --out verify_findings.sh
```

---

## Running Automated Checks & Tests

From the repository root, run the full CI-matching verification suite with:

```bash
make check
```

Or run backend/CLI checks directly from `aegispt/`:

```bash
ruff check backend cli && pytest -v
```
