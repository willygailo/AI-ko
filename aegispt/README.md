# AegisPT — Private AI Web & API Penetration Testing Platform

See the root [README.md](../README.md) for the complete architecture diagram, 3-tier tool matrix, configuration reference, and API overview, or read [TOOLS_AND_SETUP.md](./TOOLS_AND_SETUP.md) for the Ollama Cloud / local / offline setup guide and 24-tool cheat sheet.

---

## Quick Start (from `aegispt/`)

### 1. Configure & Check Kali Toolchain

```bash
cp .env.example .env
./aegispt setup           # Guided .env wizard (Ollama Cloud, Light Local, or Offline Fallback)
./aegispt doctor
./aegispt tools           # Interactive cheat sheet for all 24 tools & 12 http_probe modes

# Optional: install globally so `aegispt` and `python -m aegispt_cli.main` work anywhere
pip install --user --break-system-packages --no-build-isolation --no-deps -e .
aegispt --install-completion
```

Optional local Ollama setup (lightweight `--light` profile pulls `qwen2.5:1.5b` + `qwen2.5:3b` for 7.5–8 GB RAM hosts; pass `--coder` for 7B):

```bash
./scripts/setup_ollama.sh --light
```

### 2. Start Backend Server & Built-In Web Dashboard

```bash
./aegispt serve
```

The server listens on `http://127.0.0.1:8443` and prints your local API bearer token (`./aegispt token` to view it anytime).

### 3. Build or Develop the Frontend

```bash
cd frontend
pnpm install
pnpm build   # Served automatically by FastAPI on http://127.0.0.1:8443
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
./aegispt runs
./aegispt checklist
./aegispt chains
./aegispt findings
./aegispt report --format html --out report.html
./aegispt report --format poc_sh --out verify_findings.sh
```

---

## Running Automated Tests

```bash
PYTHONPATH=backend:cli pytest -v backend/tests
```
