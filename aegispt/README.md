# AegisPT — Private AI Web & API Penetration Testing Platform

A self-hosted, privacy-first, multi-agent AI penetration testing platform built for Kali Linux, featuring:

- **Shared FastAPI + WebSocket Backend** (`127.0.0.1:8443` with local bearer token authentication)
- **Non-Bypassable Scope & 3-Tier Policy Engine** (allowlist-only domains/URLs/CIDRs, path exclusions, DNS boundary guard, `shell=False` typed tool adapters, rate limiting)
- **Provider-Agnostic LLM Router** (local **Ollama** + any remote **OpenAI-compatible / vLLM** endpoint + reversible secret/token redaction + deterministic OWASP playbook fallback when offline)
- **12 Typed Kali Tool Adapters**: `http_probe`, `subfinder`, `httpx`, `katana`, `whatweb`, `wafw00f`, `ffuf`, `arjun`, `nuclei`, `dalfox`, `sqlmap`, `zaproxy`
- **Dual Operator Interfaces**: React Web Dashboard (Live Agent Stream, Attack-Surface Graph, Interactive Tier-3 Approval Drawer, Findings Studio) + Typer/Rich Kali CLI (`aegispt`)
- **Automated Reporting**: Markdown, self-contained HTML, JSON, and SARIF 2.1.0 exports

---

## Quick Start

### 1. Start the Backend Server

```bash
cd aegispt
cp .env.example .env
PYTHONPATH=backend:cli python3 -m aegispt_cli.main serve
```

The server listens on `http://127.0.0.1:8443` and prints your local API bearer token (stored in `data/.api_token`).

### 2. Check Kali Toolchain & AI Engine (`doctor`)

```bash
PYTHONPATH=backend:cli python3 -m aegispt_cli.main doctor
```

Optional local Ollama setup (tuned for 8 GB RAM hosts):

```bash
chmod +x scripts/setup_ollama.sh
./scripts/setup_ollama.sh
```

### 3. Build or Run the Web Dashboard

```bash
cd frontend
pnpm install
pnpm build   # Served automatically by FastAPI on http://127.0.0.1:8443
# Or for hot-reload dev mode:
pnpm dev     # Open http://127.0.0.1:5173
```

### 4. Local Practice Lab (OWASP Juice Shop — 127.0.0.1 only)

```bash
docker compose -f lab/docker-compose.lab.yml up -d
```

Then run an assessment from CLI:

```bash
PYTHONPATH=backend:cli python3 -m aegispt_cli.main engagement create \
  --name "Local Juice Shop" \
  --url http://127.0.0.1:3000 \
  --allow-private-ips \
  --mode tiered

PYTHONPATH=backend:cli python3 -m aegispt_cli.main run <ENGAGEMENT_ID>
PYTHONPATH=backend:cli python3 -m aegispt_cli.main report <ENGAGEMENT_ID> --format html --out report.html
```

---

## Running Automated Tests

```bash
cd aegispt
PYTHONPATH=backend:cli pytest -v backend/tests
```
