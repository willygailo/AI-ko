# AegisPT Setup, Optional Ollama & Tools Quick Guide

Practical reference for setting up AI backends (optional), scoped test labs, and using all 24 security tool adapters + 12 `http_probe` modes.

---

## 1. Quick Setup (`./aegispt setup`)

AegisPT runs from `<repo>/aegispt` (`./aegispt ...`) and gives you **three AI modes**:

| Mode | Best For | Command |
| :--- | :--- | :--- |
| **Ollama Cloud** *(Recommended for 7.5–8 GiB RAM)* | Zero local RAM usage + strong `qwen3` reasoning via `https://ollama.com` | `./aegispt setup --provider cloud` |
| **Local Ollama** *(Optional)* | 100% offline inference using `--light` (`qwen2.5:1.5b` + `qwen2.5:3b`, default for 7.5–8 GB RAM) or `--coder` (`qwen2.5:3b` + `qwen2.5-coder:7b` for 12+ GB RAM) | `curl -fsSL https://ollama.com/install.sh \| sh && ollama serve &`<br>`./scripts/setup_ollama.sh` *(or `--coder`)*<br>`./aegispt setup --provider local` |
| **Zero-LLM Offline Fallback** | No AI install & no API keys needed (`AEGISPT_LLM_MODE=offline`); runs all 24 tools using OWASP + 9 Skill Packs | `./aegispt setup --provider offline` |

Check readiness anytime:
```bash
./aegispt doctor
```

---

## 2. Start the Server & Dashboard

```bash
./aegispt serve
```
- Open **`http://127.0.0.1:8443`**
- Retrieve the local API bearer token anytime with **`./aegispt token`** (startup logs mask the raw token by default; set `AEGISPT_PRINT_TOKEN=1` only if you explicitly want it printed on launch).

---

## 3. Running Assessments (CLI & Dashboard)

### Local Docker Practice Lab (`127.0.0.1:3000`) or Custom Test Lab Domain
```bash
# Optional: start Juice Shop (localhost-only, pinned & hardened)
docker compose -f lab/docker-compose.lab.yml up -d

# 1. Create engagement (pass --url for HTTP/ports, --domain for bare/wildcard domains)
./aegispt engagement create \
  --name "My Test Lab" \
  --url http://127.0.0.1:3000 \
  --allow-private-ips \
  --mode tiered

# 2. Optional: guide the Cognitive Brain toward specific risks
./aegispt steer "Focus on GraphQL, JWT alg=none, and multi-role IDOR"

# 3. Run & stream live (prompts [a]pprove / [e]dit / [r]eject on Tier 3)
./aegispt run

# 4. Lifecycle control, re-attaching & manual operations
./aegispt pause
./aegispt resume
./aegispt attach
./aegispt stop
./aegispt approvals
./aegispt snapshots
./aegispt llm-profiles

# 5. Inspect everything (automatically targets your latest engagement)
./aegispt runs
./aegispt checklist
./aegispt hypotheses
./aegispt chains
./aegispt findings
./aegispt diff

# 6. Export reports + executable PoC replay script
./aegispt report --format html --out report.html
./aegispt report --format poc_sh --out verify_findings.sh
```

### Multi-Role BOLA/IDOR Testing (`User A` vs `User B`)
```bash
./aegispt engagement create \
  --name "Auth BOLA Test" \
  --url http://my-lab.local:8080 \
  --domain my-lab.local \
  -H "Authorization: Bearer <USER_A_JWT>" \
  --secondary-header "Authorization: Bearer <USER_B_JWT>" \
  --allow-private-ips \
  --mode tiered
```

---

## 4. Viewing & Running All 24 Tools

Run the built-in cheat sheet in your terminal:
```bash
./aegispt tools           # All 24 adapters + all 12 http_probe modes
./aegispt tools --tier 3  # Filter Tier-3 active verification probes only
```

Run any tool adapter directly under `ScopePolicy` via CLI (`./aegispt run-tool`), the Web Dashboard (**Scoped Manual Tool Execution**), or `POST /api/v1/engagements/{id}/run-tool` with JSON args (for example `{"mode": "graphql_deep_audit"}` or `{"mode": "race_burst_probe", "method": "POST", "burst_count": 6}`).
