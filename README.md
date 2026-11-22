<div align="center">

# AegisPT

### Private, Provider-Agnostic AI Web & API Penetration Testing Platform

Built for Kali Linux with allowlist-only scope enforcement, 3-tier human-in-the-loop approval gates, 24 typed security tool adapters, modular offensive skill packs, and a real-time Web Dashboard + CLI.

[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18%20%2B%20TypeScript-61DAFB?style=for-the-badge&logo=react&logoColor=black)](https://react.dev/)
[![Kali Linux](https://img.shields.io/badge/Kali%20Linux-Ready-557C94?style=for-the-badge&logo=kalilinux&logoColor=white)](https://www.kali.org/)
[![Tests](https://img.shields.io/badge/Pytest-35%20Passed-22C55E?style=for-the-badge&logo=pytest&logoColor=white)](./aegispt/backend/tests)

[Architecture](#architecture) •
[Autonomy & Guardrails](#autonomy--safety-guardrails) •
[Tooling Matrix](#3-tier-tooling-matrix) •
[Quick Start](#quick-start) •
[API & Config](#configuration--api-reference) •
[Testing](#running-tests)

</div>

---

## Why AegisPT?

| Pillar | What It Does |
| :--- | :--- |
| **Private & Encrypted at Rest** | FastAPI + WebSocket backend binds strictly to `127.0.0.1:8443` with bearer token auth (`data/.api_token`), Fernet-encrypted API keys & primary/secondary auth vaults (`data/.master.key`), scrubbed logs, and idempotent SQLite schema auto-migration. |
| **Provider-Agnostic LLM Router** | Hot-swap between **Local Ollama**, **Ollama Cloud (`https://ollama.com`)**, and remote **vLLM / OpenAI-compatible** endpoints with exponential retry, multi-profile failover, `fast` + `reasoning` tiers, and secret redaction on non-local calls. |
| **Cognitive Multi-Skill Brain** | Risk-weighted endpoint prioritizer (query + body params), Self-Critic gating, signal-activated **SQLite FTS5 Knowledge Base** (`12` OWASP WSTG playbooks + `9` modular Skill Packs = `21` modules), Hypothesis Tracking, Cross-Engagement Skill Stats, **Attack-Chain Synthesis**, and **Live Operator Steering** (`steer`). |
| **Non-Bypassable Scope & Multi-Role Auth** | Default-deny `ScopePolicy` enforces path-normalized allowlists (`posixpath`), hop-by-hop redirect SSRF guards, DNS boundaries, encrypted **User A vs. User B** credentials for true IDOR/BOLA verification, local `/oob` lab callback catcher, and `shell=False` typed `argv` execution. |
| **Dual Operator Experience** | Operate from the **React Web Dashboard** (Attack Graph, **Chains**, **Skill Checklist**, Endpoints, Findings + **Re-Verify**, interactive **HTTP Repeater**, **Hypotheses**, **Scan Diff**, Raw Log Viewer, **Live Steering**, Approval Modal) or **Kali CLI** (`./aegispt` with automatic `latest` engagement resolution). |
| **Developer-Ready Reporting** | One-click exports in **Print-ready HTML/PDF**, **Markdown**, **SARIF 2.1.0**, **JSON**, and executable **`PoC Replay Script (.sh)`** with Posture Score, Synthesized Attack Chains, OWASP breakdown, CVSS v3.1 scores, PoC commands, and remediation guidance. |

---

## Architecture

```mermaid
flowchart TD
    subgraph Interfaces["Operator Interfaces"]
        WEB["React Web Dashboard (Vite + Tailwind)"]
        CLI["Kali CLI (./aegispt via Typer + Rich)"]
    end

    subgraph Core["FastAPI + WebSocket Backend (127.0.0.1:8443)"]
        API["REST API, WebSocket Hub & Local /oob Catcher"]
        ORCH["Cognitive Orchestrator (Risk Ranker, Critic & Attack Chainer)"]
        POL["ScopePolicy & 3-Tier Approval Coordinator"]
        KB["SQLite FTS5 KB (12 OWASP Playbooks + 9 Skill Packs)"]
        DB["SQLite WAL Graph, Checklists, Snapshots & Skill Memory"]
        LLM["LLM Router + SecretRedactor"]
    end

    subgraph Models["Pluggable LLM Backends"]
        OLLAMA["Local Ollama (3B-8B) / Ollama Cloud"]
        REMOTE["Remote vLLM / OpenAI-Compatible"]
    end

    subgraph Tools["24 Typed Tool Adapters (shell=False)"]
        T1["Tier 1 Auto: http_probe, js_miner, spa_inspector, trufflehog, gitleaks, subfinder, dnsx, paramspider, httpx, katana, whatweb, wafw00f, sslscan"]
        T2["Tier 2 Bounded: naabu, nmap, ffuf, feroxbuster, arjun, nikto, wpscan, nuclei safe, zaproxy passive, graphql/oauth audits"]
        T3["Tier 3 Approval-Gated: sqlmap (GET/JSON), dalfox, multi-role BOLA, JWT/BFLA/HPP/TOCTOU race/SSTI/open-redirect probes, nuclei intrusive, zap active"]
    end

    WEB <--> API
    CLI <--> API
    API <--> ORCH
    ORCH <--> KB
    ORCH <--> DB
    ORCH <--> LLM
    LLM --> OLLAMA
    LLM --> REMOTE
    ORCH --> POL
    POL --> T1
    POL --> T2
    POL --> T3
```

---

## Autonomy & Safety Guardrails

AegisPT supports three operator-selectable execution modes per engagement:

- **`tiered`** *(Default)* — Runs Tier 1 recon and bounded Tier 2 scans automatically; pauses and prompts the operator (Web modal or CLI `[a]pprove / [e]dit / [r]eject`) before every Tier 3 active verification action.
- **`copilot`** — Prompts operator approval before every tool execution across all tiers.
- **`lab_autopilot`** — Unattended end-to-end execution strictly for isolated localhost/Docker practice labs.

```mermaid
sequenceDiagram
    participant Op as Operator (Web / CLI)
    participant Orch as Cognitive Orchestrator
    participant Pol as Scope & Policy Engine
    participant Tool as Typed Tool Adapter
    participant DB as SQLite Graph & Chain Vault

    Op-->>Orch: Optional Live Steering Hint (/steer)
    Orch->>Orch: Risk Rank Endpoints + Match Skill Packs + Critic Filter
    Orch->>Pol: Propose ToolCall (tool, target, args)
    Pol->>Pol: Validate ScopePolicy (allowlist, exclusions, DNS, shell=False)
    alt Out of Scope
        Pol-->>Orch: Hard Deny + Recovery Feedback
    else Tier 1 / Auto-Approved Tier 2
        Pol->>Tool: Execute validated argv with rate limits
        Tool->>DB: Correlate findings, update Skill Checklist & Attack Chains
        Tool-->>Orch: Updated risk-ranked graph
    else Tier 3 (Intrusive Verification)
        Pol->>DB: Create ApprovalRequest (AWAITING_APPROVAL)
        Pol-->>Op: Push command preview, rationale & risk via WebSocket
        Op-->>Pol: Approve / Modify Args / Reject with Note
        alt Approved or Modified
            Pol->>Tool: Execute validated argv
            Tool->>DB: Persist PoC evidence, verify hypotheses & update chains
        else Rejected
            Pol-->>Orch: Feed rejection note back for adaptive re-planning
        end
    end
```

---

## 3-Tier Tooling Matrix

| Tool | Default Tier | Escalation Rule | Capability |
| :--- | :---: | :--- | :--- |
| `http_probe` | **Tier 1** | **Tier 2** on `graphql_deep_audit`, `oauth_audit`; **Tier 3** on `replay_request`, `differential_bola`, `jwt_active_probe`, `bfla_verb_tamper`, `race_burst_probe`, `hpp_and_content_switch`, `ssti_probe`, `open_redirect_probe`, or mutating HTTP methods | Native async HTTP/TLS/header/CORS-matrix/cookie/JWT/OpenAPI analyzer, GraphQL oracle & schema importer, OAuth/OIDC auditor, multi-role BOLA/IDOR, verb BFLA, TOCTOU concurrency burst, HPP/content-type, SSTI family & open-redirect checks |
| `js_miner` | **Tier 1** | — | Mines in-scope JS bundles & `.js.map` source maps for hidden API routes, JSON `body_params`, DOM sink indicators & masked secrets |
| `spa_inspector` | **Tier 1** | — | Scope-locked Playwright headless Chromium inspector capturing SPA XHR/Fetch requests, JSON payloads, and `localStorage`/`sessionStorage` JWTs |
| `trufflehog` | **Tier 1** | — | Offline TruffleHog scan across fetched in-scope HTML/JS artifacts for leaked credentials (`--no-verification` by default) |
| `gitleaks` | **Tier 1** | — | Offline Gitleaks rule scan across fetched target artifacts (`--redact=100`) |
| `subfinder` | **Tier 1** | — | Passive subdomain enumeration |
| `dnsx` | **Tier 1** | — | DNS A/AAAA/CNAME/MX/TXT resolution & SPF/DMARC posture checks |
| `paramspider` | **Tier 1** | — | Historical parameterized URL mining scoped strictly to allowlisted domains |
| `httpx` | **Tier 1** | — | Live HTTP probing (ProjectDiscovery `httpx` with automatic native `http_probe` fallback) |
| `katana` | **Tier 1** | — | Web & JavaScript route/parameter crawling |
| `whatweb` | **Tier 1** | — | Server, CMS, and framework fingerprinting |
| `wafw00f` | **Tier 1** | — | WAF / CDN detection |
| `sslscan` | **Tier 1** | — | TLS protocol, weak cipher suite, and certificate validity auditor |
| `naabu` | **Tier 2** | Configurable (`tier2_auto`) | Fast unprivileged TCP connect port scan |
| `nmap` | **Tier 2** | Configurable (`tier2_auto`) | Bounded TCP port & service version scan (`-sT -Pn --top-ports`) |
| `ffuf` | **Tier 2** | Configurable (`tier2_auto`) | Rate-limited directory & API discovery with auto-calibration |
| `feroxbuster` | **Tier 2** | Configurable (`tier2_auto`) | Bounded recursive directory & content discovery |
| `arjun` | **Tier 2** | Configurable (`tier2_auto`) | HTTP query, form, and JSON parameter mining |
| `nikto` | **Tier 2** | Configurable (`tier2_auto`) | Bounded web server misconfiguration & dangerous file checks |
| `wpscan` | **Tier 2** | Triggered conditionally on WordPress | WordPress plugin, theme, user, and configuration vulnerability scanner (`--no-update`) |
| `nuclei` | **Tier 2** | Tier 3 when `include_intrusive=true` or `fuzz`/`intrusive` tags | Template scanner (Tier 2 excludes `dos,intrusive,fuzz,bruteforce`) |
| `zaproxy` | **Tier 2** | Tier 3 in `active_scan` mode | OWASP ZAP headless daemon spider/passive alerts & active scan |
| `dalfox` | **Tier 3** | Always gated in `tiered` mode | Cross-Site Scripting (XSS) parameter verification |
| `sqlmap` | **Tier 3** | Always gated in `tiered` mode | Bounded SQL injection verification (`--batch`, `level<=2`, `risk<=2`, GET/POST/PUT/PATCH with auto JSON `Content-Type`) |

---

## Quick Start

### 1. Clone & Run Diagnostics

```bash
git clone https://github.com/willygailo/AI-ko.git
cd AI-ko/aegispt
cp .env.example .env

# Verify all 24 Kali & native adapters, 21 KB playbooks/skills, and LLM reachability
./aegispt doctor        # Add --json for machine-readable output
```

<details>
<summary>Optional: Install <code>aegispt</code> Globally & Enable Shell Completion</summary>

The [`./aegispt`](./aegispt/aegispt) launcher works out of the box from `aegispt/` without installing anything globally. To invoke `aegispt` or `python -m aegispt_cli.main` from any directory and enable shell completion:

```bash
cd aegispt
pip install --user --break-system-packages --no-build-isolation --no-deps -e .
aegispt --install-completion
```

</details>

> [!TIP]
> **Local Ollama or Ollama Cloud**:
> - On an 8 GB / CPU-only Kali host, run `./scripts/setup_ollama.sh` to pull compact local models (`qwen2.5:3b` + `qwen2.5-coder:7b`).
> - To use **Ollama Cloud**, set `AEGISPT_OLLAMA_URL=https://ollama.com`, `AEGISPT_OLLAMA_API_KEY=<your-key>`, and cloud models in `.env` — or click the **Ollama Cloud** preset inside the Web Dashboard Settings modal.

### 2. Start the Backend & Web Dashboard

```bash
./aegispt serve
```

- Web Dashboard & API listen on `http://127.0.0.1:8443` (serves `aegispt/frontend/dist` automatically when built).
- Copy the local API bearer token printed on startup (or retrieve it anytime with `./aegispt token`).
- Dashboard tabs include **Attack Graph**, **Chains** (synthesized multi-step attack paths), **Skills** (checklist coverage matrix), **Endpoints**, **Findings** (`Confirm`, `False Positive`, **Re-Verify**, `Send to Repeater`, and HTML/Markdown/SARIF/`PoC .sh` exports), **Hypotheses**, **Repeater**, **Runs**, **Approvals**, and **Diff**, plus the **Live Steering** bar and **Multi-Role Auth Vault** (`+ New`).

<details>
<summary>Frontend Build & Hot-Reload Development Commands</summary>

```bash
cd aegispt/frontend
pnpm install
pnpm build   # Outputs dist/ served directly by FastAPI on http://127.0.0.1:8443
pnpm dev     # Optional Vite dev server with API/WS proxy on http://127.0.0.1:5173
```

</details>

### 3. Try It Against a Local Test Lab (OWASP Juice Shop)

Spin up the isolated localhost-only (`127.0.0.1:3000`) practice container:

```bash
cd aegispt
docker compose -f lab/docker-compose.lab.yml up -d
```

Create a scoped engagement (using `--url`, optional `--domain` for host/subdomains, and optional `--auth-header` / `--secondary-header` for multi-role IDOR checks), steer the AI brain, and export reports (`latest` engagement ID is used automatically when omitted):

```bash
# 1. Create scoped engagement (local URL and/or custom test-lab domain)
./aegispt engagement create \
  --name "Local Juice Shop" \
  --url http://127.0.0.1:3000 \
  --allow-private-ips \
  --mode tiered

# 2. Optional: guide the AI brain toward specific features mid-assessment
./aegispt steer "Focus on GraphQL, JWT alg=none, and multi-role BOLA checks"

# 3. Start & stream live progress + Tier-3 [a]pprove/[e]dit/[r]eject prompts
./aegispt run

# 4. Inspect runs, hypotheses, skill coverage, attack chains, and deltas
./aegispt runs
./aegispt hypotheses
./aegispt checklist
./aegispt chains
./aegispt findings
./aegispt diff
./aegispt repeat latest http://127.0.0.1:3000/api/Products

# 5. Export HTML report & executable PoC replay script
./aegispt report --format html --out report.html
./aegispt report --format poc_sh --out verify_findings.sh
```

---

## Configuration & API Reference

<details>
<summary><strong>Repository Structure</strong></summary>

```text
.
├── .gitignore
├── README.md
├── CONTRIBUTING.md / CODE_OF_CONDUCT.md / SECURITY.md
└── aegispt/
    ├── aegispt                         # CLI launcher script (./aegispt)
    ├── pyproject.toml                  # Python project & entrypoint metadata
    ├── .env.example                    # Environment configuration template
    ├── backend/
    │   ├── app/
    │   │   ├── main.py                 # FastAPI app, lifespan, OOB & static mount
    │   │   ├── config.py               # Pydantic settings (AEGISPT_*)
    │   │   ├── core/                   # auth, scope, policy, redactor, vault, ratelimit, events
    │   │   ├── db/                     # Async SQLite + auto-migration, ORM models, persistence & snapshots
    │   │   ├── llm/                    # Ollama (Local/Cloud) & OpenAI-compat router with retry & failover
    │   │   ├── tools/                  # 24 typed Kali, Playwright SPA & native security adapters
    │   │   ├── knowledge/              # 12 WSTG playbooks + 9 Markdown Skill Packs (SQLite FTS5)
    │   │   ├── agents/                 # Cognitive orchestrator, risk graph ranker, chainer & reporter
    │   │   └── api/                    # REST routers, OOB catcher, Repeater & WebSocket handler
    │   └── tests/                      # Unit & integration test suite (35 tests)
    ├── cli/aegispt_cli/                # Typer + Rich CLI client
    ├── frontend/                       # React + Vite + TypeScript + Tailwind UI
    ├── lab/docker-compose.lab.yml      # Localhost-only OWASP Juice Shop practice target
    └── scripts/setup_ollama.sh         # Optional local Ollama model pull helper
```

</details>

<details>
<summary><strong>Environment Variables (<code>aegispt/.env</code>)</strong></summary>

| Variable | Default | Description |
| :--- | :--- | :--- |
| `AEGISPT_HOST` | `127.0.0.1` | Bind address for FastAPI server |
| `AEGISPT_PORT` | `8443` | HTTP / WebSocket server port |
| `AEGISPT_API_TOKEN` | _(auto-generated)_ | Fixed bearer token; if blank, stored in `data/.api_token` |
| `AEGISPT_DATA_DIR` | `./data` | Storage directory for SQLite DBs, logs, and tool artifacts |
| `AEGISPT_OLLAMA_URL` | `http://127.0.0.1:11434` | Local Ollama or Ollama Cloud (`https://ollama.com`) endpoint |
| `AEGISPT_OLLAMA_API_KEY` | `""` | Optional Bearer API key for authenticated / cloud Ollama endpoints |
| `AEGISPT_OLLAMA_FAST_MODEL` | `qwen2.5:3b` | Fast parser / extraction model |
| `AEGISPT_OLLAMA_REASONING_MODEL` | `qwen2.5-coder:7b` | Primary planning & triage model |
| `AEGISPT_REMOTE_LLM_URL` | `""` | Optional remote OpenAI-compatible / vLLM endpoint |
| `AEGISPT_REMOTE_LLM_API_KEY` | `""` | Bearer API key for remote OpenAI-compatible LLM endpoint |
| `AEGISPT_REDACT_OUTBOUND` | `true` | Masks tokens, cookies, and JWTs before remote LLM calls |
| `AEGISPT_ZAP_URL` | `http://127.0.0.1:8080` | Optional OWASP ZAP headless daemon API URL |
| `AEGISPT_DEFAULT_TOOL_TIMEOUT` | `180` | Subprocess execution timeout (seconds) |
| `AEGISPT_DEFAULT_MAX_STEPS` | `25` | Default maximum orchestrator iterations |

</details>

<details>
<summary><strong>REST & WebSocket Endpoints</strong></summary>

All `/api/v1/*` routes (except `/api/v1/system/health` and the lab `/oob/*` callback catcher) require `Authorization: Bearer <token>`:

| Group | Endpoints |
| :--- | :--- |
| **System & KB** | `GET /api/v1/system/health`, `GET /api/v1/system/doctor`, `GET /api/v1/system/tools`, `GET /api/v1/system/kb/search` |
| **LLM Profiles** | `GET/POST /api/v1/llm-profiles`, `DELETE /api/v1/llm-profiles/{id}`, `POST /api/v1/llm-profiles/discover` |
| **Engagements & Steering** | `GET/POST /api/v1/engagements`, `GET/DELETE /api/v1/engagements/{id}`, `POST /api/v1/engagements/{id}/{start\|pause\|resume\|stop\|steer\|run-tool\|repeater\|snapshots\|chains/synthesize}`, `GET /api/v1/engagements/{id}/diff`, `GET /api/v1/engagements/{id}/runs/{run_id}/log` |
| **Local Lab OOB** | `ANY /oob/{engagement_id}/{token}`, `GET /api/v1/engagements/{id}/oob` |
| **Approvals, Hypotheses & Findings** | `GET /api/v1/engagements/{id}/approvals`, `POST /api/v1/approvals/{approval_id}/decide`, `GET /api/v1/engagements/{id}/hypotheses`, `PATCH /api/v1/hypotheses/{id}`, `GET/POST /api/v1/engagements/{id}/findings`, `PATCH /api/v1/findings/{finding_id}`, `POST /api/v1/findings/{finding_id}/reverify` |
| **Reports & Stream** | `GET /api/v1/engagements/{id}/report?format=html\|markdown\|sarif\|json\|poc_sh`, `WS /ws/engagements/{id}?token=<token>` |

</details>

---

## Running Tests

```bash
cd aegispt
PYTHONPATH=backend:cli pytest -v backend/tests
```

Covers scope allowlists & DNS boundary checks, SQLite schema auto-migration, 3-tier approval workflows, all 24 tool parsers/native probes (GraphQL, OAuth, JWT, multi-role BOLA, verb BFLA, TOCTOU race burst, JS source maps), LLM routing + failover + secret redaction, attack-chain synthesis, and REST/WebSocket integration.

---

## Contributing & Contributors

Contributions are welcome! Please read [CONTRIBUTING.md](./CONTRIBUTING.md), [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md), and [SECURITY.md](./SECURITY.md) before opening a pull request.

<table>
  <tr>
    <td align="center">
      <a href="https://github.com/willygailo">
        <img src="https://github.com/willygailo.png?size=80" width="72" height="72" alt="@willygailo" /><br />
        <sub><b>@willygailo</b></sub>
      </a><br />
      <sub>Creator &amp; Lead Maintainer</sub>
    </td>
  </tr>
</table>

View full commit history on [GitHub Contributors](https://github.com/willygailo/AI-ko/graphs/contributors).

---

> [!WARNING]
> **Authorized Use Only**: AegisPT is intended strictly for authorized security assessments, defensive hardening, and isolated lab testing. Always obtain explicit written authorization and configure strict scope allowlists before testing any system.
