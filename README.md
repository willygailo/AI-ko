<div align="center">

<img src="./docs/assets/aegispt-banner.jpg" alt="AegisPT — Private AI Web & API Penetration Testing Platform" width="100%" />

<br />

# AegisPT

### Private, Provider-Agnostic AI Web & API Penetration Testing Platform

Built for Kali Linux with allowlist-only scope enforcement, 3-tier human-in-the-loop approval gates, 24 typed security tool adapters, modular offensive skill packs, and a real-time Web Dashboard + CLI.

[![CI](https://github.com/willygailo/AI-ko/actions/workflows/ci.yml/badge.svg)](https://github.com/willygailo/AI-ko/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18%20%2B%20TypeScript-61DAFB?style=for-the-badge&logo=react&logoColor=black)](https://react.dev/)
[![Kali Linux](https://img.shields.io/badge/Kali%20Linux-Ready-557C94?style=for-the-badge&logo=kalilinux&logoColor=white)](https://www.kali.org/)

[Screenshots](#web-dashboard-preview) •
[How to Set Up](#how-to-set-up) •
[How to Use](#how-to-use) •
[Architecture](#architecture) •
[Autonomy & Guardrails](#autonomy--safety-guardrails) •
[Tooling Matrix](#3-tier-tooling-matrix) •
[API & Config](#configuration--api-reference) •
[Testing & CI](#running-tests--ci)

</div>

---

## Web Dashboard Preview

<div align="center">

### Interactive Attack-Surface Graph &amp; Live Agent Stream
<img src="./docs/assets/dashboard-attack-graph.jpg" alt="AegisPT Attack-Surface Graph and Live Agent Stream" width="100%" />

<br /><br />

### Findings &amp; Report Studio (Re-Verify, Repeater Pivot &amp; 1-Click Exports)
<img src="./docs/assets/dashboard-findings-studio.jpg" alt="AegisPT Findings and Report Studio" width="100%" />

<br /><br />

<table>
  <tr>
    <td width="50%" align="center">
      <b>Offensive Skill Methodology Checklist (13/18 Covered)</b><br /><br />
      <img src="./docs/assets/dashboard-skills-checklist.jpg" alt="AegisPT Skills Checklist Coverage" width="100%" />
    </td>
    <td width="50%" align="center">
      <b>Scoped Engagement Wizard &amp; Lab Preset</b><br /><br />
      <img src="./docs/assets/dashboard-scope-wizard.png" alt="AegisPT New Scoped Engagement Wizard" width="100%" />
    </td>
  </tr>
</table>

<details>
<summary>View Initial Scoped Workspace (Idle State Before Assessment)</summary>
<br />
<img src="./docs/assets/dashboard-workspace-idle.png" alt="AegisPT Scoped Workspace Idle State" width="100%" />
</details>

</div>

---

## Why AegisPT?

| Pillar | What It Does |
| :--- | :--- |
| **Private & Encrypted at Rest** | FastAPI + WebSocket backend binds strictly to `127.0.0.1:8443` with header-based bearer auth (`data/.api_token`, `0600`), single-use browser WebSocket tickets, owner-only `data/` (`0700`), Fernet-encrypted API keys & primary/secondary auth vaults (`data/.master.key`), scrubbed logs, and idempotent SQLite schema auto-migration. |
| **Provider-Agnostic LLM Router** | Hot-swap between **Local Ollama**, **Ollama Cloud (`https://ollama.com`)**, remote **vLLM / OpenAI-compatible** endpoints, or **Zero-LLM Offline mode** (`AEGISPT_LLM_MODE=offline`) with exponential retry, multi-profile failover, `fast` + `reasoning` tiers, and secret redaction on non-local calls. |
| **Cognitive Multi-Skill Brain** | Risk-weighted endpoint prioritizer (query + body params), Self-Critic gating, signal-activated **SQLite FTS5 Knowledge Base** (`12` OWASP WSTG playbooks + `9` modular Skill Packs = `21` modules), Hypothesis Tracking, Cross-Engagement Skill Stats, **Attack-Chain Synthesis**, and **Live Operator Steering** (`steer`). |
| **Non-Bypassable Scope & Multi-Role Auth** | Default-deny `ScopePolicy` enforces normalized port/path allowlists (with URL-decoding & `posixpath` traversal checks), hop-by-hop redirect SSRF guards, DNS boundaries, encrypted **User A vs. User B** credentials for true IDOR/BOLA verification, bounded local `/oob` lab callback catcher, and `shell=False` typed `argv` execution. |
| **Dual Operator Experience** | Operate from the **React Web Dashboard** (Attack Graph, **Chains**, **Skill Checklist**, Endpoints, Findings + **Re-Verify**, interactive **HTTP Repeater**, **Hypotheses**, **OOB Events**, **Scan Diff**, Raw Log Viewer, **Live Steering**, Approval Modal) or **Kali CLI** (`./aegispt` with automatic `latest` engagement resolution). |
| **Developer-Ready Reporting** | One-click exports in **Print-ready HTML/PDF**, **Markdown**, **SARIF 2.1.0**, **JSON**, and shell-safe **`PoC Replay Script (.sh)`** with Posture Score, Synthesized Attack Chains, OWASP breakdown, CVSS v3.1 scores, PoC commands, and remediation guidance. |

---

## How to Set Up

### Prerequisites

| Requirement | Needed For | Notes |
| :--- | :--- | :--- |
| **Linux / Kali Linux** | Core platform & CLI | Built-in `http_probe`, `js_miner`, and core scanners work anywhere; Kali provides the external CLI binaries (`nmap`, `ffuf`, `nuclei`, `sqlmap`, `dalfox`, etc.) |
| **Python 3.11+** | Backend & CLI | Required (`python3 -m venv` recommended on clean systems) |
| **Node.js 24+ & `pnpm`** | Building the Web UI | Only needed when building or developing `aegispt/frontend` |
| **Docker + Compose** *(Optional)* | Practice lab | For running the isolated localhost-only OWASP Juice Shop lab (`127.0.0.1:3000`) |
| **LLM Provider** *(Optional)* | AI planning & triage | **Ollama Cloud**, **Local Ollama**, **OpenAI-compatible / vLLM**, or **Zero-LLM Offline mode** |

### Step 1: Clone the Repository & Install Python Dependencies

```bash
git clone https://github.com/willygailo/AI-ko.git
cd AI-ko/aegispt

# Create an isolated virtualenv (recommended — ./aegispt detects .venv automatically)
python3 -m venv .venv
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -e ".[dev]"
```

<details>
<summary>Optional: Enable Playwright SPA Inspector &amp; Shell Tab Completion</summary>

```bash
# Enable headless Chromium SPA inspection (`spa_inspector`)
.venv/bin/pip install -e ".[spa]"
.venv/bin/playwright install chromium

# Enable CLI tab completion for bash/zsh/fish
./aegispt --install-completion
```

The [`./aegispt`](./aegispt/aegispt) launcher automatically prefers `aegispt/.venv/bin/python3` when present and works even when symlinked (for example, `sudo ln -s "$PWD/aegispt" /usr/local/bin/aegispt`).

</details>

### Step 2: Build the Web Dashboard UI

```bash
cd frontend
pnpm install --frozen-lockfile
pnpm build
cd ..
```

This builds `aegispt/frontend/dist/`, which the FastAPI server mounts automatically at `http://127.0.0.1:8443`.

### Step 3: Configure Your AI Provider (Web UI or Optional `.env` Wizard)

> [!TIP]
> **Easiest Way (Web Dashboard)**: You can skip editing `.env`—just run `./aegispt serve`, sign in at `http://127.0.0.1:8443`, and click **`API Key / AI Settings`** in the top bar to paste your **Ollama Cloud** (or OpenAI-compatible) API key.

If you prefer configuring via the terminal before starting the server:

```bash
cp .env.example .env
./aegispt setup
```

Choose whichever mode fits your machine:

- **Option 1 — Ollama Cloud (0 MB local RAM)**:
  ```bash
  ./aegispt setup --provider cloud
  ```
  Configures `https://ollama.com` and stores your API key in `.env` (`0600`). You can also pass `--api-key-stdin` to avoid putting secrets in shell history.
- **Option 2 — Local Ollama (100% offline on your machine)**:
  ```bash
  # Default --light profile: qwen2.5:1.5b + qwen2.5:3b (~2.5 GB, ideal for 7.5–8 GB RAM)
  ./scripts/setup_ollama.sh

  # Or --coder profile for 12+ GB RAM: qwen2.5:3b + qwen2.5-coder:7b (~6.5 GB)
  ./scripts/setup_ollama.sh --coder

  ./aegispt setup --provider local
  ```
- **Option 3 — Zero-LLM Offline Mode (no AI backend required)**:
  ```bash
  ./aegispt setup --provider offline
  ```
  Sets `AEGISPT_LLM_MODE=offline` to run deterministic OWASP WSTG + Skill Pack planning with zero outbound LLM requests.

### Step 4: Verify Your Environment

```bash
# Check all 24 tool adapters, 21 KB playbooks/skills, and LLM reachability
./aegispt doctor        # Add --json for machine-readable output

# Browse all 24 tools & 12 native http_probe modes with example arguments
./aegispt tools         # Optional: --tier 1 | 2 | 3
```

---

## How to Use

### 1. Start AegisPT (One Command — Prints Your Token Automatically)

```bash
cd aegispt
./aegispt serve
```

- Starts the Web Dashboard & REST/WebSocket API on **`http://127.0.0.1:8443`** and **immediately prints your copy-pasteable `aegis_...` Local API Token** right in the terminal (no second terminal needed!).
- Copy the printed `aegis_...` token line, open **`http://127.0.0.1:8443`**, paste the token, and click **API Key / AI Settings** in the top bar to paste your AI API key.
- *(Tip: You can also run `./aegispt token` or `./aegispt token --raw` anytime if you ever need to retrieve the token separately, or pass `./aegispt serve --hide-token` to suppress printing it on startup.)*

---

### 2. Option A — Use the Web Dashboard (`http://127.0.0.1:8443`)

1. **Sign In**: Copy the `aegis_...` token printed by `./aegispt serve`, open `http://127.0.0.1:8443`, and click **Paste from Clipboard** (or `Ctrl+V`) → **Connect to Local Engine**.
2. **Paste Your AI API Key**: Click **API Key / AI Settings** in the top header, paste your **Ollama Cloud** (or OpenAI-compatible) API key into the **API Key** box, and click **Save LLM Profile**.
3. **Create a Scoped Engagement**: Click **`+ New`** to open the **Scope Wizard**:
   - Enter authorized **Target URLs** / **Allowed Domains** (or click **Load Juice Shop Lab Preset** for local lab practice).
   - Set **Allowed CIDRs**, **Excluded Hosts/Paths**, **Max Steps**, and **Autonomy Mode** (`tiered`, `copilot`, or `lab_autopilot`).
   - Optionally add **User A / User B** headers or cookies in the encrypted **Multi-Role Auth Vault** to enable automated BOLA/IDOR testing.
4. **Run, Steer & Approve**:
   - Click **Start** to launch the Cognitive Orchestrator.
   - Watch real-time progress in the **Live Agent Stream** and **Attack Graph**.
   - Send mid-assessment guidance anytime via the **Live Steering** bar (e.g., *"Focus on GraphQL and JWT checks"*).
   - When a **Tier 3** intrusive verification is proposed in `tiered` mode, review the exact command preview in the **Approval Modal** and choose **Approve**, **Modify Args**, or **Reject**.
5. **Triage, Replay & Export Reports**:
   - Inspect **Endpoints**, **Hypotheses**, **Skills**, **Chains**, **Runs** (with raw log viewer), **OOB Events**, and **Scan Diff** snapshots.
   - Open **Findings** to mark items **Confirmed** / **False Positive**, click **Re-Verify**, or click **Send to Repeater** to craft and replay custom HTTP requests (with copyable `curl` commands).
   - Export reports in one click: **HTML**, **Markdown**, **SARIF 2.1.0**, **JSON**, or a shell-safe **PoC Replay Script (`.sh`)**.

---

### 3. Option B — Use the Kali CLI (`./aegispt`) with the Local Practice Lab

Spin up the hardened, localhost-only (`127.0.0.1:3000`) OWASP Juice Shop lab container:

```bash
cd aegispt
docker compose -f lab/docker-compose.lab.yml up -d
```

Run a full scoped assessment from your terminal (`latest` engagement ID is used automatically when omitted):

```bash
# 1. Create a scoped engagement (add -H / --secondary-header for multi-role IDOR checks)
./aegispt engagement create \
  --name "Local Juice Shop" \
  --url http://127.0.0.1:3000 \
  --allow-private-ips \
  --mode tiered

# 2. Optional: guide the AI brain toward specific attack surfaces
./aegispt steer "Focus on GraphQL, JWT alg=none, and multi-role BOLA checks"

# 3. Start & stream live progress with interactive Tier-3 [a]pprove / [e]dit / [r]eject prompts
./aegispt run

# 4. Pause, resume, re-attach, stop, or run any single tool on demand
./aegispt pause
./aegispt resume
./aegispt attach
./aegispt stop
./aegispt run-tool http_probe http://127.0.0.1:3000 --args '{"mode":"passive_audit"}'
./aegispt approvals
./aegispt snapshots
./aegispt llm-profiles

# 5. Inspect runs, hypotheses, skill coverage, attack chains, findings, deltas & replay HTTP
./aegispt runs
./aegispt hypotheses
./aegispt checklist
./aegispt chains
./aegispt findings
./aegispt findings triage <finding_id> --status confirmed
./aegispt findings reverify <finding_id>
./aegispt diff
./aegispt repeat http://127.0.0.1:3000/api/Products

# 6. Export HTML, JSON, SARIF, or shell-safe PoC replay scripts
./aegispt report --format html --out report.html
./aegispt report --format json --out report.json
./aegispt report --format sarif --out report.sarif
./aegispt report --format poc_sh --out verify_findings.sh
```

When finished practicing, tear down the local lab container:

```bash
docker compose -f lab/docker-compose.lab.yml down
```

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
        OLLAMA["Local Ollama (1.5B-7B) / Ollama Cloud"]
        REMOTE["Remote vLLM / OpenAI-Compatible / Offline Mode"]
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

## Configuration & API Reference

<details>
<summary><strong>Repository Structure</strong></summary>

```text
.
├── .github/
│   ├── PULL_REQUEST_TEMPLATE.md
│   └── workflows/ci.yml                # GitHub Actions CI (backend, frontend, security)
├── .gitignore
├── .gitleaksignore                     # Allowlist for known synthetic test-fixture fingerprints
├── .pre-commit-config.yaml             # Ruff + pre-commit hygiene & private-key hooks
├── Makefile                            # Root DevEx entrypoints (check, lint, test, build-ui, dev)
├── README.md
├── CONTRIBUTING.md / CODE_OF_CONDUCT.md / SECURITY.md
├── docs/assets/                        # README hero banner & Web Dashboard screenshots
└── aegispt/
    ├── aegispt                         # Symlink- & .venv-aware CLI launcher script (./aegispt)
    ├── pyproject.toml                  # Dependencies, extras, Ruff/Pytest/Pyrefly/Pyright config
    ├── .env.example                    # Complete environment configuration template
    ├── README.md                       # Subproject Quick Start
    ├── TOOLS_AND_SETUP.md              # AI backend setup & 24-tool operator guide
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
    │   └── tests/                      # Automated backend, security & CLI pytest suite
    ├── cli/aegispt_cli/                # Typer + Rich CLI client
    ├── frontend/                       # React + Vite + TypeScript + Tailwind UI & tests
    ├── lab/docker-compose.lab.yml      # Localhost-only hardened OWASP Juice Shop target
    └── scripts/setup_ollama.sh         # Optional local Ollama model pull helper (--light / --coder)
```

</details>

<details>
<summary><strong>Environment Variables (<code>aegispt/.env</code>)</strong></summary>

| Variable | Default | Description |
| :--- | :--- | :--- |
| `AEGISPT_HOST` | `127.0.0.1` | Bind address for FastAPI server (see [SECURITY.md](./SECURITY.md) before changing) |
| `AEGISPT_PORT` | `8443` | HTTP / WebSocket server port |
| `AEGISPT_SERVER_URL` | `""` | Optional CLI override when targeting a non-default server URL |
| `AEGISPT_API_TOKEN` | _(auto-generated)_ | Fixed bearer token; if blank, created atomically (`0600`) in `data/.api_token` |
| `AEGISPT_PRINT_TOKEN` | `1` *(via `./aegispt serve`)* | `./aegispt serve` prints the copy-pasteable `aegis_...` token by default; set `AEGISPT_PRINT_TOKEN=0` or pass `--hide-token` to suppress it |
| `AEGISPT_DATA_DIR` | `./data` | Storage directory (`0700`) for SQLite DBs, vault keys, logs, and tool artifacts |
| `AEGISPT_LLM_MODE` | `auto` | LLM mode: `auto` (use configured provider) or `offline` (disable all outbound LLM calls) |
| `AEGISPT_OLLAMA_URL` | `http://127.0.0.1:11434` | Local Ollama or Ollama Cloud (`https://ollama.com`) endpoint |
| `AEGISPT_OLLAMA_API_KEY` | `""` | Optional Bearer API key for authenticated / cloud Ollama endpoints |
| `AEGISPT_OLLAMA_FAST_MODEL` | `qwen2.5:3b` | Fast parser / extraction model (`qwen2.5:1.5b` under `--light`) |
| `AEGISPT_OLLAMA_REASONING_MODEL` | `qwen2.5-coder:7b` | Primary planning & triage model (`qwen2.5:3b` under `--light`) |
| `AEGISPT_REMOTE_LLM_URL` | `""` | Optional remote OpenAI-compatible / vLLM endpoint |
| `AEGISPT_REMOTE_LLM_API_KEY` | `""` | Bearer API key for remote OpenAI-compatible LLM endpoint |
| `AEGISPT_REMOTE_FAST_MODEL` | `""` | Fast model ID for remote OpenAI-compatible endpoint |
| `AEGISPT_REMOTE_REASONING_MODEL` | `""` | Reasoning model ID for remote OpenAI-compatible endpoint |
| `AEGISPT_REDACT_OUTBOUND` | `true` | Masks tokens, cookies, API keys, JWTs, and private keys before non-local LLM calls |
| `AEGISPT_ZAP_URL` | `http://127.0.0.1:8080` | Optional OWASP ZAP headless daemon API URL |
| `AEGISPT_ZAP_API_KEY` | `""` | Optional API key for OWASP ZAP daemon |
| `AEGISPT_DEFAULT_TOOL_TIMEOUT` | `180` | Subprocess execution timeout (seconds) |
| `AEGISPT_MAX_OUTPUT_BYTES` | `2097152` | Maximum captured stdout/stderr bytes per tool execution (2 MiB) |
| `AEGISPT_DEFAULT_MAX_STEPS` | `25` | Default maximum orchestrator iterations per engagement |
| `AEGISPT_APPROVAL_TIMEOUT_SECONDS` | `3600` | Timeout (seconds) before pending Tier-3 approval requests expire |

</details>

<details>
<summary><strong>Authentication &amp; REST / WebSocket Endpoints</strong></summary>

- **REST Authentication**: All `/api/v1/*` routes (except `/api/v1/system/health` and the lab `/oob/*` callback catcher) require header authentication via `Authorization: Bearer <token>` (or `X-API-Key: <token>`). Query-parameter `?token=` authentication is disabled on REST endpoints to prevent secret leakage in access logs and browser history.
- **WebSocket Authentication**: `WS /api/v1/engagements/{id}/ws` (and legacy alias `WS /ws/engagements/{id}`) accepts `Authorization: Bearer <token>` headers (used by the CLI and API clients) or a short-lived, single-use `?ticket=<ticket>` issued by `POST /api/v1/system/ws-ticket` (used by the React Web Dashboard).

| Group | Endpoints |
| :--- | :--- |
| **System, Auth & KB** | `GET /api/v1/system/health`, `GET /api/v1/system/doctor`, `GET /api/v1/system/tools`, `GET /api/v1/system/kb/search`, `POST /api/v1/system/ws-ticket` |
| **LLM Profiles** | `GET/POST /api/v1/llm-profiles`, `POST /api/v1/llm-profiles/{id}/default`, `DELETE /api/v1/llm-profiles/{id}`, `POST /api/v1/llm-profiles/discover` |
| **Engagements & Steering** | `GET/POST /api/v1/engagements`, `GET/DELETE /api/v1/engagements/{id}`, `POST /api/v1/engagements/{id}/{start\|pause\|resume\|stop\|steer\|run-tool\|repeater\|snapshots\|chains/synthesize}`, `GET /api/v1/engagements/{id}/diff`, `GET /api/v1/engagements/{id}/runs/{run_id}/log` |
| **Local Lab OOB** | `ANY /oob/{engagement_id}/{token}`, `GET /api/v1/engagements/{id}/oob` |
| **Approvals, Hypotheses & Findings** | `GET /api/v1/engagements/{id}/approvals`, `POST /api/v1/approvals/{approval_id}/decide`, `GET /api/v1/engagements/{id}/hypotheses`, `PATCH /api/v1/hypotheses/{id}`, `GET/POST /api/v1/engagements/{id}/findings`, `PATCH /api/v1/findings/{finding_id}`, `POST /api/v1/findings/{finding_id}/reverify` |
| **Reports & Stream** | `GET /api/v1/engagements/{id}/report?format=html\|markdown\|sarif\|json\|poc_sh` (and `/reports/{format}`), `WS /api/v1/engagements/{id}/ws` (`Authorization: Bearer` header or `?ticket=<single-use-ticket>`) |

</details>

---

## Running Tests & CI

Run the full CI-equivalent verification suite (Ruff, pytest, ShellCheck, frontend typecheck/lint/tests/build, and Docker Compose validation) from the repository root:

```bash
make check
```

Or run individual test suites:

```bash
# Backend & CLI lint + automated tests
cd aegispt && ruff check backend cli && pytest -v

# Frontend typecheck, lint, unit tests, and production build
cd aegispt/frontend && pnpm typecheck && pnpm lint && pnpm test && pnpm build
```

Automated CI ([`.github/workflows/ci.yml`](./.github/workflows/ci.yml)) runs on every push to `main` and pull request across three jobs:
- **Backend, CLI & Shell Checks**: Python 3.12 editable install (`pip install -e "./aegispt[dev]"`), Ruff lint & import sorting (`E4`, `E7`, `E9`, `F`, `I`), the full **75-test** backend/security/tool/CLI `pytest` suite, and `shellcheck` on launcher/setup scripts.
- **Frontend Typecheck, Lint, Test & Build**: Node 24 + `pnpm` 11 frozen install (`allowBuilds.esbuild: true`), strict `tsc --noEmit`, AST lint checks, **19** Node 24 unit tests, and Vite production bundle build.
- **Secret Scan & Lab Compose Validation**: Gitleaks secret scanning (`gitleaks/gitleaks-action@v2`) and `docker compose` validation of the hardened Juice Shop lab.

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
