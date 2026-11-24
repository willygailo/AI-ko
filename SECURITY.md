# Security Policy

## Supported Versions

Security fixes are applied to the active development branch and latest minor release:

| Version | Supported |
| :--- | :---: |
| `0.1.x` (`main`) | Yes |
| `< 0.1.0` | No |

---

## Authorized Use & Scope Boundaries

AegisPT is built strictly for **authorized security assessments**, **defensive research**, and **isolated lab environments** (such as `aegispt/lab/docker-compose.lab.yml`).

- Never target systems without explicit written authorization.
- Keep `ScopePolicy` allowlists tight and use `tiered` or `copilot` autonomy modes when testing real environments.

---

## Deployment & Secret Handling Model

AegisPT is designed as a **local-first** operator workstation tool with defense-in-depth defaults:

- **File & Directory Permissions**:
  - `aegispt/data/` (or `AEGISPT_DATA_DIR`) is created and enforced with `0700` permissions (owner-only access).
  - Secret and state files — `.api_token`, `.master.key`, `.env` (written by `./aegispt setup`), and SQLite database files — are created atomically where applicable (`O_CREAT | O_EXCL`) and restricted to `0600`.
- **Encryption at Rest**:
  - Stored LLM API keys and engagement primary/secondary auth vaults are encrypted at rest with Fernet (`data/.master.key`).
- **Authentication & Token Protection**:
  - All `/api/v1/*` routes (except `/api/v1/system/health` and the lab `/oob/*` callback catcher) require header-based authentication (`Authorization: Bearer <token>` or `X-API-Key: <token>`). Query-string `?token=` authentication is disabled on REST routes to prevent leaks in access logs and browser history.
  - WebSocket connections (`WS /ws/engagements/{id}`) authenticate via `Authorization: Bearer` headers (CLI/API clients) or short-lived, single-use tickets issued by `POST /api/v1/system/ws-ticket` (Web Dashboard).
  - Startup logs do not print the raw bearer token by default (`AEGISPT_PRINT_TOKEN=0`; retrieve via `./aegispt token`).
  - Outbound calls to non-local LLM endpoints pass through `SecretRedactor` (`AEGISPT_REDACT_OUTBOUND=true`) to mask bearer tokens, cookies, API keys, JWTs, and PEM private keys.

> [!CAUTION]
> **Do NOT bind `AEGISPT_HOST=0.0.0.0` on untrusted or shared networks without TLS and a hardened reverse proxy.**
> AegisPT listens on `127.0.0.1:8443` over plaintext HTTP by default. Binding `0.0.0.0` exposes the control plane, bearer tokens, WebSocket streams, and tool execution API over unencrypted network traffic. If remote access is required, bind to loopback (`127.0.0.1`) and place AegisPT behind an SSH tunnel, Tailscale/WireGuard VPN, or a TLS-terminating reverse proxy with strict IP allowlisting and rotated tokens.

---

## Reporting a Vulnerability in AegisPT

If you discover a security vulnerability in AegisPT itself (e.g., scope bypass, command/shell injection in a tool adapter or report generator, SSRF, authentication flaw, or secret redaction leak):

1. **Do not** open a public GitHub issue or pull request containing exploit details.
2. **Report privately** via [GitHub Security Advisories](https://github.com/willygailo/AI-ko/security/advisories/new) (preferred) or by contacting the repository maintainer (`@willygailo`) directly.
3. **Include details** to help us reproduce and fix the issue quickly:
   - Affected component(s) and file path(s)
   - Clear reproduction steps or minimal proof of concept
   - Assessed impact and any suggested remediation

### Disclosure & Response Timeline

- **Initial acknowledgement**: Within **72 hours** of receiving the report.
- **Triage & severity assessment**: Within **7 days**.
- **Patch & coordinated disclosure**: Target fix within **30 days** for critical/high issues (or an agreed extension if a complex architectural change is needed), with credit to the reporter upon release if desired.
