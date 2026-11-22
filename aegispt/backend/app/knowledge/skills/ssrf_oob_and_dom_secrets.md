---
id: skill-ssrf-oob-dom-secrets
title: URL Handling Hygiene, Secret Scanning & SPA DOM Audit
wstg_id: API7:2023 / WSTG-CLNT-01
owasp_category: API7:2023 - Server Side Request Forgery
tags: ssrf webhook callback url sourcemap secret trufflehog gitleaks dom xss spa
triggers:
  - url=
  - callback=
  - webhook
  - redirect=
  - .js
  - .map
recommended_tools:
  - js_miner
  - trufflehog
  - gitleaks
  - spa_inspector
  - http_probe
---
Audit URL/callback parameters safely within scope, detect exposed source maps and client credentials, and inspect SPA DOM sinks.
## Checklist
- Mine client JS bundles and `.js.map` source maps (`js_miner`) for hidden routes, JSON body keys, and DOM sinks.
- Run `trufflehog` / `gitleaks` against downloaded in-scope artifacts to verify leaked credentials with masked reporting.
- Validate redirect parameters (`http_probe` `open_redirect_probe`) and local lab OOB callback URLs cleanly within scope.
- Capture dynamic XHR/Fetch JSON body parameters via `spa_inspector` when available.
