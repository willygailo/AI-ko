---
id: skill-idor-bola-multi-role
title: Broken Object Level Authorization (BOLA / IDOR) Multi-Identity Check
wstg_id: API1:2023 / WSTG-ATHZ-04
owasp_category: API1:2023 - Broken Object Level Authorization
tags: idor bola authorization user order account profile secondary_auth uuid
triggers:
  - /users
  - /orders
  - /profile
  - /account
  - /invoices
  - /basket
recommended_tools:
  - http_probe
  - katana
  - js_miner
---
Compare access to object-referenced resources across primary identity, secondary/low-privilege identity, and unauthenticated sessions.
## Checklist
- Collect endpoints containing numeric IDs, UUIDs, or user-scoped path segments.
- Replay requests with `http_probe` (`differential_bola`) comparing User A vs User B (when `secondary_auth` is configured) and Unauthenticated sessions.
- Verify both read (`GET`) and state-mutating (`PUT`/`DELETE`) authorization boundaries.
- Discover hidden query/body object identifier parameters with `arjun` and `js_miner`.
