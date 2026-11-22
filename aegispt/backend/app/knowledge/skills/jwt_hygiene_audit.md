---
id: skill-jwt-hygiene-audit
title: JSON Web Token (JWT) Signature & Claims Audit
wstg_id: API2:2023 / WSTG-SESS-10
owasp_category: API2:2023 - Broken Authentication
tags: jwt bearer token auth session eyj alg none exp kid
triggers:
  - jwt
  - bearer
  - authorization
recommended_tools:
  - http_probe
  - js_miner
---
Audit JWT headers, claims, and server signature verification hygiene across API endpoints and client storage.
## Checklist
- Passively inspect JWT headers and claims (`http_probe` `passive_audit`) for `exp` presence and sensitive payload keys.
- Run approval-gated `http_probe` (`jwt_active_probe`) to verify the server rejects `alg: none` and stripped signatures.
- Audit JWT header metadata (`kid`, `jku`, `x5u`) and ensure tokens are not hardcoded in client JS (`js_miner` / `trufflehog`).
- Check locally whether observed HMAC tokens use trivial placeholder secrets (`secret`, `changeme`, `password`).
