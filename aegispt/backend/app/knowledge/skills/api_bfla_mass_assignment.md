---
id: skill-api-bfla-mass-assignment
title: API BFLA, Verb Consistency & Schema Strictness
wstg_id: API5:2023 / API3:2023
owasp_category: API5:2023 - Broken Function Level Authorization
tags: api rest admin role put patch delete bfla mass_assignment verb method
triggers:
  - /api
  - /rest
  - /admin
  - /users
recommended_tools:
  - http_probe
  - arjun
  - ffuf
---
Verify that every administrative or state-changing REST endpoint enforces function-level authorization consistently across HTTP verbs and rejects unexpected schema properties.
## Checklist
- Test GET, POST, PUT, PATCH, DELETE, and OPTIONS behavior consistency on privileged or restricted paths (`http_probe` `bfla_verb_tamper`).
- Check method-override headers (`X-HTTP-Method-Override`) for authorization mismatch.
- Verify server strictly ignores unexpected privilege fields (`role`, `isAdmin`, `permissions`) via `hpp_and_content_switch`.
- Audit OpenAPI schemas (`http_probe` `api_discovery`) for undocumented admin routes.
