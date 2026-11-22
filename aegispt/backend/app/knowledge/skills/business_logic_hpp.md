---
id: skill-business-logic-hpp
title: Business Logic State Transitions & Parameter Consistency
wstg_id: WSTG-BUSL-01 / WSTG-INPV-04
owasp_category: A04:2021 - Insecure Design
tags: logic hpp parameter_pollution price quantity discount workflow form json xml
triggers:
  - /cart
  - /checkout
  - /order
  - /payment
  - /settings
recommended_tools:
  - http_probe
  - arjun
  - paramspider
---
Evaluate multi-step workflows, client-supplied numeric/pricing fields, and parser consistency across query strings and request bodies.
## Checklist
- Map multi-step transaction paths and body parameter keys from JS bundles (`js_miner`) and SPA XHR inspection (`spa_inspector`).
- Verify parser consistency across `application/json` vs `application/x-www-form-urlencoded` and duplicate parameters (`http_probe` `hpp_and_content_switch`).
- Audit client-side bundles for feature flags or debug toggles hidden in UI but reachable via API.
