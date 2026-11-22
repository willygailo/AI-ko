---
id: skill-waf-adaptive-posture
title: WAF Detection & Adaptive Assessment Pacing
wstg_id: WSTG-INFO-02 / WSTG-CONF-06
owasp_category: A05:2021 - Security Misconfiguration
tags: waf cloudflare akamai modsecurity incapsula awswaf rate_limit adaptive
triggers:
  - cloudflare
  - modsecurity
  - akamai
  - aws waf
  - imperva
recommended_tools:
  - wafw00f
  - dnsx
  - http_probe
---
Adapt scan concurrency, template selection, and false-positive filtering when a protective WAF or CDN sits in front of the target.
## Checklist
- Identify WAF/CDN vendor via `wafw00f` and response headers.
- Reduce `nuclei`/`ffuf` noise and prioritize native passive/schema/API authorization verification (`http_probe`, `js_miner`) that does not trigger false-positive 403 block pages.
- Verify TLS/DNS posture (`sslscan`, `dnsx`) and origin header security (`http_probe` `passive_audit`).
