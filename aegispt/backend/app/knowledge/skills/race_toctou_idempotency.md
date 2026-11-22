---
id: skill-race-toctou-idempotency
title: Concurrency, Idempotency & TOCTOU Timing Audit
wstg_id: API4:2023 / WSTG-BUSL-09
owasp_category: API4:2023 - Unrestricted Resource Consumption
tags: race toctou concurrent idempotency coupon redeem checkout transfer withdraw vote
triggers:
  - /coupon
  - /redeem
  - /checkout
  - /transfer
  - /withdraw
  - /vote
  - /apply
recommended_tools:
  - http_probe
---
Verify single-use business actions and quota-limited endpoints enforce atomic database locking or idempotency keys under concurrent bursts.
## Checklist
- Identify state-mutating endpoints handling balances, coupons, votes, or rate-limited verification tokens.
- Run approval-gated `http_probe` (`race_burst_probe`) sending synchronized parallel requests to measure lock/idempotency behavior.
- Inspect whether multiple concurrent calls return `200/201` instead of `409 Conflict` / `429 Too Many Requests`.
