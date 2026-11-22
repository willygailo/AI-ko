---
id: skill-graphql-assessment
title: GraphQL Introspection, Oracle & Query Surface Audit
wstg_id: API8:2023 / WSTG-API-GRAPHQL
owasp_category: API8:2023 - Security Misconfiguration
tags: graphql graphiql playground schema introspection query mutation batching
triggers:
  - /graphql
  - /graphiql
  - /playground
recommended_tools:
  - http_probe
  - js_miner
  - katana
---
Evaluate GraphQL endpoint exposure, introspection restrictions, field suggestion leakage, GET CSRF support, and batching posture.
## Checklist
- Probe standard GraphQL routes (`/graphql`, `/api/graphql`, `/v1/graphql`, `/graphiql`) via `http_probe` (`graphql_deep_audit`).
- Verify `__schema` and targeted `__type` introspection enforcement.
- Test whether error responses leak field suggestions (`Did you mean...`) on unknown fields.
- Check whether GET-method GraphQL queries or batched JSON query arrays are accepted without restrictions.
- Import discovered Query and Mutation operations as trackable endpoints in the Attack-Surface Graph.
