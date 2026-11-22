---
id: skill-oauth-oidc-hygiene
title: OAuth 2.0 & OIDC Configuration Hygiene Audit
wstg_id: API2:2023 / WSTG-ATHN-05
owasp_category: API2:2023 - Broken Authentication
tags: oauth oidc openid authorize callback state pkce redirect_uri token
triggers:
  - /oauth
  - /authorize
  - /.well-known/openid-configuration
  - /callback
recommended_tools:
  - http_probe
  - katana
---
Audit OAuth 2.0 / OIDC discovery endpoints, PKCE support, `state` CSRF enforcement, and `redirect_uri` strict allowlist validation.
## Checklist
- Inspect `/.well-known/openid-configuration` via `http_probe` (`oauth_audit`) for deprecated implicit (`token`) grant types.
- Verify `code_challenge_methods_supported` advertises `S256` PKCE support.
- Check whether `/authorize` enforces unguessable `state` parameters and rejects unregistered `.invalid` `redirect_uri` domains.
- Verify no open redirect exists on the same origin that could chain with `redirect_uri` (`open_redirect_probe`).
