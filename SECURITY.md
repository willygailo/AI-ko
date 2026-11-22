# Security Policy

## Authorized Use & Scope Boundaries

AegisPT is built strictly for **authorized security assessments**, **defensive research**, and **isolated lab environments** (such as `aegispt/lab/docker-compose.lab.yml`).

- Never target systems without explicit written authorization.
- Keep `ScopePolicy` allowlists tight and use `tiered` or `copilot` autonomy modes when testing real environments.

## Reporting a Vulnerability in AegisPT

If you discover a security vulnerability in AegisPT itself (e.g., scope bypass, command injection in a tool adapter, authentication flaw, or secret redaction leak):

1. **Do not** open a public issue with exploit details.
2. Report it privately via GitHub Security Advisories or contact the repository maintainer (`@willygailo`).
3. Include reproduction steps, affected file paths, and potential impact so we can patch and release a fix promptly.
