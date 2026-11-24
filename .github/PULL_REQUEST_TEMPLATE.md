## Summary

Describe what this PR changes and why.

## Type of Change

- [ ] Bug fix
- [ ] New tool adapter / analyzer
- [ ] Orchestrator / LLM router improvement
- [ ] Web Dashboard / CLI enhancement
- [ ] Security hardening
- [ ] Documentation / CI / tests

## Verification

- [ ] Full check passes (`make check`) — or individually:
  - [ ] Backend & CLI lint + tests pass (`cd aegispt && ruff check backend cli && pytest -v`)
  - [ ] Frontend checks & build pass (`cd aegispt/frontend && pnpm typecheck && pnpm lint && pnpm test && pnpm build`)
  - [ ] Shell scripts & lab compose validate (`shellcheck aegispt/aegispt aegispt/scripts/setup_ollama.sh` and `docker compose -f aegispt/lab/docker-compose.lab.yml config -q`)
- [ ] Tool adapters enforce `ScopePolicy` and `shell=False`
- [ ] No secrets, tokens, or `aegispt/data/` artifacts are staged
