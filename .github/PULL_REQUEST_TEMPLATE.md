## Summary

Describe what this PR changes and why.

## Type of Change

- [ ] Bug fix
- [ ] New tool adapter / analyzer
- [ ] Orchestrator / LLM router improvement
- [ ] Web Dashboard / CLI enhancement
- [ ] Documentation / tests

## Verification

- [ ] `PYTHONPATH=backend:cli pytest -v backend/tests` passes
- [ ] Frontend typecheck & build pass (`./node_modules/.bin/tsc -b && ./node_modules/.bin/vite build`)
- [ ] Tool adapters enforce `ScopePolicy` and `shell=False`
