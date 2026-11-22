# Contributing to AegisPT

Thank you for your interest in contributing to **AegisPT**! Whether you are adding a new typed Kali tool adapter, expanding OWASP playbooks, improving the React dashboard, or fixing bugs, we welcome pull requests.

---

## Development Setup

```bash
git clone https://github.com/willygailo/AI-ko.git
cd AI-ko/aegispt
cp .env.example .env

# Run diagnostics (verifies installed Kali binaries & OWASP KB)
./aegispt doctor

# Run the backend test suite
PYTHONPATH=backend:cli pytest -v backend/tests

# Build and typecheck the React frontend
cd frontend
pnpm install
./node_modules/.bin/tsc -b && ./node_modules/.bin/vite build
```

---

## Adding a New Tool Adapter

1. Create a new adapter under `aegispt/backend/app/tools/` inheriting from `BaseToolAdapter`.
2. Define a strict Pydantic `args_schema` and assign the appropriate risk tier:
   - **Tier 1**: Passive recon / safe metadata inspection
   - **Tier 2**: Bounded, rate-limited scanning
   - **Tier 3**: Intrusive verification (always approval-gated in `tiered` mode)
3. Always use `shell=False` `argv` lists via `build_argv()` and respect `scope.max_rps` / `scope.max_concurrency`.
4. Register the adapter in `aegispt/backend/app/tools/registry.py`.
5. Add unit tests with fixture outputs in `aegispt/backend/tests/`.

---

## Pull Request Checklist

- [ ] All tests pass (`PYTHONPATH=backend:cli pytest -v backend/tests`)
- [ ] Frontend builds cleanly (`./node_modules/.bin/tsc -b && ./node_modules/.bin/vite build`)
- [ ] New tool adapters enforce `ScopePolicy` and `shell=False`
- [ ] No secrets, tokens, or `data/` files are staged
- [ ] Follow [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md) and [SECURITY.md](./SECURITY.md)
