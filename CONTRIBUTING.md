# Contributing to AegisPT

Thank you for your interest in contributing to **AegisPT**! Whether you are adding a new typed Kali tool adapter, expanding OWASP playbooks, improving the React dashboard, or fixing bugs, we welcome pull requests.

---

## Development Setup

```bash
git clone https://github.com/willygailo/AI-ko.git
cd AI-ko/aegispt
cp .env.example .env
pip install -e ".[dev]"

# Optional: enable pre-commit hooks (ruff, trailing whitespace, YAML & secret checks)
pre-commit install

# Run diagnostics (verifies installed Kali binaries, OWASP KB, and LLM config)
./aegispt doctor

# Install frontend dependencies
cd frontend
pnpm install --frozen-lockfile
```

### Verification Commands

Run the full CI-matching suite from the repository root:

```bash
make check
```

Or run individual checks:

```bash
# Backend & CLI lint + unit/integration tests
cd aegispt && ruff check backend cli && pytest -v

# Frontend typecheck, lint, unit tests, and production build
cd aegispt/frontend && pnpm typecheck && pnpm lint && pnpm test && pnpm build

# Shell scripts & Docker lab validation
shellcheck aegispt/aegispt aegispt/scripts/setup_ollama.sh
docker compose -f aegispt/lab/docker-compose.lab.yml config -q
```

---

## Adding a New Tool Adapter

1. Create a new adapter under `aegispt/backend/app/tools/` inheriting from `BaseToolAdapter`.
2. Define a strict Pydantic `args_schema` and assign the appropriate risk tier:
   - **Tier 1**: Passive recon / safe metadata inspection
   - **Tier 2**: Bounded, rate-limited scanning
   - **Tier 3**: Intrusive verification (always approval-gated in `tiered` mode)
3. Always use `shell=False` `argv` lists via `build_argv()`, quote any generated PoC commands with `shlex.quote()`, filter discovered targets against `ScopePolicy`, and respect `scope.max_rps` / `scope.max_concurrency`.
4. Register the adapter in `aegispt/backend/app/tools/registry.py`.
5. Add unit tests with fixture outputs in `aegispt/backend/tests/`.

---

## Pull Request Checklist

- [ ] `make check` passes (or backend `ruff check backend cli && pytest -v` and frontend `pnpm typecheck && pnpm lint && pnpm test && pnpm build` pass)
- [ ] Shell scripts and lab compose validate cleanly (`shellcheck` and `docker compose ... config -q`)
- [ ] New tool adapters enforce `ScopePolicy` and `shell=False`
- [ ] No secrets, tokens, `.env`, or `aegispt/data/` files are staged
- [ ] Follow [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md) and [SECURITY.md](./SECURITY.md)
