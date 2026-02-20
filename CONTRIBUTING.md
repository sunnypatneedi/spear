# Contributing to Spear

Thanks for wanting to help make LLM pipelines safer. Contributions of all kinds are welcome — bug reports, new attack probes, gate improvements, policy tuning, and documentation.

## Quick Start

```bash
git clone https://github.com/sunnypatneedi/spear
cd spear
pnpm install
pnpm build
pnpm test
```

## Types of Contributions

### 1. New attack probes (highest value)

The red-team corpus in `packages/core/redteam/` is what drives Spear's detection quality. If you find a prompt injection technique that Spear misses, add it:

1. Add the raw attack string to `packages/core/redteam/attacks.txt` (or the appropriate language file)
2. Write a failing test in `packages/core/tests/high-signal-probes.test.ts`
3. Fix the gate so the test passes
4. Open a PR

### 2. Bug reports

Open an issue using the **Bug Report** template. Include:
- The input that caused unexpected behavior
- Which gate was involved
- Whether you're in `shadow` or `enforce` mode
- Your policy profile

### 3. Gate improvements

The four gates live in `packages/core/src/gates/`. Each has a corresponding test file in `packages/core/tests/`.

- Fix a false positive → add a test case that should pass through
- Fix a false negative → add a test case that should be blocked
- Run `pnpm test` before submitting

### 4. New policy options

Policies live in `packages/core/src/core/policy.ts` (schema) and `packages/core/policies/*.yaml` (profiles). If you're adding a new knob, update the schema, add it to all three policy files, and document it in the README.

### 5. Documentation

The README, QUICK_START.md, and inline JSDoc are all fair game. Clear documentation is a feature.

## Development Workflow

```bash
pnpm build          # compile TypeScript (all packages)
pnpm test           # run unit tests
pnpm typecheck      # type check without emitting
pnpm lint           # ESLint
```

Tests in `packages/core/tests/` cover the full gate pipeline. The eval harness in `packages/core/eval/` runs the complete red-team corpus against promptfoo — run it with `pnpm eval`.

## Pull Request Guidelines

- Keep PRs focused — one concern per PR
- Include a test for every behavior change
- Update the relevant docs if you're changing the public API
- The CI must pass (build + typecheck + lint + tests)

## Security Vulnerabilities

Please don't open public issues for security vulnerabilities. See [SECURITY.md](./SECURITY.md) for the responsible disclosure process.

## Contributor License Agreement

By opening a pull request, you agree to the [Contributor License Agreement](./CLA.md). Your contributions will be licensed under [AGPL-3.0-only](./LICENSE).
