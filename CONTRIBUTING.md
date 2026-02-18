# Contributing to Spear

Thanks for wanting to help make LLM pipelines safer. Contributions of all kinds are welcome — bug reports, new attack probes, gate improvements, policy tuning, and documentation.

## Quick Start

```bash
git clone https://github.com/sunnypatneedi/spear
cd spear
npm install
npm run build
npm test
```

## Types of Contributions

### 1. New attack probes (highest value)

The red-team corpus in `redteam/` is what drives Spear's detection quality. If you find a prompt injection technique that Spear misses, add it:

1. Add the raw attack string to `redteam/attacks.txt` (or the appropriate language file)
2. Write a failing test in `tests/high-signal-probes.test.ts`
3. Fix the gate so the test passes
4. Open a PR

### 2. Bug reports

Open an issue using the **Bug Report** template. Include:
- The input that caused unexpected behavior
- Which gate was involved
- Whether you're in `shadow` or `enforce` mode
- Your policy profile

### 3. Gate improvements

The four gates live in `src/gates/`. Each has a corresponding test file in `tests/`.

- Fix a false positive → add a test case that should pass through
- Fix a false negative → add a test case that should be blocked
- Run `npm test` before submitting

### 4. New policy options

Policies live in `src/core/policy.ts` (schema) and `policies/*.yaml` (profiles). If you're adding a new knob, update the schema, add it to all three policy files, and document it in the README.

### 5. Documentation

The README, QUICK_START.md, and inline JSDoc are all fair game. Clear documentation is a feature.

## Development Workflow

```bash
npm run build       # compile TypeScript
npm test            # run unit tests
npm run typecheck   # type check without emitting
npm run lint        # ESLint
```

Tests in `tests/` cover the full gate pipeline. The eval harness in `eval/` runs the complete red-team corpus against promptfoo — run it with `npm run eval`.

## Pull Request Guidelines

- Keep PRs focused — one concern per PR
- Include a test for every behavior change
- Update the relevant docs if you're changing the public API
- The CI must pass (build + typecheck + lint + tests)

## Security Vulnerabilities

Please don't open public issues for security vulnerabilities. See [SECURITY.md](./SECURITY.md) for the responsible disclosure process.

## License

By contributing, you agree that your contributions will be licensed under the [Apache-2.0 License](./LICENSE).
