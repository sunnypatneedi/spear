# AGENTS.md — AI Agent Instructions for Spear

This file guides AI coding agents contributing to Spear (`github.com/sunnypatneedi/spear`).

## Quick Rules

1. **Maintain zero external dependencies** in core (except `yaml`, `zod`, `fastest-levenshtein`)
2. **All source code lives in `packages/`** — the root is a pure workspace coordinator
3. **Add attack patterns to `packages/core/redteam/attacks.txt`** with test coverage
4. **Update `packages/core/policies/` YAML** when adding new detection rules
5. **Run `pnpm build && pnpm test`** before committing
6. **Keep TypeScript strict mode** — no `any` types
7. **Add JSDoc comments** for all public APIs

## Monorepo Structure

```
spear/
├── .github/workflows/
│   ├── ci.yml                  # Single CI workflow (pnpm)
│   └── publish.yml             # npm publish on release
├── packages/
│   ├── core/                   # @spear-secure/core (published)
│   │   ├── src/core/           # canary, pii, policy, provenance, runtime, session, unicode, emergent
│   │   ├── src/gates/          # input_gate, instruction_shield, tool_mediator, output_gate
│   │   ├── src/adapters/       # supabase-edge.ts (excluded from build)
│   │   ├── policies/           # balanced.yaml, safe.yaml, permissive.yaml
│   │   ├── redteam/            # Attack corpus (not in npm)
│   │   ├── eval/               # Promptfoo config
│   │   └── tests/              # Vitest tests
│   ├── hook/                   # @spear-secure/hook (published)
│   ├── mcp/                    # @spear-secure/mcp (published)
│   └── cli/                    # Planned stub
├── services/sidecar/           # Python ML similarity service
├── examples/
│   ├── basic/
│   └── edge-function/
├── docs/
├── llms.txt
├── tsconfig.base.json
├── pnpm-workspace.yaml
├── package.json                # Pure workspace coordinator
└── README.md
```

## Adding New Attack Patterns

1. **Add to `packages/core/redteam/attacks.txt`**:
```
# Class X: My New Attack
My new attack pattern
Variant 1
Variant 2
```

2. **Add regex to `packages/core/policies/balanced.yaml`**:
```yaml
input_rules:
  regex_block:
    - '(?i)my[ -]?new[ -]?pattern'
```

3. **Test it**:
```bash
pnpm test
pnpm eval  # Runs promptfoo
```

## Testing Rules

All test files use ESM-safe `__dirname` shim — **never use bare `__dirname`**:

```typescript
// CORRECT — required for NodeNext ESM
import { dirname } from 'path';
import { fileURLToPath } from 'url';
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
```

All imports must use `.js` extensions (NodeNext resolution):

```typescript
import { inputGate } from '../src/gates/input_gate.js';  // correct
import { inputGate } from '../src/gates/input_gate';      // wrong
```

## Testing Checklist

- [ ] Unit tests pass (`pnpm test`)
- [ ] Eval passes with thresholds (`pnpm eval`)
- [ ] TypeScript compiles (`pnpm typecheck`)
- [ ] No lint errors (`pnpm lint`)
- [ ] README updated if public API changed
- [ ] redteam corpus updated if new attack class

## CI Thresholds

- Leak-rate <= 0.1%
- False-block <= 2%
- p95 latency <= 350ms

See `.github/workflows/ci.yml` for enforcement.

## ESM Pitfalls (from production bugs)

| Don't | Do | Why |
|-------|-----|-----|
| Module-level `/g` regex with `.test()` | Inline non-`/g` literals for `.test()` | `.test()` advances `lastIndex` — alternating calls return wrong result |
| `catch { return getDefaultPolicy() }` | `catch { throw new Error('Policy load failed') }` | Silent fallback = tests pass against empty policy |
| Bare `__dirname` in test files | ESM `fileURLToPath` shim | Undefined in ESM — causes `ReferenceError` |
| Import without `.js` extension | Always include `.js` in imports | NodeNext module resolution requires it |
