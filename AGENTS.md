# AGENTS.md — AI Agent Instructions for Spear

This file guides AI coding agents contributing to Spear (`github.com/sunnypatneedi/spear`).

## Quick Rules

1. ✅ **Maintain zero external dependencies** (except `yaml`, `zod`, `fastest-levenshtein`)
2. ✅ **No `@saymake/*` or internal monorepo imports** — Spear is a standalone public package
3. ✅ **Add attack patterns to `redteam/attacks.txt`** with test coverage
4. ✅ **Update `policies/` YAML** when adding new detection rules
5. ✅ **Run `npm run build && npm test`** before committing
6. ✅ **Keep TypeScript strict mode** — no `any` types
7. ✅ **Add JSDoc comments** for all public APIs

## Package Structure

```
spear/
├── src/
│   ├── gates/        # Security gates (standalone, composable)
│   │   ├── input_gate.ts
│   │   ├── instruction_shield.ts
│   │   ├── tool_mediator.ts
│   │   └── output_gate.ts
│   ├── core/         # Utilities (unicode, canary, pii, policy, provenance, runtime, session)
│   └── index.ts      # Public API exports
├── policies/         # YAML configurations (balanced, safe, permissive)
├── redteam/          # Attack corpus for testing
├── eval/             # Promptfoo eval harness
└── tests/            # Vitest unit tests
```

## Adding New Attack Patterns

1. **Add to `redteam/attacks.txt`**:
```
# Class X: My New Attack
My new attack pattern
Variant 1
Variant 2
```

2. **Add regex to `policies/balanced.yaml`**:
```yaml
input_rules:
  regex_block:
    - '(?i)my[ -]?new[ -]?pattern'
```

3. **Test it**:
```bash
npm test
npm run eval  # Runs promptfoo
```

## Adding New Detectors

```typescript
// src/gates/my_new_gate.ts
import type { Policy } from '../core/policy.js';

export interface MyGateResult {
  allowed: boolean;
  reason?: string;
}

export async function myNewGate(
  input: unknown,
  policy: Policy
): Promise<MyGateResult> {
  // Detection logic
  return { allowed: true };
}
```

Export in `src/index.ts` and integrate into `src/core/runtime.ts`.

## Testing Rules

All test files use ESM-safe `__dirname` shim — **never use bare `__dirname`**:

```typescript
// CORRECT — required for NodeNext ESM
import { dirname } from 'path';
import { fileURLToPath } from 'url';
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// WRONG — undefined in ESM, causes silent policy fallback
const policy = loadPolicy('../policies/balanced.yaml'); // uses __dirname internally
```

All imports must use `.js` extensions (NodeNext resolution):

```typescript
import { inputGate } from '../src/gates/input_gate.js';  // ✅
import { inputGate } from '../src/gates/input_gate';      // ❌
```

## Testing Checklist

- [ ] Unit tests pass (`npm test`)
- [ ] Eval passes with thresholds (`npm run eval`)
- [ ] TypeScript compiles (`npm run typecheck`)
- [ ] No lint errors (`npm run lint`)
- [ ] README updated if public API changed
- [ ] redteam corpus updated if new attack class

## CI Thresholds

- Leak-rate ≤ 0.1%
- False-block ≤ 2%
- p95 latency ≤ 350ms

See `.github/workflows/spear-ci.yaml` for enforcement.

## ESM Pitfalls (from production bugs)

| ❌ Don't | ✅ Do | Why |
|----------|-------|-----|
| Module-level `/g` regex with `.test()` | Inline non-`/g` literals for `.test()` | `.test()` advances `lastIndex` — alternating calls return wrong result |
| `catch { return getDefaultPolicy() }` | `catch { throw new Error('Policy load failed') }` | Silent fallback = tests pass against empty policy |
| Bare `__dirname` in test files | ESM `fileURLToPath` shim | Undefined in ESM — causes `ReferenceError` |
| Import without `.js` extension | Always include `.js` in imports | NodeNext module resolution requires it |
