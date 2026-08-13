# SPEAR Core — AI Agent Instructions

**Parent Guide**: See `/AGENTS.md` for monorepo-level conventions.

This file provides AI-specific guidance for contributing to SPEAR Core (Secure Prompt Enforcement At Runtime).

## Quick Rules

1. **Maintain zero external dependencies** (except yaml, zod, fastest-levenshtein)
2. **Keep adapters in src/adapters/** (integration-specific code isolation)
3. **Add attack patterns to redteam/attacks.txt** with test coverage
4. **Update policies/ YAML** when adding new detection rules
5. **Run `pnpm build && pnpm test`** before committing
6. **Keep TypeScript strict mode** — no `any` types
7. **Add JSDoc comments** for all public APIs

## Package Structure

```
packages/core/
├── src/
│   ├── gates/        # Security gates (standalone, composable)
│   ├── core/         # Utilities (unicode, canary, pii, policy, provenance, runtime, session, emergent)
│   ├── adapters/     # Integration adapters (excluded from build)
│   └── index.ts      # Public API exports
├── policies/         # YAML configurations (balanced, safe, permissive)
├── redteam/          # Attack corpus for testing (not in npm)
├── eval/             # Promptfoo eval harness
└── tests/            # Vitest unit tests
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
