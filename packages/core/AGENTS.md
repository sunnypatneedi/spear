# SPEAR AGENTS.md - AI Agent Instructions

**Parent Guide**: See `/AGENTS.md` for general SayMake conventions.

This file provides AI-specific guidance for contributing to SPEAR (Secure Prompt Enforcement At Runtime).

## Quick Rules

1. ✅ **Maintain zero external dependencies** (except yaml, zod, fastest-levenshtein)
2. ✅ **Keep adapters in src/adapters/** (SayMake-specific code isolation)
3. ✅ **Add attack patterns to redteam/attacks.txt** with test coverage
4. ✅ **Update policies/ YAML** when adding new detection rules
5. ✅ **Run pnpm build && pnpm test** before committing
6. ✅ **Keep TypeScript strict mode** - no any types
7. ✅ **Add JSDoc comments** for all public APIs

## Package Structure

```
packages/sapps/
├── src/
│   ├── gates/        # Security gates (standalone, composable)
│   ├── core/         # Utilities (unicode, canary, pii, policy, runtime)
│   ├── adapters/     # Integration adapters (SayMake-specific)
│   └── index.ts      # Public API exports
├── policies/         # YAML configurations (balanced, safe, permissive)
├── redteam/          # Attack corpus for testing
├── eval/             # Promptfoo eval harness
└── tests/            # Vitest unit tests
```

## Adding New Attack Patterns

1. **Add to redteam/attacks.txt**:
```
# Class X: My New Attack
My new attack pattern
Variant 1
Variant 2
```

2. **Add regex to policies/balanced.yaml**:
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

## Adding New Detectors

```typescript
// src/gates/my_new_gate.ts
export interface MyGateResult {
  allowed: boolean;
  reason?: string;
}

export async function myNewGate(
  input: any,
  policy: Policy
): Promise<MyGateResult> {
  // Detection logic
  return { allowed: true };
}
```

Export in `src/index.ts` and integrate into `src/core/runtime.ts`.

## OSS Extraction Rules

To keep SPEAR OSS-ready:
- ❌ NO imports from @saymake/* packages in core/gates
- ✅ OK in src/adapters/* only
- ❌ NO hardcoded SayMake URLs/IDs
- ✅ Environment variables for configuration
- ❌ NO Supabase/SayMake-specific types in public APIs

## Testing Checklist

- [ ] Unit tests pass (pnpm test)
- [ ] Eval passes with thresholds (pnpm eval)
- [ ] TypeScript compiles (pnpm typecheck)
- [ ] No lint errors (pnpm lint)
- [ ] README updated if public API changed
- [ ] redteam corpus updated if new attack class

## CI Thresholds

- Leak-rate ≤ 0.1%
- False-block ≤ 2%
- p95 latency ≤ 350ms

See `.github/workflows/sapps-ci.yaml` for enforcement.
