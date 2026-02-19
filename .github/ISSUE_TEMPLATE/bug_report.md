---
name: Bug report
about: A gate is blocking something it shouldn't, or letting something through it shouldn't
title: '[bug] '
labels: bug
assignees: ''
---

## What happened

<!-- Describe the unexpected behavior -->

## Expected behavior

<!-- What should Spear have done? -->

## Reproduction

```typescript
import { quick } from '@spear-secure/core';

const runtime = quick('balanced');

// paste the input that triggered the issue
const result = await runtime.pre([
  { role: 'user', content: '...' }
]);

console.log(result);
```

## Environment

- Spear version:
- Node.js version:
- Policy profile: `balanced` / `safe` / `permissive` / custom
- Mode: `shadow` / `enforce`

## Gate involved

- [ ] InputGate
- [ ] InstructionShield
- [ ] ToolMediator
- [ ] OutputGate
- [ ] Not sure

## Is this a false positive or false negative?

- [ ] **False positive** — Spear blocked something it should have allowed
- [ ] **False negative** — Spear allowed something it should have blocked
