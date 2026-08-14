# @spear-secure/core

**Defense-in-depth security middleware for LLM I/O pipelines.**

## Installation

```bash
npm install @spear-secure/core
pnpm add @spear-secure/core
```

Requires **Node.js >= 18** (ESM).

## Quick Start

```typescript
import { quick } from '@spear-secure/core';

const spear = quick('balanced');

// Pre-gate: scan input, embed canary, sanitize
const pre = await spear.pre(messages, { sessionId: 'abc' });
if (!pre.allowed) throw new Error(pre.reason);

// Your LLM call
const response = await llm(pre.messages);

// Post-gate: scan output, detect exfiltration, mask PII
const post = await spear.post({ output: response, canary: pre.canary });
```

## Architecture

Every request flows through four gates:

```
User Input → InputGate → InstructionShield → [LLM] → OutputGate → Safe Response
                                                ↕
                                          ToolMediator
```

- **InputGate**: Unicode normalization, 7-class injection detection
- **InstructionShield**: Role hierarchy enforcement, system prompt protection
- **OutputGate**: Canary exfiltration detection, PII masking, encoded leak scanning
- **ToolMediator**: CaMeL-inspired data provenance, capability-based tool RBAC
- **Emergent defense**: Session-level compositions (collect-then-exfil, goal hijack, split canary)

## Session API

For multi-step agent loops (ReAct, LangChain, Vercel AI SDK):

```typescript
const session = spear.session({ sessionId: 'agent-001', userId: 'u-42' });

const step = await session.step(messages);          // pre-gate with persistent canary
const { allowed, blocked } = await session.tools(toolCalls); // batch tool checks
session.observe(results, { source: 'external' });   // tag tool outputs with provenance
const snapshot = session.inspect();                  // emergent composition findings
const final = await session.complete(output);        // final output gate
```

## Policy Profiles

| Profile | Aggressiveness | Use case |
|---------|---------------|----------|
| `balanced` | Medium | Production default |
| `safe` | High | Enterprise / regulated |
| `permissive` | Low | Development / testing |

## Shadow Mode

Start in shadow (log only), flip to enforce when ready:

```typescript
const spear = quick('balanced', { mode: 'shadow' });
// Later:
const spear = quick('balanced', { mode: 'enforce' });
```

## Subpath Exports

```typescript
import { sanitize, hasSuspiciousUnicode } from '@spear-secure/core/unicode';
import { detectPII, tokenizePII } from '@spear-secure/core/pii';
```

## Full Documentation

See the [monorepo README](../../README.md) for complete API reference, session API examples, and deployment guides.

## License

AGPL-3.0-only
