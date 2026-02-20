# SPEAR (Secure Prompt Enforcement At Runtime)

**Defense-in-depth security middleware for LLM I/O pipelines.**

See full implementation plan in `docs/SPEAR_PLAN.md` (513 lines)

## Overview

SPEAR provides comprehensive protection against prompt injection, jailbreaks, and tool-abuse attacks on LLM systems.

**Architecture**: Input→InputGate→InstructionShield→[LLM]→OutputGate→Output

**Core Components**:
- **InputGate**: Unicode normalization, pattern-based detection (7 attack classes)
- **InstructionShield**: Role hierarchy enforcement
- **ToolMediator**: RBAC + schema validation
- **OutputGate**: Canary detection, PII masking, similarity checks

## Quick Start

```typescript
import { quick } from '@spear-secure/core';

const runtime = quick('balanced');
const preResult = await runtime.pre(messages, { sessionId: 'abc' });
const llmOutput = await yourLLM(preResult.messages);
const postResult = await runtime.post({ output: llmOutput, canary: preResult.canary });
```

## Comparables

- **NeMo Guardrails**: SPEAR adds tool RBAC + canary CI
- **Guardrails AI**: SPEAR adds canary audit + tool mediation
- **LLM Guard/Rebuff**: SPEAR orchestrates + enforces at gates
- **Promptfoo/PyRIT**: SPEAR integrates into CI gates
- **Llama Guard**: Complementary, used at I/O stages

**SPEAR Unique Value**: End-to-end pipeline, provable auditing, tool RBAC, policy-as-code, composable

## License

Apache-2.0
