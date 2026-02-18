# SAPPS (Secure AI Prompt Protection System)

**Defense-in-depth security middleware for LLM I/O pipelines.**

See full implementation plan in `docs/SAPPS_PLAN.md` (513 lines)

## Overview

SAPPS provides comprehensive protection against prompt injection, jailbreaks, and tool-abuse attacks on LLM systems.

**Architecture**: Input→InputGate→InstructionShield→[LLM]→OutputGate→Output

**Core Components**:
- **InputGate**: Unicode normalization, pattern-based detection (7 attack classes)
- **InstructionShield**: Role hierarchy enforcement
- **ToolMediator**: RBAC + schema validation
- **OutputGate**: Canary detection, PII masking, similarity checks

## Quick Start

```typescript
import { quick } from '@saymake/sapps';

const runtime = quick('balanced');
const preResult = await runtime.pre(messages, { sessionId: 'abc' });
const llmOutput = await yourLLM(preResult.messages);
const postResult = await runtime.post({ output: llmOutput, canary: preResult.canary });
```

## Comparables

- **NeMo Guardrails**: SAPPS adds tool RBAC + canary CI
- **Guardrails AI**: SAPPS adds canary audit + tool mediation
- **LLM Guard/Rebuff**: SAPPS orchestrates + enforces at gates
- **Promptfoo/PyRIT**: SAPPS integrates into CI gates
- **Llama Guard**: Complementary, used at I/O stages

**SAPPS Unique Value**: End-to-end pipeline, provable auditing, tool RBAC, policy-as-code, composable

## License

Apache-2.0
