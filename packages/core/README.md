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
- **Agent boundary**: session budgets, taint circuit breakers, egress/secret scanning,
  unsafe-payload checks, and approval gates

## Session API

For multi-step agent loops (ReAct, LangChain, Vercel AI SDK):

```typescript
const session = spear.session({ sessionId: 'agent-001', userId: 'u-42' });

const step = await session.step(messages);              // canary + circuit breakers
const { allowed, blocked } = await session.tools(toolCalls); // persistent mediation
const observation = await session.observe(results, { source: 'external' });
if (!observation.accepted) throw new Error('Untrusted result quarantined');
const final = await session.complete(output);            // final output gate
const snapshot = session.inspect(); // composed attack findings
```

In enforce mode, stamp each model-produced tool call with a
server-created `selectionProvenance` (for example,
`ProvenanceSource.userInput('agent-request')`). Never let the model supply or
upgrade that provenance itself.

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

## Egress and high-impact actions

Use the egress guard for every network request made by an agent tool. It checks
SSRF targets, cloud metadata addresses, suspicious capture/dead-drop hosts, and
credential-shaped data before the request leaves the process.

```typescript
const response = await spear.guardedFetch(url, {
  method: 'POST',
  body: JSON.stringify(payload)
});
```

In enforce mode, configure an approval verifier for tools that send, delete,
write, deploy, upload, execute code, or handle credentials. The verifier must
be server-controlled; never copy a model-provided approval field into it.

See [`docs/emergent-agent-defense.md`](../../docs/emergent-agent-defense.md)
for the incident-informed threat model and infrastructure requirements.

## Subpath Exports

```typescript
import { sanitize, hasSuspiciousUnicode } from '@spear-secure/core/unicode';
import { quick as edgeQuick } from '@spear-secure/core/edge';
import { SpearCallbackHandler } from '@spear-secure/core/langchain';
import { withSpear } from '@spear-secure/core/vercel-ai';
```

`@spear-secure/core/edge` never touches `fs` / `path`. Pass `policy: loadPolicyFromString(yaml)` or use `getDefaultPolicy()`.

Streaming output:

```typescript
for await (const chunk of spear.postStream(llmStream, { sessionId, canary: pre.canary })) {
  res.write(chunk);
}
```

OpenTelemetry (no OTel dependency in core — pass a callback):

```typescript
const spear = quick('balanced', {
  telemetryExporter: {
    export(event) {
      span.setAttribute('spear.allowed', event.allowed);
    },
  },
});
```

## Full Documentation

See the [monorepo README](../../README.md) for complete API reference, session API examples, and deployment guides.

## License

AGPL-3.0-only

### Hardening migration

`observe()` is asynchronous: await its result before using retrieved data.
`complete()` closes the session; use `runtime.post()` for intermediate outputs.
Enforce-mode tool calls require application-owned selection provenance when
provenance is enabled, and approval-listed actions require `approvalVerifier`.
See [the migration and boundary notes](../../docs/emergent-agent-defense.md#follow-up-integration-on-main)
for payload limits, supported request bodies, and network enforcement limits.
