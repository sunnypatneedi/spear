# Spear

**Defense-in-depth security middleware for LLM I/O pipelines.**

Blocks prompt injection, jailbreaks, PII leaks, and unicode attacks — at every stage of your LLM pipeline, before they reach your model or your users.

<img width="2816" height="1536" alt="Gemini_Generated_Image_frvxrmfrvxrmfrvx" src="https://github.com/user-attachments/assets/0d7267c4-8630-47a5-84af-9ed81dd1b821" />

Install (recommended)
```
npm install spear
```

---

## Why Spear

Most guardrail libraries check one thing. Spear guards the entire pipeline:

```
User Input → InputGate → InstructionShield → [Your LLM] → OutputGate → Response
                                   ↑
                            ToolMediator
                        (for agent/tool calls)
```

| Gate | What it blocks |
|------|----------------|
| **InputGate** | 7 prompt-injection classes, unicode homoglyph attacks, bidirectional text tricks |
| **InstructionShield** | System-prompt exfiltration, privilege escalation via role spoofing |
| **ToolMediator** | Unauthorized tool calls, capability violations (CaMeL-inspired provenance) |
| **OutputGate** | PII leaks, canary exfiltration, response similarity to system prompt |

---

## Quick Start

```typescript
import { quick } from 'spear';

// One line to get a guarded runtime
const runtime = quick('balanced');  // or 'safe' | 'permissive'

// Wrap your LLM call
const pre = await runtime.pre(messages, { sessionId: 'abc' });

if (!pre.allowed) {
  return { error: 'Request blocked' };  // injection detected
}

const llmOutput = await yourLLM(pre.messages);  // sanitized messages

const post = await runtime.post({ output: llmOutput, canary: pre.canary });

if (!post.allowed) {
  return { error: 'Output blocked' };  // leak / canary triggered
}

return { response: post.output };
```

See [QUICK_START.md](./QUICK_START.md) for a full walkthrough including enforce mode, shadow mode, and the Python sidecar.

---

## Installation

```bash
npm install spear
# or
pnpm add spear
```

Requires Node.js ≥ 18 (ESM).

---

## Policies

Three built-in policy profiles ship with the package:

| Profile | Use case | Aggressiveness |
|---------|----------|----------------|
| `balanced` | Production default | Medium |
| `safe` | High-security / enterprise | High |
| `permissive` | Development / testing | Low |

Load by name or bring your own YAML:

```typescript
import { quick, loadPolicy, createRuntime } from 'spear';

// By name (uses bundled policy files)
const runtime = quick('safe');

// Custom YAML file
const policy = loadPolicy('./my-policy.yaml');
const runtime = createRuntime({ policy, mode: 'enforce' });
```

---

## Modes

| Mode | Behaviour |
|------|-----------|
| `shadow` | Log violations, never block — safe for gradual rollout |
| `enforce` | Block requests/responses that fail gates |

Override at runtime:

```typescript
const runtime = quick('balanced', { mode: 'enforce' });
```

Or via environment variable:

```bash
SPEAR_MODE=enforce node server.js
```

---

## API

### `quick(policy?, options?)`

Convenience factory. Returns a `SpearRuntime`.

```typescript
quick('balanced', {
  mode: 'shadow' | 'enforce',
  sidecarUrl: process.env.SPEAR_SIDECAR_URL,  // optional Python sidecar
  budgetMs: 50,                                // max latency per gate (ms)
})
```

### `runtime.pre(messages, context?)`

Runs InputGate + InstructionShield. Returns:

```typescript
{
  allowed: boolean,
  reason?: string,
  messages: Message[],   // sanitized — pass these to your LLM
  canary: string,        // embed in system prompt for exfiltration detection
  riskScore: number,     // 0–1
}
```

### `runtime.post(input, context?)`

Runs OutputGate. Returns:

```typescript
{
  allowed: boolean,
  reason?: string,
  output: string,        // sanitized output
  riskScore: number,
}
```

### Standalone gates

All gates are individually importable for custom pipelines:

```typescript
import { inputGate, outputGate, instructionShield, toolMediator } from 'spear';
```

### PII utilities

```typescript
import { detectPII, maskPII, tokenizePII, detokenizePII } from 'spear';
```

### Data provenance (CaMeL-inspired)

```typescript
import { tagValue, createProvenance, checkCapabilities } from 'spear';
```

---

## Python Sidecar (optional)

For deeper ML-based inspection, run the optional Python sidecar alongside your Node service:

```bash
cd sidecar
docker build -t spear-sidecar .
docker run -p 8088:8088 spear-sidecar

# Tell Spear to use it
SPEAR_SIDECAR_URL=http://localhost:8088 node server.js
```

The sidecar adds semantic similarity checks and embedding-based leak detection that the pure-JS gates can't do.

---

## Eval Harness

Spear ships with a [promptfoo](https://promptfoo.dev) eval harness covering the full red-team corpus:

```bash
npm i -g promptfoo
promptfoo eval -c eval/promptfooconfig.yaml
```

Thresholds: ≤ 0.1% leak rate, ≤ 2% false-block rate. See [PROBE_VERIFICATION_REPORT.md](./PROBE_VERIFICATION_REPORT.md) for results.

---

## Compared to Alternatives

| Library | Prompt injection | Tool RBAC | Canary detection | Policy-as-code | CI eval harness |
|---------|:---:|:---:|:---:|:---:|:---:|
| **Spear** | ✅ | ✅ | ✅ | ✅ | ✅ |
| NeMo Guardrails | ✅ | ❌ | ❌ | partial | ❌ |
| Guardrails AI | ✅ | ❌ | ❌ | ✅ | ❌ |
| LLM Guard | ✅ | ❌ | ❌ | ❌ | ❌ |
| Llama Guard | partial | ❌ | ❌ | ❌ | ❌ |

---

## License

Apache-2.0
