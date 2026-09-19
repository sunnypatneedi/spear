# SPEAR technical architecture

![SPEAR agent security architecture](spear.png)

The diagram describes the TypeScript core on main at commit
[`ddd7cc4`](https://github.com/sunnypatneedi/spear/commit/ddd7cc4b0735f0b7880bd744de54bba9f772abfe),
including the hardening merged in PR #29. It is a runtime integration map,
not a deployment topology or a claim of complete attack prevention.

## What is distinctive about this design?

| Design choice | Technical value | Implementation |
| --- | --- | --- |
| Checks at multiple agent boundaries | Mediate model input, final output, proposed tool calls and retrieved results | [Runtime](../../packages/core/src/core/runtime.ts), [gates](../../packages/core/src/gates/) |
| Session state across steps | Combine persistent canaries, peak risk, budgets, repeated-call limits and taint circuit breakers | [Session](../../packages/core/src/core/session.ts), [canaries](../../packages/core/src/core/canary.ts) |
| Provenance and verified approval | Evaluate where tool choices/arguments came from and invoke an application-owned approval verifier for configured high-impact actions | [ToolMediator](../../packages/core/src/gates/tool_mediator.ts), [provenance](../../packages/core/src/core/provenance.ts) |
| Composed-attack inspection | Look for dangerous tool sequences and goal shifts that individual calls may not reveal | [EmergentTracker](../../packages/core/src/core/emergent.ts) |
| Policy as code | Review configuration in git; observe violations in shadow mode before enforcing | [Policy](../../packages/core/src/core/policy.ts), [presets](../../packages/core/policies/) |
| Guarded HTTP egress | Inspect URL destinations and transmitted secrets in supported request data | [Egress](../../packages/core/src/core/egress.ts) |

These are architectural characteristics, not a benchmark or a claim that no
other security product has comparable controls.

## Plain-language labels and code names

The diagram uses everyday language. Developers can use this table to find the
matching implementation; the interactive diagram also retains source links.

| Diagram label | Implementation |
| --- | --- |
| Check requests | `InputGate` + `InstructionShield`, through `session.step()` |
| Your AI assistant | Application-owned agent / LLM call |
| Check answers | `OutputGate`, through `session.complete()` |
| Your safety rules | YAML policy; shadow and enforce modes |
| Approve actions | `ToolMediator`, through `session.tools()` |
| Apps and information | Application tools, APIs and retrieval |
| Check outgoing data | Opt-in `guardedFetch()` HTTP wrapper |
| Track ongoing risk | `SpearSession` budgets, taint and emergent tracker |
| Check incoming results | `session.observe()` |

## Read the diagram

1. Your application calls `session.step()` and invokes its chosen LLM only when allowed.
2. Proposed tool calls pass through `session.tools()`. SPEAR returns decisions;
   your application executes the allowed calls.
3. Await `session.observe(results, { source: 'external' })` before reusing tool or
   retrieval results. Rejected observations should be quarantined. Observations
   feed session state; in enforce mode, taint can block later steps, tools and
   completion. The diagram shows the tool circuit breaker as one example.
4. Use `session.complete()` for the final response and honor its verdict and
   returned output. The output gate checks canary leakage and configured PII rules.
5. Route application HTTP calls through `spear.guardedFetch()` to inspect egress.
   This wrapper is not automatically installed in arbitrary tools or SDKs.

The policy arrow represents configuration shared by all SPEAR controls. Session
memory also includes the emergent tracker; it is not a separate hosted service.
The application owns the loop back to the next model step.

## Trust and deployment limits

- Controls depend on the selected policy and mode. The `collect_then_exfiltrate`
  rule is enabled in the safe YAML preset and disabled in balanced; both presets
  enable other emergent checks. Shadow mode
  records violations without enforcing the corresponding blocks.
- Provenance labels and approval verification must come from trusted application
  code. Model-supplied labels or approval tokens are not proof of authorization.
- URL checks do not resolve and pin DNS destinations. Use infrastructure egress
  controls for DNS rebinding protection and traffic outside the wrapper.
- Isolate shell/code-execution tools and use scoped, short-lived credentials.
  SPEAR is application middleware, not a kernel or network sandbox.
- Input and secret detectors are heuristic. The diagram does not imply perfect
  detection, automatic data lineage, or a guarantee of safe model output.

## Edit and export with Archify

The editable source is [spear.architecture.json](spear.architecture.json).
Download [spear.html](spear.html) and open it locally for source links, zoom,
light/dark themes and the built-in PNG/SVG export menu. GitHub does not execute
the interactive viewer inside its file preview.

Generated with [Archify](https://github.com/tt-a1i/archify), revision
`72c750bb070d95171dbb2244e5b62b1b7da69c12` (skill version 2.17).
From a SPEAR checkout, with that Archify checkout available:

```bash
node "$ARCHIFY_ROOT/archify/bin/archify.mjs" validate architecture \
  docs/architecture/spear.architecture.json --repo-root . --quality showcase --json
node "$ARCHIFY_ROOT/archify/bin/archify.mjs" deliver architecture \
  docs/architecture/spear.architecture.json docs/architecture/spear.html \
  --repo-root . --quality showcase --json
node "$ARCHIFY_ROOT/archify/bin/archify.mjs" visual-check \
  docs/architecture/spear.html --json
```

Use the viewer's Export → PNG action in the light theme to replace `spear.png`.
Preserve the pinned repository revision until the diagram's claims are reviewed
against a newer commit. The [delivery receipt](receipt.json) records the exact
specification and HTML hashes; PNG export is a separate artifact.
