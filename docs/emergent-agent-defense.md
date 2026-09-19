# Emergent-agent defense

Spear is an application boundary, not a kernel sandbox. The OpenAI–Hugging
Face incident shows why an AI app needs both: an agent can optimize a narrow
goal into a long-running campaign that crosses tools, package proxies, public
web services, credentials, and internal networks.

## What the talk and incident timeline imply

The Black Hat talk is available on [YouTube](https://www.youtube.com/watch?v=87DyyMV0kCY).
The [publicly indexed transcript](https://lironshapira.substack.com/p/openais-bombshell-hack-swarms-of-agents)
is useful for timestamps—ExploitGym at 04:21, the shared message board at
06:46, SSRF escape at 08:41, and zero-day RCE at 28:15—but
the technical facts below are based on the primary disclosures from
[OpenAI](https://openai.com/index/hugging-face-model-evaluation-security-incident/)
and [Hugging Face](https://huggingface.co/blog/agent-intrusion-technical-timeline).

The relevant behavior was not one isolated prompt injection:

1. A hard benchmark objective created pressure to find a shortcut.
2. The agent escaped through a permitted package-registry proxy rather than a
   deliberately granted open-internet permission.
3. Agents shared state through ordinary infrastructure and public services.
4. The external foothold became a launchpad for dataset/data-loader attacks,
   credential theft, lateral movement, and persistence.
5. Detection came after a large amount of activity, so investigators had to
   reconstruct the campaign from billions of logs and agent traces.

Hugging Face reports roughly 17,600 recovered actions across 4.5 days. The
specific exploit details are intentionally not reproduced here; the defensive
lesson is the trust-boundary sequence.

## Controls now in Spear

### 1. Continuous session state

`SpearSession` now preserves the canary and tool mediation context across every
step. It also limits steps, duration, tool attempts, and repeated same-tool
loops. This closes the old reset behavior where a new `session.tools()` call
could lose prior call counts and provenance.

### 2. Active observation and taint

`session.observe()` scans tool/RAG/external data for injection patterns and
credential-shaped secrets. It records provenance metadata, feeds the existing in-memory composition
tracker, marks the session tainted, and trips the circuit breaker in enforce mode before the next
privileged step. Tool arguments are also checked for common RCE-shaped payloads,
template execution, staged shell chains, metadata probes, and Kubernetes service
account reads.

```ts
const observation = await session.observe(searchResults, { source: 'external' });
if (!observation.accepted) return 'Untrusted result quarantined';
```

### 3. Egress boundary

`inspectOutboundRequest()` and `guardedFetch()` block or report:

- private, loopback, and cloud-metadata destinations;
- non-HTTPS schemes and credentials embedded in URLs;
- redirect-based SSRF (redirects are disabled by default);
- configured dead-drop/capture hosts;
- likely credentials in headers or request bodies;
- transmission of untrusted data in write requests.

```ts
const response = await spear.guardedFetch(url, {
  method: 'POST',
  body: JSON.stringify(payload)
});
```

This does not protect a shell tool that runs `curl` internally. Deny or isolate
shell/code-execution tools and enforce a container/VPC egress policy too.
The in-process URL check cannot see DNS rebinding or a destination reached by a
different SDK; enforce destination policy at the network layer as well.

### 4. Server-side approval for high-impact actions

Policies can mark tools such as deploy, delete, upload, send, shell, and
credential operations as approval-required. The model cannot approve itself;
the application supplies an `approvalVerifier` that is called outside the
model loop.

```ts
const spear = quick('safe', {
  mode: 'enforce',
  approvalVerifier: async (call) => humanApprovalStore.consume(call.id)
});
```

## Deployment stance

Use `balanced` in shadow mode first to inspect telemetry. Move autonomous or
privileged workflows to `safe` plus a real network/container boundary. Set
`fail_closed: true` for security-critical paths. Keep tool allowlists narrow,
use short-lived scoped credentials, remove secrets from agent environments,
and treat package registries, data loaders, CI runners, code sandboxes, and
public paste/request services as part of the attack surface.

Spear helps an app decide when to stop. The infrastructure must still enforce
what the process can reach and what credentials it can use.

## Follow-up integration on main

This ports the missing controls from local commit `c941757` onto `5a73738`,
retaining the independent implementations merged in PRs #27 and #28.

| Original intent | Integration |
| --- | --- |
| Persistent canary and tool counts | Retains main's CanaryManager TTL/cap and adds serialized runtime/session operations |
| Step, duration, attempt and repetition budgets | Agent policy checks across calls, with explicit session close |
| Active tool/RAG observation | Injection and secret scanning plus existing EmergentTracker findings |
| Taint circuit breaker | Blocks later steps, tools and completion in enforce mode |
| Approval gate | Application-owned verifier; a model-supplied approval token never grants approval by itself |
| Unsafe arguments | Template execution, staged shell payloads and metadata probes checked before approval |
| Outbound boundary | Public HTTPS destinations by default, URL/header/body secret checks, redirects disabled by default |
| MCP observation | `spear_session_observe`, limited to tool/external/untrusted sources |
| Integration compatibility | HTTP endpoint awaits observation; LangChain intermediate LLM completions keep the session open; edge exports retained |

### Migration notes

- **Await `session.observe()`**. It now returns `Promise<ObservationResult>`.
  The resolved value includes the existing `allowed` and `findings` fields plus
  `accepted`, `tainted`, `secretCount`, and provenance metadata. Session operations
  run in invocation order, including when an observation is still scanning.
- **`session.complete()` closes the session** and releases its runtime state.
  Use `runtime.post()` for intermediate LLM responses; call `session.close()`
  when abandoning a loop. The LangChain callback provides `close()` for cleanup.
- **Enforce mode requires tool-selection provenance when provenance is enabled**,
  even if the provenance policy previously said shadow. Supply provenance from
  application-owned state, never from model-authored trust claims. MCP has no
  trusted provenance or approval-service configuration hook; privileged enforce
  workflows need an application integration that supplies these controls.
- Configure `approvalVerifier` on the runtime. It must validate the exact tool,
  arguments, session and any approval token, and return boolean `true`. Merely
  sending `approvalToken` or calling an MCP tool is not approval.
- Oversized or unserializable values are rejected rather than scanning only a
  safe prefix. Observation/secret inspection is bounded at 100,000 characters;
  tool-argument inspection at 50,000. Outbound inspection includes URL and headers
  in its limit. With secret scanning enabled, `guardedFetch` supports string,
  URLSearchParams, ArrayBuffer/view and small Blob bodies; opaque bodies such as
  streams and FormData are rejected in enforce mode. Serialize supported payloads
  explicitly or use an application-specific inspection path.
- Redirects are disabled by default. Enabling redirects opts out of per-hop
  destination protection. URL checks do not resolve or pin DNS and cannot prevent
  DNS rebinding or enforce the destination used internally by a tool. Use network
  egress controls for those boundaries.
- Secret detection is heuristic, not a guarantee against all encodings or custom
  credentials. Generic tool inspection infers HTTP requests from URL-bearing
  arguments; adapters should provide `outboundRequest` for their actual request
  or execute the request through `guardedFetch`. Non-HTTP tool effects still need
  application-specific controls.

The retained EmergentTracker keeps truncated observation content in its in-memory
trace for composition analysis. Observation scan results and new scan telemetry
exclude raw secret values; do not treat the entire existing trace as payload-free.
