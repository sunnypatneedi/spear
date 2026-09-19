# SPEAR competitive review

Reviewed: September 19, 2026.

## Scope and method

This desk review covers the four alternatives previously named in the README,
adds Meta's dedicated injection classifier, and includes Lakera's Guard API as a
commercial content and action-security alternative. It is not an exhaustive market survey. The
comparison separates documented capabilities from our assessment of product fit.
We read official repositories, documentation and model cards; we did not run
competitors, buy services, or compare accuracy, latency, price or support quality.

SPEAR's code basis is main at `ddd7cc4b0735f0b7880bd744de54bba9f772abfe`, including
PR #29. Repository capabilities do not establish availability in every npm release.
Competitor docs are live pages, accessed on the review date; development-branch
features may differ from installed releases. Check the chosen version before adoption.

## Corrections to the previous table

| Previous impression | Finding and evidence |
| --- | --- |
| Only SPEAR checks retrieved content or tools | NeMo defines retrieval and execution rails alongside input/output and dialog rails. Its configuration includes YAML, Colang and custom actions. [NeMo documentation](https://github.com/NVIDIA-NeMo/Guardrails#types-of-guardrails) |
| LLM Guard does not address indirect injection | Its injection scanner describes external-content attacks and RAG scenarios. The project separately documents sensitive-output redaction. [Injection scanner](https://protectai.github.io/llm-guard/input_scanners/prompt_injection/), [sensitive scanner](https://protectai.github.io/llm-guard/output_scanners/sensitive/) |
| Other guardrail systems force a fixed block/no-block choice | Guardrails AI supports user-configured failure actions and custom validators. Lakera documents Detect/Enforce project modes. These are related rollout options, not necessarily identical to SPEAR's runtime semantics. [Validators](https://guardrailsai.com/guardrails/docs/concepts/validators), [project modes](https://docs.lakera.ai/docs/projects) |
| Llama Guard represents Meta's injection protection | Llama Guard 4 classifies content safety, including multimodal input. Prompt Guard 2 targets injection/jailbreak attempts. Neither model alone is an application authorization system. [Llama Guard 4](https://huggingface.co/meta-llama/Llama-Guard-4-12B), [Prompt Guard 2](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M) |
| Only SPEAR examines agent actions across context | Lakera documents deterministic tool allow/deny lists and a beta Dangerous Deviation detector that assesses tool calls using conversation history and trusted user/system intent. It also screens tool results as untrusted content. [Agent Behavior Defense](https://docs.lakera.ai/docs/agent-behavior-defense) |
| All listed open-source alternatives remain maintained | LLM Guard's README explicitly marks the repository and associated models as archived and unmaintained. [Project notice](https://github.com/protectai/llm-guard) |

The old table also marked competitor canaries, provenance, session APIs and tool
RBAC as absent without sufficient evidence. Those blanket negatives are removed.
Customizability is not the same as an equivalent turnkey implementation, but lack
of a matching feature name is not proof of absence either.

## Recommended positioning (our assessment)

**SPEAR helps TypeScript developers control what an AI agent can do across a whole
task, alongside checks on what it reads and says.**

The strongest supported story is the combination of controls in one API:

- [Session coordination](../packages/core/src/core/session.ts): operation ordering,
  step/time/tool budgets, observed-result taint and peak risk.
- [Action mediation](../packages/core/src/gates/tool_mediator.ts): configured tool
  permissions, trusted provenance inputs and application-owned approval verification.
- [Cross-step inspection](../packages/core/src/core/emergent.ts): configured sequence
  and goal-shift checks, rather than treating each message independently.
- [Leak and egress checks](../packages/core/src/core/egress.ts): outbound request
  inspection complements [canary detection](../packages/core/src/core/canary.ts).

This supports a focused integration proposition, not an exclusive moat or evidence
of better detection. NeMo's flow control, Guardrails AI's structured-output focus,
and Meta's classifiers solve overlapping but distinct jobs. Lakera overlaps directly in action security as well as content screening; its
beta behavior detector makes it especially relevant for evaluation. They may be alternatives or complementary components, depending
on where the application needs enforcement. No tested SPEAR integration with those
products is implied.

## Limits and next evidence to build

SPEAR depends on correct application wiring, trustworthy provenance labels and
approval callbacks. Its detectors are heuristic. Policy presets enable different
checks; for example, safe enables `collect_then_exfiltrate` while balanced disables
that rule. URL checks do not resolve and pin DNS, and shell/SDK traffic can bypass
an HTTP wrapper. See the [architecture limits](architecture/README.md).

Recommended follow-up work, not completed as part of this documentation change:

1. Run a reproducible comparison on the same benign and adversarial agent tasks,
   with pinned product versions, policies, model settings and hardware. Measure
   successful unauthorized actions, false blocks, task completion and added latency.
2. Ablate content scanning, provenance, budgets and sequence detection to show
   which controls contribute beyond a standalone classifier.
3. Publish executable integration examples with realistic approvals and trusted
   provenance. Measure setup effort as well as detection quality.
4. Recheck maintenance status and product docs before a release or public launch;
   replace the date only after reviewing the evidence again.

Build/unit-test success verifies repository consistency; it does not validate a
competitive security ranking. No superiority claim should be added without the
comparison above.
