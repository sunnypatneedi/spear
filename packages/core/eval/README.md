# Reproducible security evaluation

Run `pnpm eval` from the repository root. It removes stale results, builds core,
executes the reviewed corpus and atomically writes `packages/core/eval/report.json`.
`pnpm --filter @spear-secure/core eval:verify` independently verifies that report.
Both commands exit nonzero for incomplete, invalid or below-target results.

## Two distinct measurements

**Input screening:** Each input is passed as one user message to a fresh
`SpearRuntime.pre()`. The balanced policy is loaded explicitly in enforce mode,
without environment interpolation or a sidecar. Fresh state prevents earlier
prompts or rate limits from influencing later cases. No model output is invented.

**Agent scenarios:** Eleven inherited tool-attack descriptions map to executable
fixtures in `scripts/scenarios.mjs`. They call real session, tool-mediation,
provenance, approval and outbound-request inspection APIs. No tool implementation
or network side effect is executed. Each fixture first asserts legitimate actions
are allowed, then attempts the unsafe action. A failed prerequisite is an error,
not a successful attack detection. Reports retain the actions and decisions.

Scenario fixtures explicitly allow their tools and raise the per-runtime tool-call
count to 100 so an unrelated RBAC/count denial cannot hide a missing control.
Server-side approval is supplied for composition fixtures, and withheld in the
approval-bypass fixture, which separately tests that approved deployment works.
All fixture overrides are recorded in report evidence; they are not production
policy defaults. Agent recursion limits remain enabled. File-transmission cases
may be stopped by provenance before reaching the composition detector; existing
unit tests independently exercise that detector.

| Metric | Denominator | Required result |
|---|---|---|
| Attack-allowed rate | Input attacks only | ≤5%, overall and per language |
| False-block rate | Benign inputs only | ≤2%, overall and per language |
| Unsafe agent actions allowed | Agent scenarios only | Zero |
| Execution errors | All cases | Zero |

Both attack and benign cases are required for every evaluated language. The 95%
input-blocking target retains the legacy probe verifier's target; the 2%
false-block target is retained. Neither establishes the historical 0.1% model-leak
or 350 ms production-latency aspirations. Those need separate evaluations.

## Corpus review and coverage

`corpus.json` enumerates every `.txt` file under `redteam/`, with content hashes,
language labels, explicit one-based `benignLines` and optional `scenarioLines`.
Blank lines and comments are excluded; all other lines inherit the attack label.
Paraphrased attacks following a benign section remain attacks. File additions,
removals, changed bytes and invalid line references fail validation until reviewed.

Exact duplicate language/prompt pairs execute once and retain all source locations.
Conflicting labels or scenario mappings fail validation. Reports distinguish source
entries from unique executed cases. Text is trimmed but otherwise preserved by the
harness; bounded decoding and confusable inspection happen inside SPEAR itself.

`LABEL_REVIEW.json` documents ten corrections: two ordinary English questions about
identity/purpose, and eight translations of a usefulness question that contains no
private-instruction request. Adjacent attacks equating usefulness with a private
prompt remain attacks. Eleven tool descriptions now execute as agent scenarios;
none was discarded. The additional benign directory supplies 52 near-neighbor
controls across all twelve languages, and four new attacks cover paraphrases and
encoding. Separate unit regressions are not included in the scored denominator.

When editing a corpus file, review its labels and mappings, document corrections,
then update its `sha256` (for example, `sha256sum <file>`). Do not tune the labels
or thresholds merely to increase the score. The current corpus is development data,
not a held-out benchmark; broad effectiveness needs independent evaluation and
larger, naturally distributed benign samples reviewed by fluent speakers.

## Reports and failure handling

Schema version 2 records every prompt, source location, label, decision, error and
scenario trace, with separate recomputed metrics. Identity binds the Git commit,
corpus manifest, resolved policy, core source, built output and harness hashes.
CI also binds `SPEAR_EVAL_RUN_ID` to the workflow run and attempt. Local verification
accepts a prior run only for the same identity. This detects stale/mismatched
artifacts; it is not cryptographic proof against someone forging all report fields.

The runner removes the previous report **before** building, including when invoked
directly. A build failure cannot leave an old success behind. Internal gate failures
and asynchronous case timeouts become errors; missing or malformed runtime decisions
also fail. Cases have a ten-second asynchronous timeout and CI jobs have a ten-minute
wall-clock limit (the timer alone cannot interrupt synchronous JavaScript).

Verification rejects missing/duplicate cases, altered case content, stale identities,
invalid decisions, missing/contradictory scenario evidence, missing positive scenario
prerequisites, changed thresholds and inconsistent metrics. CI requires a report
artifact and uploads it even when targets fail. No failure is ignored.

## Current evidence and limits

See [BASELINE.md](BASELINE.md) for the initial and current measurements, denominator
changes, one retained miss and reproducibility fingerprints. `pnpm test` includes
harness failure-path tests and independent detector regressions.

The balanced input policy now recognizes additional localized private-instruction
requests. Inspection views handle mixed-script lookalikes, spaced letters, common
letter/digit substitutions, escaped Unicode, marked reversed text and one layer
of explicitly marked Base64/ROT13. They do not rewrite application messages.
Malformed regex rules fail closed in enforce mode instead of becoming silent
non-matching rules. Encoding work and input length are bounded.

Passing this suite validates these deterministic boundaries on these fixtures.
It does not establish live-model leakage, arbitrary obfuscation resistance,
production latency, deployment configuration correctness or universal language
coverage. Output/model evaluations and larger independent multilingual datasets
remain separate work. The old mock provider and fabricated-leak script are removed;
`test:probes` now invokes this evaluator.
