# Deterministic input-screening evaluation

From the repository root, run `pnpm eval`. This builds core, executes cases and
writes `packages/core/eval/report.json`. No API key or model service is needed.
Run `pnpm --filter @spear-secure/core eval:verify` to independently verify that
report. Both commands exit nonzero when the report fails the screening targets.

## What is measured

Each unique case is passed as one user message to a fresh `SpearRuntime.pre()`.
The balanced policy is loaded explicitly with enforce mode; environment policy
interpolation is disabled and no sidecar is configured. Fresh state prevents
rate limits or earlier cases from changing a later decision. No generated model
response is invented, and output gates are not evaluated by this harness.

`attackAllowedRate` is allowed attack-labelled cases divided by all attack cases.
`falseBlockRate` is blocked benign cases divided by all benign cases. Internal
gate failures are errors, never successful attack detections. Languages without
benign controls have a null false-block rate, not an estimated zero.

The screening targets are at least 95% attack blocking and at most 2% benign
false blocking. The former retains the legacy probe verifier's block target;
the latter retains the prior evaluation's false-block target. These do **not**
replace or demonstrate the historical 0.1% model-leak or 350 ms p95 aspirations.
Those require separate, executable model/output and latency evaluations.

## Corpus contract

`corpus.json` enumerates every `.txt` file under `redteam/`, with SHA-256 content
hashes, language labels and explicit one-based benign line numbers. Blank lines
and comments are excluded. All other lines retain the corpus's attack label;
in particular, paraphrased attacks after the benign section remain attacks.
The manifest fails validation if a file is added, removed or changed without
review, or a benign line points to a comment or blank line.

Exact duplicate prompts within the same language run once, retaining every file
and line location. Conflicting duplicate labels fail validation. The report
distinguishes source entries from unique executed cases. Prompt text is trimmed
but otherwise preserved: literal `\u200B` sequences are not silently decoded.

To change the corpus, review labels first, update the relevant `benignLines`,
then update the file's `sha256` (for example, `sha256sum <file>`). All languages
are exercised, but a language label and ten prompts are not proof of general
language support. The current benign population is only 19 prompts in four
languages. Some inherited attacks are ambiguous requests or descriptions of
tool-use scenarios; this harness measures their input decision only.

## Report and CI contract

The report records every prompt, source location, label, decision and error,
plus recomputed aggregate and language counts. Its identity contains the Git
commit, corpus manifest hash, resolved policy hash, core source hash and harness
hash. CI also binds it to `SPEAR_EVAL_RUN_ID` using the workflow run and attempt.
Local verification accepts a prior run only for the same checkout content and
commit; it is not a cryptographic attestation of execution.

The runner removes the previous report before loading the runtime and writes a
replacement atomically. Runtime failures remain visible as case errors in the
report. Setup errors may produce no report, which is also a failure. The verifier
rejects incomplete coverage, duplicate rows, nonboolean decisions, changed
thresholds, inconsistent metrics and stale identities before checking targets.
CI does not continue past evaluation failure as success and always attempts to
verify and upload the report; a missing artifact is an error.

`pnpm test` includes harness regression tests covering error handling, manifest
coverage and threshold boundaries. The old mock provider, Promptfoo configuration
and synthetic-leak probe script have been removed. `test:probes` now runs this
evaluation instead of reporting fabricated leakage results.

## Remaining work

The [baseline](BASELINE.md) fails the input-blocking target. Keep this visible.
Before claiming stronger protection:

- Triage allowed cases, reviewing ambiguous labels and assigning tool scenarios
  to executable tool/egress/approval tests with expected outcomes.
- Improve detectors with independent regression and held-out benign cases;
  add benign samples for the eight languages that currently have none.
- Evaluate real model responses and output defenses using explicit secrets,
  model/version settings and an actual leakage oracle.
- Measure latency separately under documented load and hardware.

Do not call allowed inputs model leaks, count internal errors as detections, or
restore the former “700+ probes” claim from corpus presence alone.
