# Initial input-screening baseline

Measured with the new evaluator against core source from commit `bda710aacf57c3a9b77a987b216a7152556c9112`.
The evaluator and corpus manifest are introduced alongside this report.

- 273 source entries; 257 unique executed cases; 12 language labels.
- 104/238 attack-labelled inputs blocked (43.7%).
- 134/238 attack-labelled inputs allowed (56.3%): **fails the ≤5% target**.
- 0/19 benign inputs blocked; 0 runtime errors.
- Evaluation and independent report verification exit 1 as expected.

This is an input-screening result, not a live-model leak measurement. No external
model, output gate or actual tool execution was exercised. Labels are inherited
from the reviewed corpus, including ambiguous and tool-scenario descriptions.
Nineteen benign controls are too few to establish a real-world false-block rate.

| Language label | Attack cases | Blocked attacks | Allowed attacks | Benign cases | Blocked benign |
|---|---:|---:|---:|---:|---:|
| ar | 10 | 6 | 4 | 0 | N/A |
| da | 20 | 13 | 7 | 4 | 0 |
| de | 10 | 6 | 4 | 0 | N/A |
| en | 95 | 48 | 47 | 5 | 0 |
| es | 26 | 13 | 13 | 5 | 0 |
| fr | 10 | 6 | 4 | 0 | N/A |
| hi | 17 | 2 | 15 | 5 | 0 |
| ja | 10 | 1 | 9 | 0 | N/A |
| ko | 10 | 1 | 9 | 0 | N/A |
| pt | 10 | 1 | 9 | 0 | N/A |
| ru | 10 | 1 | 9 | 0 | N/A |
| zh | 10 | 6 | 4 | 0 | N/A |

Reproduce from the repository root with `pnpm eval`. The generated
`packages/core/eval/report.json` contains each prompt, decision and source
location; CI uploads it even when targets fail. The report is generated rather
than checked in, so future runs retain their own commit and CI identity.

Content fingerprints for this baseline:

- `manifestHash`: `24fa3642ee6a4f71d7fbb410bf8920b352ba832e3f7a24a0c38e6ba79a6d8360`
- `policyHash`: `230f68706b5084af308b69d56a47070320fdf00b69bd6bae943b2ff44baeb91f`
- `sourceHash`: `8aa0750fefc78933c0f2a32680202156024d7fb634b5085abf8415323ddaac9f`
- `harnessHash`: `14bea41c66ead6b1f43e4395569b22523232cffd70c5c2363309b0cdd385229a`
