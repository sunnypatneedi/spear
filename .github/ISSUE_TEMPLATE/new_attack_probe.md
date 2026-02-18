---
name: New attack probe
about: Found a prompt injection technique that Spear misses? Add it to the corpus.
title: '[probe] '
labels: security, enhancement
assignees: ''
---

## Attack description

<!-- What class of attack is this? Direct exfil, override, synonym, transform, etc. -->

## Probe string(s)

```
<!-- paste the attack prompt(s) here -->
```

## Which gate should catch it

- [ ] InputGate (injection in user message)
- [ ] InstructionShield (system prompt manipulation)
- [ ] ToolMediator (unauthorized tool call)
- [ ] OutputGate (leak in response)

## Current Spear behavior

<!-- Does Spear block this? In shadow mode or enforce mode? -->

## Source / reference

<!-- Where did you find this technique? Paper, blog post, red-team exercise? -->

## Suggested fix (optional)

<!-- New regex pattern, policy option, or gate logic change -->
