# Spear Product Launch Video Guide

A comprehensive playbook for creating a launch video that highlights value, differentiates from alternatives, goes viral in developer communities, and drives GitHub stars.

---

## 1. Strategy Overview

### Target Audience Segments

| Segment | Where they are | What they fear | Hook angle |
|---------|---------------|----------------|------------|
| **AI Engineers** (25-40) | Twitter/X, YouTube, HN | Shipping insecure AI to prod | "Your RAG pipeline is an open injection channel" |
| **Backend/Fullstack Devs** (28-45) | LinkedIn, Twitter/X, Reddit | Being the one whose app leaks data | "Your competitor just published your system prompt" |
| **Engineering Managers** (30-50) | LinkedIn, YouTube | SOC 2 audit failure, compliance gaps | "Your auditor asks: show me your LLM controls" |
| **Indie Hackers / Solopreneurs** | Twitter/X, YouTube Shorts | Getting hacked with no security team | "One npm install between you and prompt injection" |

### Core Message (One Sentence)

> Spear is the open-source security middleware that guards your LLM pipeline against prompt injection, system prompt theft, and PII leaks -- with a shadow mode so you can observe before you enforce.

### Three Differentiators to Hammer

1. **Guards the pipeline, not just the model** -- ToolMediator + CaMeL data provenance tracks where every value came from
2. **Canary tokens make exfiltration visible** -- proof of leak, not just pattern matching
3. **Shadow mode = zero-risk adoption** -- observe what would be blocked, tune, then enforce

---

## 2. Video Formats & Scripts

### Format A: 15-Second Twitter/X Clip (Pattern Interrupt)

**Goal**: Stop the scroll, plant the idea, drive profile click.

```
[0-3s] HOOK (text overlay, dark terminal background)
  Visual: Terminal showing a prompt injection attack hitting a RAG pipeline
  Text:   "Your RAG pipeline right now:"
  Audio:  Keyboard sounds, then a sharp alert tone

[3-10s] THE ATTACK (screen recording, fast)
  Visual: Attacker input flows through retrieval → LLM executes it
  Text:   "Attacker uploads doc → your agent runs their instructions"
  Audio:  Tense ambient beat

[10-13s] THE FIX (code flash)
  Visual: 3 lines of Spear code appearing with a satisfying animation
  Text:   "const spear = quick('balanced');"
  Audio:  Beat drop / resolution sound

[13-15s] CTA
  Visual: GitHub star button animation
  Text:   "github.com/sunnypatneedi/spear"
  Audio:  Clean close
```

**Caption**: "Your model provider's safety filter never sees what's inside your tool responses. Spear does. Link in bio."

---

### Format B: 30-Second YouTube Short / Reel (Problem-Agitate-Solve)

**Goal**: Educate + differentiate. Drive GitHub visit.

```
[0-3s] HOOK
  Visual: Split screen -- clean chat UI on left, terminal on right
  Words:  "Three things go wrong in production that safety filters never catch."
  Style:  Direct to camera or voiceover with terminal visuals

[3-10s] PROBLEM (agitate with specifics)
  Visual: Animated diagram -- attacker doc → RAG → LLM → execution
  Words:  "One: your RAG pipeline is an open injection channel.
           An attacker embeds instructions in a document,
           your retrieval pulls it in, your agent runs it."
  Style:  Fast cuts, red highlights on the attack path

[10-18s] PROBLEM x2 (stack the pain)
  Visual: Terminal showing system prompt being extracted word by word
  Words:  "Two: someone is extracting your system prompt right now.
           50 requests. No trace in your logs.
           You find out when a competitor posts it on Twitter."
  Style:  Each word of the system prompt appearing, then screenshot of it "leaked"

[18-25s] SOLUTION
  Visual: Code editor -- 6 lines of Spear integration
  Words:  "Spear catches all of this. Four security gates.
           Shadow mode first, enforce when you're ready.
           npm install, three lines of code."
  Style:  Code typing animation, green checkmarks appearing at each gate

[25-28s] PROOF
  Visual: Stats overlay
  Words:  "700+ attack probes. 11 languages. 0% false positives."
  Style:  Numbers animating in

[28-30s] CTA
  Visual: GitHub repo page with star count
  Words:  "Star us on GitHub. Link below."
  Style:  Star button click animation
```

**Caption**: "Model providers guard the conversation. Nobody guards what's inside your tool responses, RAG chunks, or database results. Until Spear. Open source, TypeScript-native, 3 lines to integrate."

---

### Format C: 60-Second YouTube Explainer (Story Spine + Demo)

**Goal**: Full value prop + technical credibility. The canonical launch video.

```
[0-3s] HOOK (bold text on dark bg, no intro fluff)
  Visual: White text on black: "Your LLM app has a security gap you can't see."
  Audio:  Single piano note or ambient tension

[3-12s] SETUP -- paint the current reality
  Visual: Animated architecture diagram of a typical LLM app
  Words:  "You build an AI feature. You trust your model provider's
           safety filters. But your app has a RAG pipeline, tool calls,
           database queries. The safety filter never sees inside those.
           An attacker doesn't need to jailbreak the model.
           They just need to put instructions where your tools will find them."
  Style:  Diagram progressively highlighting blind spots in red

[12-25s] THE ATTACK (make it visceral)
  Visual: Screen recording of an actual attack chain
  Words:  "Here's what that looks like.
           Attacker uploads a resume with hidden instructions.
           Your retrieval system pulls it in.
           Your agent calls send_email with the attacker's payload.
           Your logs? Nothing. The model's safety filter? Never triggered."
  Style:  Real terminal / code execution, each step highlighted

[25-40s] THE SOLUTION (live code demo)
  Visual: VS Code with Spear integration
  Words:  "Spear is open-source security middleware for your LLM pipeline.
           npm install @spear-secure/core. Three lines to integrate.

           InputGate catches injection before your LLM sees it.
           Canary tokens prove when your system prompt leaks.
           ToolMediator tracks where every value came from --
           untrusted data can't trigger privileged actions.

           And you start in shadow mode.
           Nothing blocked. Everything logged.
           Tune your policy, then flip the switch to enforce."
  Style:  Code typing with gate diagram overlay showing the flow

[40-50s] DIFFERENTIATION (comparison flash)
  Visual: Quick comparison table
  Words:  "Other guardrails protect the conversation.
           Spear protects the pipeline.
           Indirect injection, data provenance, canary detection,
           session-scoped agent security --
           things no other library does."
  Style:  Checkmarks appearing for Spear, X's for alternatives

[50-57s] CTA
  Visual: GitHub repo with star animation
  Words:  "It's open source. Apache 2.0.
           Star the repo. Try it in five minutes.
           github.com/sunnypatneedi/spear"
  Style:  URL large on screen, star count ticking up

[57-60s] CLOSE
  Visual: Spear logo + tagline
  Text:   "Defense-in-depth for LLM pipelines."
  Audio:  Clean resolve
```

---

## 3. Visual Design Language

### Color Palette

| Role | Color | Hex | Usage |
|------|-------|-----|-------|
| Background | Near-black | `#0D1117` | Terminal / code backgrounds (GitHub dark) |
| Primary accent | Electric blue | `#58A6FF` | Spear branding, safe states, code highlights |
| Danger | Signal red | `#F85149` | Attack paths, vulnerabilities, blocked states |
| Success | Clean green | `#3FB950` | Checkmarks, allowed states, gates passing |
| Text | Off-white | `#E6EDF3` | Body text, code |
| Subtle | Mid-gray | `#8B949E` | Secondary text, diagram lines |

### Typography

- **Headlines / Overlays**: Inter Bold or JetBrains Mono Bold -- monospace reads "developer" instantly
- **Code**: JetBrains Mono or Fira Code with ligatures
- **Body captions**: Inter Regular, 16-18px equivalent

### Motion Principles

| Element | Animation Style | Timing |
|---------|----------------|--------|
| Text overlays | Fade up + slight scale (0.95 -> 1.0) | 200-300ms, ease-out |
| Code appearing | Character-by-character typing | 30-50ms per char |
| Gate diagram | Sequential left-to-right flow | 150ms stagger between gates |
| Attack path | Red pulse traveling along connection lines | 400ms, with glow |
| Checkmarks | Pop-in with slight bounce (spring physics) | 250ms, bounce: 0.3 |
| Transitions | Hard cut preferred (no dissolves -- feels dev-native) | Instant |

### Screen Layout Templates

**Terminal Demo Layout**:
```
┌─────────────────────────────────────────┐
│  [Terminal / VS Code]          80% width │
│                                          │
│  Code with syntax highlighting           │
│  Spear gates visualized inline           │
│                                          │
├──────────────────────────────────────────┤
│  [Text overlay bar]           20% height │
│  Key point in bold, short sentence       │
└──────────────────────────────────────────┘
```

**Comparison Layout**:
```
┌──────────────┬───────────────────────────┐
│              │  Spear  NeMo  Guard  LLM  │
│  Feature     │   ✅     ❌    ❌    ❌   │
│  Feature     │   ✅     ❌    ❌    ❌   │
│  Feature     │   ✅    partial ✅    ❌   │
└──────────────┴───────────────────────────┘
```

---

## 4. Distribution Strategy

### Platform Priorities

| Platform | Format | Timing | Audience |
|----------|--------|--------|----------|
| **Twitter/X** | 15s native video + thread | Tuesday or Wednesday 10-11 AM PT | AI/ML engineers, indie hackers |
| **YouTube Shorts** | 30s vertical | Same day | Search-driven developers |
| **YouTube** | 60s explainer | Same day, pinned | Long-tail discovery |
| **LinkedIn** | 30s native + text post | Tuesday 9-10 AM ET | Eng managers, technical founders |
| **Reddit** | 60s link post | Day 2 | r/MachineLearning, r/LocalLLaMA, r/artificial |
| **Hacker News** | Show HN with 60s link | Day 2-3, 8 AM ET | Technical early adopters |

### Twitter/X Launch Thread (pair with 15s video)

```
Tweet 1 (with video):
Your model provider's safety filter has a blind spot.

It guards the conversation. It never sees what's inside
your tool responses, RAG chunks, or database results.

Built Spear to fix this. Open source. Apache 2.0.

github.com/sunnypatneedi/spear

Tweet 2:
Three things it catches that nothing else does:

1. Indirect injection through RAG/tools
   (attacker puts instructions in a doc, your agent runs them)

2. System prompt exfiltration
   (canary tokens = proof of leak, not just guessing)

3. Tainted data triggering privileged actions
   (CaMeL-inspired provenance tracking)

Tweet 3:
How it works:

→ InputGate: 7-class injection detection + Unicode normalization
→ InstructionShield: Role hierarchy enforcement
→ OutputGate: Canary detection + PII masking
→ ToolMediator: Data provenance + capability-based RBAC

Shadow mode first. Enforce when ready.

Tweet 4:
3 lines to integrate:

const spear = quick('balanced');
const pre = await spear.pre(messages);
const post = await spear.post({ output, canary: pre.canary });

Works with any LLM. OpenAI, Anthropic, local models. Doesn't matter.

Tweet 5:
700+ attack probes across 11 languages.
0% false positive rate.
<70ms p95 latency.

We red-team it in CI so you don't have to.

If you're building with LLMs, give it a star:
github.com/sunnypatneedi/spear
```

### LinkedIn Post (pair with 30s video)

```
I spent months studying how LLM apps actually get attacked in production.

Not the jailbreaks you see in demos. The real ones.

The attacker who embeds "ignore previous instructions" inside a PDF
that your RAG pipeline retrieves. The one who extracts your system
prompt across 50 requests, and your logs show nothing.

Every guardrail library I found guards the conversation.
None of them guard the pipeline.

So I built one. Open source.

Spear is TypeScript-native security middleware that sits between
your app and your LLM. Four gates. Shadow mode first so you can
observe before you block anything.

What makes it different:
- Catches indirect injection through RAG and tool responses
- Canary tokens that prove when your prompt leaks
- CaMeL-inspired data provenance (tracks where every value came from)
- Session API for multi-step agent loops

npm install @spear-secure/core

Three lines of code. Works with any LLM provider.

We run 700+ attack probes across 11 languages in CI.
0% false positive rate so far.

If you're shipping LLM features: github.com/sunnypatneedi/spear

What's the scariest LLM security gap you've seen in production?
```

---

## 5. Production Checklist

### Pre-Production

- [ ] Record terminal demos with real Spear code (not mockups)
- [ ] Prepare attack chain screen recording (injection through RAG)
- [ ] Create gate flow diagram animation (Input -> Shield -> LLM -> Output)
- [ ] Build comparison table graphic (Spear vs NeMo vs Guardrails AI vs LLM Guard)
- [ ] Set up code typing animation in VS Code or terminal
- [ ] Choose background music: lo-fi electronic, no lyrics, subtle tension-to-resolution arc
- [ ] Record voiceover or prepare text overlays (both work for dev audience)

### Recording

- [ ] 9:16 vertical for Shorts/Reels/TikTok
- [ ] 16:9 horizontal for YouTube + LinkedIn
- [ ] Dark mode everything (devs expect it)
- [ ] Font size large enough to read on mobile (min 18px equivalent)
- [ ] No webcam face necessary (terminal + diagrams + text overlays work better for dev tools)

### Post-Production

- [ ] Hard cuts between sections (no slow dissolves)
- [ ] Captions/subtitles burned in (most watch muted)
- [ ] Code syntax highlighted with Spear lines in accent blue
- [ ] Attack paths in red, safe paths in green
- [ ] GitHub URL visible for 3+ seconds at the end
- [ ] Star button animation as final frame

### Launch Day Sequence

| Time | Action |
|------|--------|
| T-1 day | Upload YouTube 60s as unlisted, prepare all posts |
| T+0, 10 AM PT | Publish Twitter thread with 15s video |
| T+0, 10 AM ET | Publish LinkedIn post with 30s video |
| T+0, 10 AM PT | Publish YouTube Short (30s) + full video (60s) |
| T+2 hours | Reply to every comment within first 2 hours (critical for algo) |
| T+1 day | Submit to Hacker News (Show HN) with YouTube link |
| T+1 day | Post to r/MachineLearning, r/LocalLLaMA |
| T+3 days | Repost top-performing format with slight hook variation |

---

## 6. Viral Mechanics for Developer Content

### What makes dev content shareable

| Trigger | Example for Spear |
|---------|-------------------|
| **"I didn't know that"** | "Your RAG pipeline is an injection channel" -- most devs haven't thought about this |
| **Fear of looking dumb** | "If your competitor publishes your system prompt..." -- nobody wants to be that person |
| **Save for later** | The 3-line integration code -- people bookmark practical code snippets |
| **Tag a friend** | "Send this to whoever owns your LLM feature" -- creates sharing behavior |
| **Contrarian take** | "Safety filters are not security" -- challenges the assumption most teams operate on |

### Engagement Bait That Works for Devs (not cringe)

- Ask a real question: "What's the scariest LLM attack you've seen in prod?"
- Invite code review: "Can you break our InputGate? File an issue."
- Challenge: "Try extracting the system prompt from a Spear-protected app"

---

## 7. Closing CTA Templates

Every piece of content ends with one of these:

**Soft (awareness)**:
> "Star us if you're building with LLMs: github.com/sunnypatneedi/spear"

**Medium (consideration)**:
> "npm install @spear-secure/core. Three lines. Shadow mode. See what it catches. github.com/sunnypatneedi/spear"

**Direct (action)**:
> "Your LLM app is unguarded right now. Fix it in 5 minutes: github.com/sunnypatneedi/spear"

---

## Key URLs

- **GitHub**: https://github.com/sunnypatneedi/spear
- **npm**: https://www.npmjs.com/package/@spear-secure/core
- **CaMeL paper** (differentiator reference): https://arxiv.org/abs/2503.18813
